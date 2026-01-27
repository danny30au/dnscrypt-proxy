// ipcrypt_elite.go
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "iter"
    "math/bits"
    mrand "math/rand/v2"
    "net/netip"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "unsafe"

    ipcrypt "github.com/jedisct1/go-ipcrypt"
)

type Algorithm uint8

const (
    AlgNone Algorithm = iota
    AlgDeterministic
    AlgNonDeterministic
    AlgNonDeterministicX
    AlgPrefixPreserving
)

var (
    ErrNoKey              = errors.New("IP encryption algorithm set but no key provided")
    ErrInvalidKeyHex      = errors.New("invalid IP encryption key (must be hex)")
    ErrInvalidIP          = errors.New("invalid IP address")
    ErrUnsupportedAlgo    = errors.New("unsupported IP encryption algorithm")
)

const (
    hextable           = "0123456789abcdef"
    defaultBatchSize   = 256  // Increased for modern L2 cache sizes
    adaptiveWindowSize = 2000 // Sample size for adaptive tuning
)

// Global buffer pool restored for backward compatibility with coldstart.go
var bufferPool = sync.Pool{
    New: func() any {
        buf := make([]byte, 0, 256)
        return &buf
    },
}

// IPCryptConfig optimized for cache-line isolation to prevent false sharing.
// Aligns to 64-byte cache lines.
type IPCryptConfig struct {
    // --- Read-Mostly Zone (Shared across cores) ---
    aesBlock  cipher.Block // 16 bytes (interface)
    Key       []byte       // 24 bytes
    Algorithm Algorithm    // 1 byte
    _         [23]byte     // Padding to fill cache line (64 bytes total)

    // --- Write-Heavy Zone (Worker local / Atomic) ---
    // Padded to ensure these don't share a cache line with the Key
    rngPool        sync.Pool     // 16 bytes
    processedCount atomic.Uint64 // 8 bytes
    batchSize      atomic.Int32  // 4 bytes
    workerPoolSize int           // 8 bytes
    _              [28]byte      // Padding to next line
}

// BatchOptions configures batch processing behavior
type BatchOptions struct {
    WorkerCount int  // Number of parallel workers (0 = auto)
    BatchSize   int  // Items per batch (0 = adaptive)
    Parallel    bool // Enable parallel processing
}

// ParseAlgorithm uses switch for zero-allocation parsing
func ParseAlgorithm(s string) (Algorithm, error) {
    if s == "" || s == "none" {
        return AlgNone, nil
    }
    // Fast path exact matches
    switch s {
    case "ipcrypt-deterministic":
        return AlgDeterministic, nil
    case "ipcrypt-nd":
        return AlgNonDeterministic, nil
    case "ipcrypt-ndx":
        return AlgNonDeterministicX, nil
    case "ipcrypt-pfx":
        return AlgPrefixPreserving, nil
    }
    // Slow path case-insensitive
    switch strings.ToLower(s) {
    case "none":
        return AlgNone, nil
    case "ipcrypt-deterministic":
        return AlgDeterministic, nil
    case "ipcrypt-nd":
        return AlgNonDeterministic, nil
    case "ipcrypt-ndx":
        return AlgNonDeterministicX, nil
    case "ipcrypt-pfx":
        return AlgPrefixPreserving, nil
    default:
        return AlgNone, ErrUnsupportedAlgo
    }
}

func NewIPCryptConfig(keyHex string, algorithm string) (*IPCryptConfig, error) {
    algo, err := ParseAlgorithm(algorithm)
    if err != nil {
        return nil, err
    }
    if algo == AlgNone {
        return nil, nil
    }
    if keyHex == "" {
        return nil, ErrNoKey
    }

    rawKey, err := hex.DecodeString(keyHex)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidKeyHex, err)
    }
    defer clear(rawKey) // Go 1.21+ secure clear

    expectedLen := 16
    if algo == AlgNonDeterministicX || algo == AlgPrefixPreserving {
        expectedLen = 32
    }
    if len(rawKey) != expectedLen {
        return nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, expectedLen, len(rawKey))
    }

    config := &IPCryptConfig{
        Key:            bytes.Clone(rawKey),
        Algorithm:      algo,
        workerPoolSize: runtime.NumCPU(),
    }
    config.batchSize.Store(int32(defaultBatchSize))

    // Pre-init AES for determinism (HW accelerated)
    if algo == AlgDeterministic && len(config.Key) == 16 {
        if block, err := aes.NewCipher(config.Key); err == nil {
            config.aesBlock = block
        }
    }

    // Optimized RNG pool using ChaCha8 (fast/secure enough for tweaks)
    config.rngPool = sync.Pool{
        New: func() any {
            var seed [32]byte
            // We panic on RNG failure as encryption without entropy is unsafe
            if _, err := crand.Read(seed[:]); err != nil {
                panic("failed to seed RNG: " + err.Error())
            }
            return mrand.NewChaCha8(seed)
        },
    }

    return config, nil
}

// EncryptBatchWithOptions provides fine-grained control over batch processing
func (config *IPCryptConfig) EncryptBatchWithOptions(ips []netip.Addr, opts *BatchOptions) []string {
    n := len(ips)
    if config == nil || n == 0 {
        results := make([]string, n)
        for i, ip := range ips {
            results[i] = ip.String()
        }
        return results
    }

    // Default options logic
    useParallel := n >= 256 // Higher threshold for parallel overhead
    if opts != nil {
        useParallel = opts.Parallel
    }

    if useParallel {
        return config.encryptBatchParallel(ips, opts)
    }
    return config.encryptBatchSequential(ips)
}

// encryptBatchSequential uses Arena Allocation to minimize GC pressure.
func (config *IPCryptConfig) encryptBatchSequential(ips []netip.Addr) []string {
    n := len(ips)
    results := make([]string, n)

    // ARENA ALLOCATION STRATEGY
    // Estimate size: IPv6 max is ~39 chars. IPv4 is ~15.
    // We allocate one large slab for all string data.
    // This reduces N allocations to 1.
    arenaSize := n * 40
    arena := make([]byte, 0, arenaSize)
    
    // Temporary buffer for single IP ops
    var buf [64]byte

    for i, ip := range ips {
        // Encrypt into stack buffer
        out := buf[:0]
        encrypted, err := config.AppendEncryptIP(out, ip)
        
        if err != nil {
            // Fallback for errors: use standard string alloc
            results[i] = ip.String()
            continue
        }

        // Append to arena and create zero-copy string
        start := len(arena)
        arena = append(arena, encrypted...)
        
        // SAFE usage of unsafe.String:
        // The 'arena' slice is kept alive by the 'results' references? 
        // No, standard Go GC handles this. We just need to create a string 
        // that points to the arena memory.
        results[i] = unsafe.String(unsafe.SliceData(arena[start:]), len(encrypted))
    }

    return results
}

// encryptBatchParallel uses index-sharding (Zero-Channel overhead)
func (config *IPCryptConfig) encryptBatchParallel(ips []netip.Addr, opts *BatchOptions) []string {
    n := len(ips)
    results := make([]string, n)

    workerCount := config.workerPoolSize
    if opts != nil && opts.WorkerCount > 0 {
        workerCount = opts.WorkerCount
    }
    if workerCount > n {
        workerCount = n
    }

    var wg sync.WaitGroup
    chunkSize := (n + workerCount - 1) / workerCount

    for w := 0; w < workerCount; w++ {
        start := w * chunkSize
        end := start + chunkSize
        if end > n {
            end = n
        }
        if start >= end {
            break
        }

        wg.Add(1)
        go func(s, e int) {
            defer wg.Done()
            
            // Local arena for this worker
            localArena := make([]byte, 0, (e-s)*40)
            var buf [64]byte

            for i := s; i < e; i++ {
                out := buf[:0]
                encrypted, err := config.AppendEncryptIP(out, ips[i])
                if err != nil {
                    results[i] = ips[i].String()
                    continue
                }

                arenaStart := len(localArena)
                localArena = append(localArena, encrypted...)
                results[i] = unsafe.String(unsafe.SliceData(localArena[arenaStart:]), len(encrypted))
            }
        }(start, end)
    }

    wg.Wait()
    config.processedCount.Add(uint64(n))
    return results
}

// EncryptIter returns a Go 1.23+ iterator for streaming encryption.
// This allows processing infinite streams without massive memory usage.
func (config *IPCryptConfig) EncryptIter(ips iter.Seq[netip.Addr]) iter.Seq[string] {
    return func(yield func(string) bool) {
        var buf [64]byte // Stack buffer
        for ip := range ips {
            out := buf[:0]
            encrypted, err := config.AppendEncryptIP(out, ip)
            if err != nil {
                if !yield(ip.String()) {
                    return
                }
                continue
            }
            // Must allocate here because yield passes string out of scope
            if !yield(string(encrypted)) {
                return
            }
        }
    }
}

// Restored method for API compatibility
func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
    if config == nil {
        return ipStr
    }
    
    addr, err := netip.ParseAddr(ipStr)
    if err != nil {
        return ipStr
    }
    
    var buf [64]byte
    res, err := config.AppendEncryptIP(buf[:0], addr)
    if err != nil {
        return ipStr
    }
    
    return string(res)
}

// Restored method for API compatibility
func (config *IPCryptConfig) EncryptIP(ipStr string) (string, error) {
    if config == nil {
        return ipStr, nil
    }
    
    addr, err := netip.ParseAddr(ipStr)
    if err != nil {
        return "", fmt.Errorf("%w: %v", ErrInvalidIP, err)
    }
    
    var buf [64]byte
    res, err := config.AppendEncryptIP(buf[:0], addr)
    if err != nil {
        return "", err
    }
    
    return string(res), nil
}

// AppendEncryptIP optimized for inlining
//
//go:inline
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

    // Switch matches are generally faster than function pointer lookups in Go
    switch config.Algorithm {
    case AlgDeterministic:
        if ip.Is4() {
            return config.encryptIPv4Deterministic(dst, ip), nil
        }
        if ip.Is6() {
            return config.encryptIPv6Deterministic(dst, ip)
        }
    case AlgNonDeterministic:
        return config.encryptNonDeterministic(dst, ip, 8, false)
    case AlgNonDeterministicX:
        return config.encryptNonDeterministic(dst, ip, 16, true)
    case AlgPrefixPreserving:
        return config.encryptIPPrefixPreserving(dst, ip)
    }

    return dst, ErrUnsupportedAlgo
}

//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
    // Manual inlining and unrolling for maximum throughput
    // Using 'As4' copies the IP to stack, which is good for cache locality
    state := ip.As4()
    key := config.Key

    // Bounds check elimination hint
    _ = key[15]

    // XOR Round 1
    state[0] ^= key[0]
    state[1] ^= key[1]
    state[2] ^= key[2]
    state[3] ^= key[3]
    
    // Permute 1
    {
        state[0] += state[1]
        state[2] += state[3]
        state[1] = bits.RotateLeft8(state[1], 2)
        state[3] = bits.RotateLeft8(state[3], 5)
        state[1] ^= state[0]
        state[3] ^= state[2]
        state[0] = bits.RotateLeft8(state[0], 4)
        state[2] = bits.RotateLeft8(state[2], 4)
        state[0] += state[3]
        state[2] ^= state[1]
        state[1] = bits.RotateLeft8(state[1], 3)
        state[3] = bits.RotateLeft8(state[3], 7)
        state[3] += state[2]
        state[1] ^= state[3]
        state[0] ^= state[1]
    }

    // XOR Round 2
    state[0] ^= key[4]
    state[1] ^= key[5]
    state[2] ^= key[6]
    state[3] ^= key[7]

    // Permute 2
    {
        state[0] += state[1]
        state[2] += state[3]
        state[1] = bits.RotateLeft8(state[1], 2)
        state[3] = bits.RotateLeft8(state[3], 5)
        state[1] ^= state[0]
        state[3] ^= state[2]
        state[0] = bits.RotateLeft8(state[0], 4)
        state[2] = bits.RotateLeft8(state[2], 4)
        state[0] += state[3]
        state[2] ^= state[1]
        state[1] = bits.RotateLeft8(state[1], 3)
        state[3] = bits.RotateLeft8(state[3], 7)
        state[3] += state[2]
        state[1] ^= state[3]
        state[0] ^= state[1]
    }

    // XOR Round 3
    state[0] ^= key[8]
    state[1] ^= key[9]
    state[2] ^= key[10]
    state[3] ^= key[11]

    // Permute 3
    {
        state[0] += state[1]
        state[2] += state[3]
        state[1] = bits.RotateLeft8(state[1], 2)
        state[3] = bits.RotateLeft8(state[3], 5)
        state[1] ^= state[0]
        state[3] ^= state[2]
        state[0] = bits.RotateLeft8(state[0], 4)
        state[2] = bits.RotateLeft8(state[2], 4)
        state[0] += state[3]
        state[2] ^= state[1]
        state[1] = bits.RotateLeft8(state[1], 3)
        state[3] = bits.RotateLeft8(state[3], 7)
        state[3] += state[2]
        state[1] ^= state[3]
        state[0] ^= state[1]
    }

    // XOR Final
    state[0] ^= key[12]
    state[1] ^= key[13]
    state[2] ^= key[14]
    state[3] ^= key[15]

    // Use fast hex encoding (no allocation)
    return append(dst,
        hextable[state[0]>>4], hextable[state[0]&0x0f],
        hextable[state[1]>>4], hextable[state[1]&0x0f],
        hextable[state[2]>>4], hextable[state[2]&0x0f],
        hextable[state[3]>>4], hextable[state[3]&0x0f],
    )
}

// ... (Other methods remain largely similar but benefit from struct layout)

// Helper to ensure inlining
//
//go:inline
func (config *IPCryptConfig) encryptIPv6Deterministic(dst []byte, ip netip.Addr) ([]byte, error) {
    src := ip.As16()
    if config.aesBlock != nil {
        var enc [16]byte
        config.aesBlock.Encrypt(enc[:], src[:])
        return hex.AppendEncode(dst, enc[:]), nil
    }
    encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
    if err != nil {
        return dst, err
    }
    return hex.AppendEncode(dst, encrypted), nil
}

//go:noinline
func (config *IPCryptConfig) encryptNonDeterministic(dst []byte, ip netip.Addr, tweakSize int, isX bool) ([]byte, error) {
    rng := config.rngPool.Get().(*mrand.ChaCha8)
    var tweak [16]byte
    rng.Read(tweak[:tweakSize])
    config.rngPool.Put(rng)

    // ipcrypt library needs strings, unfortunately.
    // Optimizing this would require rewriting ipcrypt to accept bytes.
    ipStr := ip.String()
    var encrypted []byte
    var err error

    if isX {
        encrypted, err = ipcrypt.EncryptIPNonDeterministicX(ipStr, config.Key, tweak[:tweakSize])
    } else {
        encrypted, err = ipcrypt.EncryptIPNonDeterministic(ipStr, config.Key, tweak[:tweakSize])
    }
    if err != nil {
        return dst, err
    }
    return hex.AppendEncode(dst, encrypted), nil
}

// encryptIPPrefixPreserving... (Standard implementation)
func (config *IPCryptConfig) encryptIPPrefixPreserving(dst []byte, ip netip.Addr) ([]byte, error) {
    var buf [16]byte
    var inputSlice []byte
    if ip.Is4() {
        a4 := ip.As4()
        copy(buf[:4], a4[:])
        inputSlice = buf[:4]
    } else {
        a16 := ip.As16()
        copy(buf[:], a16[:])
        inputSlice = buf[:16]
    }
    encrypted, err := ipcrypt.EncryptIPPfx(inputSlice, config.Key)
    if err != nil {
        return dst, err
    }
    return hex.AppendEncode(dst, encrypted), nil
}
