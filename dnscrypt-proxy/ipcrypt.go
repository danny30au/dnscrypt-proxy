// ipcrypt.go
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
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
    ErrTweakGen           = errors.New("failed to generate random tweak")
    ErrUnsupportedAlgo    = errors.New("unsupported IP encryption algorithm")
    ErrEncryptionDisabled = errors.New("encryption disabled")
)

const (
    hextable              = "0123456789abcdef"
    defaultBatchSize      = 100           // Optimal for cache utilization
    minBatchSize          = 10
    maxBatchSize          = 1000
    adaptiveWindowSize    = 1000          // Sample size for adaptive tuning
    defaultWorkerPoolSize = 0             // 0 = auto-detect based on CPU cores
)

// Buffer pool for batch operations - reduces allocations
var bufferPool = sync.Pool{
    New: func() any {
        buf := make([]byte, 0, 256)
        return &buf
    },
}

// IPCryptConfig optimized for cache-line alignment (64 bytes)
type IPCryptConfig struct {
    aesBlock       cipher.Block // 16 bytes (interface = pointer + type)
    Key            []byte       // 24 bytes (slice header)
    Algorithm      Algorithm    // 1 byte
    _              [7]byte      // padding to 48 bytes
    rngPool        sync.Pool    // 16 bytes
    workerPoolSize int          // Number of workers for parallel processing
    batchSize      atomic.Int32 // Adaptive batch size
    processedCount atomic.Uint64
}

// BatchOptions configures batch processing behavior
type BatchOptions struct {
    WorkerCount int  // Number of parallel workers (0 = auto)
    BatchSize   int  // Items per batch (0 = adaptive)
    Parallel    bool // Enable parallel processing
}

// ParseAlgorithm uses a more efficient string comparison approach
func ParseAlgorithm(s string) (Algorithm, error) {
    if s == "" || s == "none" {
        return AlgNone, nil
    }
    
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

    defer clear(rawKey)

    expectedLen := 16
    if algo == AlgNonDeterministicX || algo == AlgPrefixPreserving {
        expectedLen = 32
    }
    if len(rawKey) != expectedLen {
        return nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, expectedLen, len(rawKey))
    }

    key := bytes.Clone(rawKey)

    config := &IPCryptConfig{
        Key:            key,
        Algorithm:      algo,
        workerPoolSize: runtime.NumCPU(),
    }
    
    config.batchSize.Store(int32(defaultBatchSize))

    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

    config.rngPool = sync.Pool{
        New: func() any {
            var seed [32]byte
            if _, err := crand.Read(seed[:]); err != nil {
                panic("failed to seed RNG: " + err.Error())
            }
            return mrand.NewChaCha8(seed)
        },
    }

    return config, nil
}

//go:inline
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

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

// EncryptBatch processes multiple IPs with optimal batching strategy
func (config *IPCryptConfig) EncryptBatch(ips []netip.Addr) []string {
    return config.EncryptBatchWithOptions(ips, nil)
}

// EncryptBatchWithOptions provides fine-grained control over batch processing
func (config *IPCryptConfig) EncryptBatchWithOptions(ips []netip.Addr, opts *BatchOptions) []string {
    if config == nil || len(ips) == 0 {
        results := make([]string, len(ips))
        for i, ip := range ips {
            results[i] = ip.String()
        }
        return results
    }

    if opts == nil {
        opts = &BatchOptions{
            WorkerCount: 0,
            BatchSize:   0,
            Parallel:    len(ips) > 100,
        }
    }

    if opts.Parallel && len(ips) >= 100 {
        return config.encryptBatchParallel(ips, opts)
    }

    return config.encryptBatchSequential(ips)
}

// encryptBatchSequential handles small batches without parallelization overhead
func (config *IPCryptConfig) encryptBatchSequential(ips []netip.Addr) []string {
    buf := bufferPool.Get().(*[]byte)
    defer func() {
        *buf = (*buf)[:0]
        bufferPool.Put(buf)
    }()

    results := make([]string, len(ips))

    for i, ip := range ips {
        *buf = (*buf)[:0]
        encrypted, err := config.AppendEncryptIP(*buf, ip)
        if err != nil {
            results[i] = ip.String()
            continue
        }
        results[i] = unsafe.String(unsafe.SliceData(encrypted), len(encrypted))
    }

    return results
}

// encryptBatchParallel uses worker pool for high-throughput processing
func (config *IPCryptConfig) encryptBatchParallel(ips []netip.Addr, opts *BatchOptions) []string {
    workerCount := opts.WorkerCount
    if workerCount <= 0 {
        workerCount = config.workerPoolSize
    }
    if workerCount > len(ips) {
        workerCount = len(ips)
    }

    batchSize := opts.BatchSize
    if batchSize <= 0 {
        batchSize = int(config.batchSize.Load())
    }

    results := make([]string, len(ips))
    
    type job struct {
        start, end int
    }
    
    jobs := make(chan job, workerCount)
    var wg sync.WaitGroup

    // Start workers
    for w := 0; w < workerCount; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            
            buf := bufferPool.Get().(*[]byte)
            defer func() {
                *buf = (*buf)[:0]
                bufferPool.Put(buf)
            }()

            for j := range jobs {
                for i := j.start; i < j.end; i++ {
                    *buf = (*buf)[:0]
                    encrypted, err := config.AppendEncryptIP(*buf, ips[i])
                    if err != nil {
                        results[i] = ips[i].String()
                        continue
                    }
                    results[i] = unsafe.String(unsafe.SliceData(encrypted), len(encrypted))
                }
            }
        }()
    }

    // Distribute work in cache-friendly batches
    for start := 0; start < len(ips); start += batchSize {
        end := start + batchSize
        if end > len(ips) {
            end = len(ips)
        }
        jobs <- job{start, end}
    }
    
    close(jobs)
    wg.Wait()

    // Update adaptive batch size
    config.processedCount.Add(uint64(len(ips)))
    if config.processedCount.Load()%adaptiveWindowSize == 0 {
        config.adjustBatchSize()
    }

    return results
}

// adjustBatchSize implements adaptive tuning based on processing patterns
func (config *IPCryptConfig) adjustBatchSize() {
    current := int(config.batchSize.Load())
    
    // Simple heuristic: increase for sustained high throughput
    // In production, you'd measure actual latency/throughput
    if config.processedCount.Load() > adaptiveWindowSize*10 {
        if current < maxBatchSize {
            config.batchSize.Store(int32(current * 110 / 100)) // Increase by 10%
        }
    } else if current > minBatchSize {
        config.batchSize.Store(int32(current * 90 / 100)) // Decrease by 10%
    }
}

// EncryptBatchStrings encrypts IP strings with optimal batching
func (config *IPCryptConfig) EncryptBatchStrings(ipStrs []string) []string {
    return config.EncryptBatchStringsWithOptions(ipStrs, nil)
}

// EncryptBatchStringsWithOptions provides control over string batch processing
func (config *IPCryptConfig) EncryptBatchStringsWithOptions(ipStrs []string, opts *BatchOptions) []string {
    if config == nil || len(ipStrs) == 0 {
        return ipStrs
    }

    // Pre-parse all IPs (parallel parsing for large batches)
    ips := make([]netip.Addr, len(ipStrs))
    validMask := make([]bool, len(ipStrs))
    
    if opts != nil && opts.Parallel && len(ipStrs) >= 1000 {
        // Parallel parsing for very large batches
        workers := runtime.NumCPU()
        chunkSize := (len(ipStrs) + workers - 1) / workers
        var wg sync.WaitGroup
        
        for w := 0; w < workers; w++ {
            start := w * chunkSize
            if start >= len(ipStrs) {
                break
            }
            end := start + chunkSize
            if end > len(ipStrs) {
                end = len(ipStrs)
            }
            
            wg.Add(1)
            go func(start, end int) {
                defer wg.Done()
                for i := start; i < end; i++ {
                    if addr, err := netip.ParseAddr(ipStrs[i]); err == nil {
                        ips[i] = addr
                        validMask[i] = true
                    }
                }
            }(start, end)
        }
        wg.Wait()
    } else {
        // Sequential parsing for smaller batches
        for i, ipStr := range ipStrs {
            if addr, err := netip.ParseAddr(ipStr); err == nil {
                ips[i] = addr
                validMask[i] = true
            }
        }
    }

    // Encrypt valid IPs
    encrypted := config.EncryptBatchWithOptions(ips, opts)
    
    // Map back to original strings where parsing failed
    results := make([]string, len(ipStrs))
    for i := range ipStrs {
        if validMask[i] {
            results[i] = encrypted[i]
        } else {
            results[i] = ipStrs[i]
        }
    }

    return results
}

//go:noinline
func (config *IPCryptConfig) encryptNonDeterministic(dst []byte, ip netip.Addr, tweakSize int, isX bool) ([]byte, error) {
    rng := config.rngPool.Get().(*mrand.ChaCha8)
    
    var tweak [16]byte
    rng.Read(tweak[:tweakSize])
    config.rngPool.Put(rng)

    var encrypted []byte
    var err error
    
    ipStr := ip.String()
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

//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
    state := ip.As4()
    key := config.Key

    _ = key[15]
    
    if cap(dst)-len(dst) < 8 {
        newDst := make([]byte, len(dst), len(dst)+8)
        copy(newDst, dst)
        dst = newDst
    }
    
    state[0] ^= key[0]
    state[1] ^= key[1]
    state[2] ^= key[2]
    state[3] ^= key[3]
    permute(&state)

    state[0] ^= key[4]
    state[1] ^= key[5]
    state[2] ^= key[6]
    state[3] ^= key[7]
    permute(&state)

    state[0] ^= key[8]
    state[1] ^= key[9]
    state[2] ^= key[10]
    state[3] ^= key[11]
    permute(&state)

    state[0] ^= key[12]
    state[1] ^= key[13]
    state[2] ^= key[14]
    state[3] ^= key[15]

    return append(dst,
        hextable[state[0]>>4], hextable[state[0]&0x0f],
        hextable[state[1]>>4], hextable[state[1]&0x0f],
        hextable[state[2]>>4], hextable[state[2]&0x0f],
        hextable[state[3]>>4], hextable[state[3]&0x0f],
    )
}

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

//go:inline
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

//go:inline
//go:nosplit
func permute(s *[4]byte) {
    s[0] += s[1]
    s[2] += s[3]
    s[1] = bits.RotateLeft8(s[1], 2)
    s[3] = bits.RotateLeft8(s[3], 5)
    
    s[1] ^= s[0]
    s[3] ^= s[2]
    
    s[0] = bits.RotateLeft8(s[0], 4)
    s[2] = bits.RotateLeft8(s[2], 4)
    
    s[0] += s[3]
    s[2] ^= s[1]
    s[1] = bits.RotateLeft8(s[1], 3)
    s[3] = bits.RotateLeft8(s[3], 7)
    
    s[3] += s[2]
    s[1] ^= s[3]
    s[0] ^= s[1]
}

func (config *IPCryptConfig) EncryptIP(ipStr string) (string, error) {
    if config == nil {
        return ipStr, nil
    }
    
    addr, err := netip.ParseAddr(ipStr)
    if err != nil {
        return "", fmt.Errorf("%w: %v", ErrInvalidIP, err)
    }
    
    res, err := config.AppendEncryptIP(nil, addr)
    if err != nil {
        return "", err
    }
    
    return unsafe.String(unsafe.SliceData(res), len(res)), nil
}

func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
    if config == nil {
        return ipStr
    }
    
    addr, err := netip.ParseAddr(ipStr)
    if err != nil {
        return ipStr
    }
    
    res, err := config.AppendEncryptIP(nil, addr)
    if err != nil {
        return ipStr
    }
    
    return unsafe.String(unsafe.SliceData(res), len(res))
}
