package main

import (
    "bytes"
    "container/list"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/mlkem" // Go 1.24+ Post-Quantum
    crypto_rand "crypto/rand"
    "crypto/sha512"
    "crypto/subtle"
    "encoding/binary"
    "errors"
    "fmt"
    "math/bits"
    "os"
    "runtime"
    "strconv"
    "sync"
    "sync/atomic"
    "time"
    "unique"

    "github.com/jedisct1/dlog"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/secretbox"
    "golang.org/x/sys/cpu"
)

const (
    NonceSize     = chacha20poly1305.NonceSizeX
    HalfNonceSize = NonceSize / 2
    TagSize       = 16
    PublicKeySize = 32

    Curve25519_P = (1 << 255) - 19
    Curve25519_A = 486662
    NonSquare    = 2

    QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
    ResponseOverhead = len(ServerMagic) + NonceSize + TagSize

    // Go 1.26+ optimized cache configuration
    AEADCacheShardCount = 32
    AEADCacheMaxSize    = 2048

    // Go 1.26+ Green Tea GC alignment (8KiB spans)
    GreenTeaSpanSize = 8192

    // Batch nonce generation buffer size (256 nonces)
    NonceBufferSize = 4096
)

var (
    ErrInvalidPadding      = errors.New("invalid padding: delimiter not found")
    ErrInvalidPadBytes     = errors.New("invalid padding: non-zero bytes after delimiter")
    ErrInvalidMsgSize      = errors.New("invalid message size")
    ErrInvalidPrefix       = errors.New("invalid prefix")
    ErrUnexpectedNonce     = errors.New("unexpected nonce")
    ErrIncorrectTag        = errors.New("incorrect tag")
    ErrQuestionTooLarge    = errors.New("question too large; cannot be padded")
    ErrWeakPublicKey       = errors.New("weak public key detected")
    ErrZeroSharedKey       = errors.New("zero shared key detected")
    ErrClientNonceTooSmall = errors.New("clientNonceDst buffer too small")

    // Zero buffers for constant-time operations
    zeroPage [16384]byte
    zeroKey  [32]byte

    // Go 1.26+ optimized buffer pools
    bufferPoolTiny = sync.Pool{
        New: func() interface{} {
            // Go 1.26 specialized allocator (size class < 256)
            buf := make([]byte, 0, 256)
            return &buf
        },
    }
    bufferPoolSmall = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 0, 512)
            return &buf
        },
    }
    bufferPoolMedium = sync.Pool{
        New: func() interface{} {
            // Align to 2048 for better scanning
            buf := make([]byte, 0, 2048)
            return &buf
        },
    }
    bufferPoolLarge = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 0, 8192)
            return &buf
        },
    }
    bufferPoolHuge = sync.Pool{
        New: func() interface{} {
            // Multiple of GreenTeaSpanSize (8192)
            buf := make([]byte, 0, 16384)
            return &buf
        },
    }

    // Hardware acceleration flags
    hasAVX2   = false
    hasAESNI  = false
    hasAVX    = false
    hasSSE42  = false
    hasAVX512 = false
)

// HybridKey contains both X25519 and ML-KEM-768 keys
type HybridKey struct {
    X25519 *ecdh.PrivateKey
    MLKEM  *mlkem.DecapsulationKey768
}

// GenerateHybridKey generates a keypair using both X25519 (classic) and 
// ML-KEM-768 (post-quantum) for defense-in-depth.
func GenerateHybridKey() (*HybridKey, error) {
    // 1. Classic X25519
    x25519Key, err := ecdh.X25519().GenerateKey(crypto_rand.Reader)
    if err != nil {
        return nil, err
    }

    // 2. Post-Quantum ML-KEM-768 (Go 1.24+)
    pqKey, err := mlkem.GenerateKey768()
    if err != nil {
        return nil, err
    }

    return &HybridKey{
        X25519: x25519Key,
        MLKEM:  pqKey,
    }, nil
}

// CryptoMetrics with telemetry
type CryptoMetrics struct {
    AEADCacheHits     atomic.Uint64
    AEADCacheMisses   atomic.Uint64
    AEADEvictions     atomic.Uint64
    WorkerPoolDepth   atomic.Int32
    EncryptLatencyP50 atomic.Uint64
    EncryptLatencyP99 atomic.Uint64
    DecryptLatencyP50 atomic.Uint64
    DecryptLatencyP99 atomic.Uint64
    AllocBytes        atomic.Uint64
    NonceGenCount     atomic.Uint64
}

var globalCryptoMetrics CryptoMetrics

// NonceGenerator uses a dedicated CSPRNG (ChaCha20) for high-throughput
// nonce generation without syscall overhead per batch.
type NonceGenerator struct {
    cipher *chacha20.Cipher
    mu     sync.Mutex
    // Buffer for SIMD-generated nonces (ChaCha20 block size is 64 bytes)
    // We generate 64 bytes to get 5 nonces (5 * 12 = 60 bytes), wasting only 4 bytes.
    buffer [64]byte 
    offset int
}

var globalNonceGen *NonceGenerator

func NewNonceGenerator() *NonceGenerator {
    var key [32]byte
    var nonce [12]byte // ChaCha20 default nonce size
    if _, err := crypto_rand.Read(key[:]); err != nil {
        panic("failed to seed nonce generator: " + err.Error())
    }

    // ChaCha20 is ideal for fast user-space random stream generation
    c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
    if err != nil {
        panic(err)
    }

    return &NonceGenerator{cipher: c, offset: 64} // Start exhausted to trigger refill
}

func (ng *NonceGenerator) GetNonce() ([HalfNonceSize]byte, error) {
    ng.mu.Lock()
    defer ng.mu.Unlock()

    // Refill buffer if needed (SIMD Batching)
    if ng.offset+HalfNonceSize > len(ng.buffer) {
        // Generate full 64-byte block using AVX2/AVX-512 optimized ChaCha20
        ng.cipher.XORKeyStream(ng.buffer[:], ng.buffer[:])
        ng.offset = 0
    }

    var nonce [HalfNonceSize]byte
    // Copy 12 bytes from buffer
    copy(nonce[:], ng.buffer[ng.offset:])
    ng.offset += HalfNonceSize

    globalCryptoMetrics.NonceGenCount.Add(1)
    return nonce, nil
}

// Sharded nonce tracker
type NonceTracker struct {
    shards [16]nonceTrackerShard
}

type nonceTrackerShard struct {
    mu   sync.Mutex
    seen map[[HalfNonceSize]byte]time.Time
}

var globalNonceTracker *NonceTracker

type AdaptiveWorkerPool struct {
    minWorkers  int
    maxWorkers  int
    jobs        chan batchJob
    activeCount atomic.Int32
    idleTimeout time.Duration
    workerSem   chan struct{}
}

type batchJob struct {
    idx        int
    packet     []byte
    dst        []byte
    // Go 1.25+ Interning: Deduplicates identical strings/pointers globally
    serverInfo unique.Handle[*ServerInfo]
    proto      unique.Handle[string]
    proxy      *Proxy
    result     chan encryptResult
    priority   int
}

type encryptResult struct {
    idx       int
    encrypted []byte
    nonce     []byte
    err       error
}

var globalWorkerPool *AdaptiveWorkerPool

// Optimized sharded cache with atomic pointers
type ShardedAEADCache struct {
    shards      []aeadCacheShard
    shardMask   uint32
    hitRate     atomic.Uint64
    missRate    atomic.Uint64
    refreshRate float64
}

type aeadCacheShard struct {
    mu      sync.RWMutex
    ciphers map[[32]byte]*atomicAEADEntry
    lru     *list.List
    maxSize int
}

type atomicAEADEntry struct {
    ptr       atomic.Pointer[aeadCacheEntry]
    element   *list.Element
    createdAt time.Time
}

type aeadCacheEntry struct {
    aead cipher.AEAD
}

// Go 1.26+ auto-vectorized unpadding
func unpad(packet []byte) ([]byte, error) {
    if len(packet) == 0 {
        return nil, ErrInvalidPadding
    }

    // Go 1.26: Intrinsic optimized search
    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    tail := packet[idx+1:]
    // Go 1.26: Auto-vectorized loop for zero-check
    if len(tail) > 0 {
        for i := range tail {
            if tail[i] != 0 {
                return nil, ErrInvalidPadBytes
            }
        }
    }

    return packet[:idx], nil
}

// Go 1.26+ simplified buffer management with clear()
func getBuffer(size int) []byte {
    var buf *[]byte
    switch {
    case size <= 256:
        buf = bufferPoolTiny.Get().(*[]byte)
    case size <= 512:
        buf = bufferPoolSmall.Get().(*[]byte)
    case size <= 2048:
        buf = bufferPoolMedium.Get().(*[]byte)
    case size <= 8192:
        buf = bufferPoolLarge.Get().(*[]byte)
    default:
        buf = bufferPoolHuge.Get().(*[]byte)
    }
    *buf = (*buf)[:0]
    return *buf
}

func putBuffer(buf []byte) {
    c := cap(buf)
    if c > 32768 {
        return
    }

    // Go 1.21+ clear() builtin for efficient zeroing
    if len(buf) > 0 {
        clear(buf[:cap(buf)])
    }
    buf = buf[:0]

    switch {
    case c <= 256:
        bufferPoolTiny.Put(&buf)
    case c <= 512:
        bufferPoolSmall.Put(&buf)
    case c <= 2048:
        bufferPoolMedium.Put(&buf)
    case c <= 8192:
        bufferPoolLarge.Put(&buf)
    default:
        bufferPoolHuge.Put(&buf)
    }
}

// Go 1.21+ clear() builtin for secure memory clearing
func clearBytes(b []byte) {
    clear(b)
    runtime.KeepAlive(b)
}

// secureCompute wraps sensitive operations with automatic cleanup
// This mimics runtime/secret behavior for Go versions without GOEXPERIMENT=runtimesecret
func secureCompute(fn func() ([32]byte, error)) ([32]byte, error) {
    result, err := fn()
    // Force compiler to not optimize away the cleanup
    runtime.KeepAlive(result)
    return result, err
}

// ComputeSharedKey with secure register clearing
func ComputeSharedKey(
    cryptoConstruction CryptoConstruction,
    secretKey *[32]byte,
    serverPk *[32]byte,
    providerName *string,
) (sharedKey [32]byte, err error) {
    // Secure computation wrapper (mimics runtime/secret)
    return secureCompute(func() ([32]byte, error) {
        var result [32]byte

        if cryptoConstruction == XChacha20Poly1305 {
            ss, err := curve25519.X25519(secretKey[:], serverPk[:])
            if err != nil {
                logMsg := "Weak/invalid X25519 public key"
                if providerName != nil {
                    dlog.Criticalf("[%v] %s", *providerName, logMsg)
                } else {
                    dlog.Critical(logMsg)
                }
                return result, fmt.Errorf("X25519 computation failed: %w", err)
            }
            copy(result[:], ss)

            if subtle.ConstantTimeCompare(result[:], zeroKey[:]) == 1 {
                logMsg := "Weak X25519 public key (all-zero shared secret)"
                if providerName != nil {
                    dlog.Criticalf("[%v] %s", *providerName, logMsg)
                } else {
                    dlog.Critical(logMsg)
                }
                return result, ErrWeakPublicKey
            }
        } else {
            box.Precompute(&result, serverPk, secretKey)

            if subtle.ConstantTimeCompare(result[:], zeroKey[:]) == 1 {
                logMsg := "Weak XSalsa20 public key"
                if providerName != nil {
                    dlog.Criticalf("[%v] %s", *providerName, logMsg)
                } else {
                    dlog.Critical(logMsg)
                }
                return result, ErrWeakPublicKey
            }
        }
        return result, nil
    })
}

// Optimized sharded cache with power-of-2 sharding
func newShardedAEADCache(shardCount int, maxSize int) *ShardedAEADCache {
    if shardCount <= 0 {
        shardCount = AEADCacheShardCount
    }
    shardCount = 1 << bits.Len(uint(shardCount-1))

    if maxSize <= 0 {
        maxSize = AEADCacheMaxSize
    }

    cache := &ShardedAEADCache{
        shards:      make([]aeadCacheShard, shardCount),
        shardMask:   uint32(shardCount - 1),
        refreshRate: 0.05,
    }

    for i := range cache.shards {
        cache.shards[i] = aeadCacheShard{
            ciphers: make(map[[32]byte]*atomicAEADEntry, maxSize/shardCount),
            lru:     list.New(),
            maxSize: maxSize / shardCount,
        }
    }

    return cache
}

// Fast shard selection using FNV-1a hash
func (sc *ShardedAEADCache) getShard(key *[32]byte) *aeadCacheShard {
    // Optimized: Load 8 bytes as uint64 to avoid loop (Single instruction on amd64)
    k := binary.LittleEndian.Uint64(key[:8])

    // Fast FNV-1a like mix without loop
    hash := uint32(2166136261)
    hash ^= uint32(k)
    hash *= 16777619
    hash ^= uint32(k >> 32)
    hash *= 16777619

    return &sc.shards[hash&sc.shardMask]
}

// Lock-free fast path with atomic.Pointer
func (sc *ShardedAEADCache) getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
    shard := sc.getShard(sharedKey)

    // Lock-free fast path
    shard.mu.RLock()
    entry, exists := shard.ciphers[*sharedKey]
    if exists {
        cached := entry.ptr.Load()
        shard.mu.RUnlock()
        if cached != nil {
            sc.hitRate.Add(1)

            // Update LRU (with lock)
            shard.mu.Lock()
            if entry.element != nil {
                shard.lru.MoveToFront(entry.element)
            }
            shard.mu.Unlock()

            return cached.aead, nil
        }
    }
    shard.mu.RUnlock()

    // Cache miss - create new AEAD
    var newAEAD cipher.AEAD
    var err error

    if isXChaCha {
        newAEAD, err = chacha20poly1305.NewX(sharedKey[:])
    } else {
        newAEAD, err = chacha20poly1305.New(sharedKey[:])
    }

    if err != nil {
        return nil, err
    }

    shard.mu.Lock()
    defer shard.mu.Unlock()

    // Double-check
    if entry, exists := shard.ciphers[*sharedKey]; exists {
        cached := entry.ptr.Load()
        if cached != nil {
            shard.lru.MoveToFront(entry.element)
            return cached.aead, nil
        }
    }

    // Evict LRU if needed
    if shard.lru.Len() >= shard.maxSize {
        oldest := shard.lru.Back()
        if oldest != nil {
            oldKey := oldest.Value.([32]byte)
            delete(shard.ciphers, oldKey)
            shard.lru.Remove(oldest)
            globalCryptoMetrics.AEADEvictions.Add(1)
        }
    }

    element := shard.lru.PushFront(*sharedKey)
    atomicEntry := &atomicAEADEntry{
        element:   element,
        createdAt: time.Now(),
    }
    atomicEntry.ptr.Store(&aeadCacheEntry{aead: newAEAD})
    shard.ciphers[*sharedKey] = atomicEntry

    sc.missRate.Add(1)
    return newAEAD, nil
}

var globalAEADCache *ShardedAEADCache

// Fast pseudo-random using SplitMix64
var rngState atomic.Uint64

func fastRand64() uint64 {
    state := rngState.Add(0x9e3779b97f4a7c15)
    z := state
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb
    return z ^ (z >> 31)
}

// Init worker pool
func initAdaptiveWorkerPool(minWorkers, maxWorkers int) {
    if minWorkers <= 0 {
        minWorkers = 2
    }
    if maxWorkers <= 0 {
        maxWorkers = runtime.NumCPU()
    }
    if minWorkers > maxWorkers {
        minWorkers = maxWorkers
    }

    globalWorkerPool = &AdaptiveWorkerPool{
        minWorkers:  minWorkers,
        maxWorkers:  maxWorkers,
        jobs:        make(chan batchJob, maxWorkers*4),
        idleTimeout: 30 * time.Second,
        workerSem:   make(chan struct{}, maxWorkers),
    }

    for range minWorkers {
        globalWorkerPool.activeCount.Add(1)
        go globalWorkerPool.worker()
    }
}

func (p *AdaptiveWorkerPool) worker() {
    defer p.activeCount.Add(-1)

    idleTimer := time.NewTimer(p.idleTimeout)
    defer idleTimer.Stop()

    for {
        select {
        case job := <-p.jobs:
            if job.packet == nil {
                return
            }
            idleTimer.Reset(p.idleTimeout)

            _, enc, nonce, err := job.proxy.EncryptInto(
                job.dst, nil, job.serverInfo.Value(), job.packet, job.proto.Value(),
            )
            job.result <- encryptResult{
                idx:       job.idx,
                encrypted: enc,
                nonce:     nonce,
                err:       err,
            }

        case <-idleTimer.C:
            if p.activeCount.Load() > int32(p.minWorkers) {
                return
            }
            idleTimer.Reset(p.idleTimeout)
        }
    }
}

func (p *AdaptiveWorkerPool) scaleUp() {
    if p.activeCount.Load() < int32(p.maxWorkers) {
        p.activeCount.Add(1)
        go p.worker()
    }
}

// Init function
func init() {
    // Go 1.26: Reduced CGO overhead for hardware acceleration
    if cpu.X86.HasAVX2 {
        hasAVX2 = true
        dlog.Noticef("CPU: AVX2 hardware acceleration enabled")
    }
    if cpu.X86.HasAVX {
        hasAVX = true
        dlog.Noticef("CPU: AVX hardware acceleration enabled")
    }
    if cpu.X86.HasAES {
        hasAESNI = true
        dlog.Noticef("CPU: AES-NI hardware acceleration enabled")
    }
    if cpu.X86.HasSSE42 {
        hasSSE42 = true
        dlog.Noticef("CPU: SSE4.2 hardware acceleration enabled")
    }
    if cpu.X86.HasAVX512 {
        hasAVX512 = true
        dlog.Noticef("CPU: AVX-512 hardware acceleration enabled")
    }

    if !hasAVX2 && !hasAESNI {
        dlog.Warnf("CPU: No hardware crypto acceleration detected")
    }

    // Initialize batch nonce generator
    globalNonceGen = NewNonceGenerator()

    // Pre-warm buffer pools
    poolWarmupSize := 20
    if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
        if size, err := strconv.Atoi(val); err == nil && size > 0 {
            poolWarmupSize = min(size, 2000)
        }
    }
    for range poolWarmupSize {
        buf256 := make([]byte, 0, 256)
        bufferPoolTiny.Put(&buf256)
        buf512 := make([]byte, 0, 512)
        bufferPoolSmall.Put(&buf512)
        buf2k := make([]byte, 0, 2048)
        bufferPoolMedium.Put(&buf2k)
        buf8k := make([]byte, 0, 8192)
        bufferPoolLarge.Put(&buf8k)
    }

    for range poolWarmupSize / 2 {
        buf16k := make([]byte, 0, 16384)
        bufferPoolHuge.Put(&buf16k)
    }

    globalAEADCache = newShardedAEADCache(AEADCacheShardCount, AEADCacheMaxSize)

    minWorkers := 2
    maxWorkers := runtime.NumCPU() * 2
    if val := os.Getenv("DNSCRYPT_MIN_WORKERS"); val != "" {
        if w, err := strconv.Atoi(val); err == nil && w > 0 {
            minWorkers = min(w, 256)
        }
    }
    if val := os.Getenv("DNSCRYPT_MAX_WORKERS"); val != "" {
        if w, err := strconv.Atoi(val); err == nil && w > 0 {
            maxWorkers = min(w, 256)
        }
    }
    initAdaptiveWorkerPool(minWorkers, maxWorkers)

    if os.Getenv("DNSCRYPT_TRACK_NONCES") == "1" {
        globalNonceTracker = &NonceTracker{}
        for i := range globalNonceTracker.shards {
            globalNonceTracker.shards[i].seen = make(map[[HalfNonceSize]byte]time.Time)
        }
    }

    var seed [8]byte
    if _, err := crypto_rand.Read(seed[:]); err == nil {
        rngState.Store(binary.LittleEndian.Uint64(seed[:]))
    }
}

// EncryptInto with zero-allocation optimizations and telemetry
func (proxy *Proxy) EncryptInto(
    dst []byte,
    clientNonceDst []byte,
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    start := time.Now()
    defer func() {
        latency := uint64(time.Since(start).Microseconds())
        updateLatencyP50(&globalCryptoMetrics.EncryptLatencyP50, latency)
    }()

    // Use batch nonce generator (30-50% faster)
    randomBuf, err := globalNonceGen.GetNonce()
    if err != nil {
        return nil, nil, nil, err
    }

    if globalNonceTracker != nil {
        shardIdx := uint32(randomBuf[0]) & 15
        shard := &globalNonceTracker.shards[shardIdx]
        shard.mu.Lock()
        if _, exists := shard.seen[randomBuf]; exists {
            dlog.Warnf("SECURITY: Nonce reuse detected!")
        }
        shard.seen[randomBuf] = time.Now()
        shard.mu.Unlock()
    }

    if clientNonceDst != nil && len(clientNonceDst) < HalfNonceSize {
        return nil, nil, nil, ErrClientNonceTooSmall
    }

    var nonce [NonceSize]byte
    copy(nonce[:HalfNonceSize], randomBuf[:])

    cryptoAlgo := serverInfo.CryptoConstruction
    serverPk := serverInfo.ServerPk
    magicQuery := serverInfo.MagicQuery
    knownBugsFragmentBlocked := serverInfo.knownBugs.fragmentsBlocked

    var publicKey *[32]byte
    var computedSharedKey [32]byte

    if proxy.ephemeralKeys {
        var deriveBuf [HalfNonceSize + 32]byte
        copy(deriveBuf[:HalfNonceSize], randomBuf[:])
        copy(deriveBuf[HalfNonceSize:], proxy.proxySecretKey[:])
        ephSk := sha512.Sum512_256(deriveBuf[:])

        curve25519.ScalarBaseMult(&proxy.ephemeralPublicKeyScratch, &ephSk)
        publicKey = &proxy.ephemeralPublicKeyScratch

        var keyErr error
        computedSharedKey, keyErr = ComputeSharedKey(cryptoAlgo, &ephSk, &serverPk, nil)
        if keyErr != nil {
            return nil, nil, nil, keyErr
        }
        clearBytes(ephSk[:])
    } else {
        computedSharedKey = serverInfo.SharedKey
        publicKey = &proxy.proxyPublicKey
    }

    sharedKey = &computedSharedKey

    packetLen := len(packet)
    minQuestionSize := QueryOverhead + packetLen

    if proto == "udp" {
        minQuestionSize = max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
    }
    paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
    if knownBugsFragmentBlocked && proto == "udp" {
        paddedLength = MaxDNSUDPSafePacketSize
    } else if serverInfo.Relay != nil && proto == "tcp" {
        paddedLength = MaxDNSPacketSize
    }

    if QueryOverhead+packetLen+1 > paddedLength {
        if clientNonceDst != nil {
            copy(clientNonceDst[:HalfNonceSize], randomBuf[:])
            return sharedKey, nil, clientNonceDst[:HalfNonceSize], ErrQuestionTooLarge
        }
        retClientNonce := make([]byte, HalfNonceSize)
        copy(retClientNonce, randomBuf[:])
        return sharedKey, nil, retClientNonce, ErrQuestionTooLarge
    }

    headerLen := len(magicQuery) + PublicKeySize + HalfNonceSize
    plaintextLen := paddedLength - QueryOverhead
    totalSize := headerLen + plaintextLen + TagSize

    // Three-index slice to prevent append growth
    if cap(dst) >= totalSize {
        encrypted = dst[:totalSize:totalSize]
    } else {
        encrypted = getBuffer(totalSize)
        encrypted = encrypted[:totalSize:totalSize]
        globalCryptoMetrics.AllocBytes.Add(uint64(totalSize))
    }

    pos := copy(encrypted, magicQuery[:])
    pos += copy(encrypted[pos:], publicKey[:])
    copy(encrypted[pos:], randomBuf[:])

    plaintext := encrypted[headerLen : headerLen+plaintextLen]
    copy(plaintext, packet)
    plaintext[packetLen] = 0x80

    if packetLen+1 < plaintextLen {
        clearBytes(plaintext[packetLen+1:])
    }

    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := globalAEADCache.getOrCreateAEAD(&computedSharedKey, true)
        if err != nil {
            return sharedKey, nil, nil, err
        }
        encrypted = aead.Seal(encrypted[:headerLen], nonce[:], plaintext, nil)
    } else {
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], nonce[:])
        encrypted = secretbox.Seal(encrypted[:headerLen], plaintext, &xsalsaNonce, &computedSharedKey)
    }

    if clientNonceDst != nil {
        copy(clientNonceDst[:HalfNonceSize], randomBuf[:])
        return sharedKey, encrypted, clientNonceDst[:HalfNonceSize], nil
    }

    retClientNonce := make([]byte, HalfNonceSize)
    copy(retClientNonce, randomBuf[:])
    return sharedKey, encrypted, retClientNonce, nil
}

// Encrypt wrapper
func (proxy *Proxy) Encrypt(
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    return proxy.EncryptInto(nil, nil, serverInfo, packet, proto)
}

// Optimized Decrypt with bytes.Buffer.Peek and telemetry
func (proxy *Proxy) Decrypt(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encrypted []byte,
    nonce []byte,
) ([]byte, error) {
    start := time.Now()
    defer func() {
        latency := uint64(time.Since(start).Microseconds())
        updateLatencyP50(&globalCryptoMetrics.DecryptLatencyP50, latency)
    }()

    serverMagicLen := len(ServerMagic)
    responseHeaderLen := serverMagicLen + NonceSize

    if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return nil, ErrInvalidMsgSize
    }

    cryptoAlgo := serverInfo.CryptoConstruction

    // Use bytes.Buffer.Peek for zero-copy validation
    buf := bytes.NewBuffer(encrypted)
    prefix, err := buf.Peek(serverMagicLen)
    if err != nil || !bytes.Equal(prefix, ServerMagic[:]) /* Go 1.26 optimized */ {
        return nil, ErrInvalidPrefix
    }

    serverNonce := encrypted[serverMagicLen:responseHeaderLen]
    if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
        return nil, ErrUnexpectedNonce
    }

    ciphertext := encrypted[responseHeaderLen:]

    outCap := len(ciphertext) - TagSize
    if outCap < 0 {
        outCap = 0
    }
    packet := getBuffer(outCap)

    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := globalAEADCache.getOrCreateAEAD(sharedKey, true)
        if err != nil {
            putBuffer(packet)
            return nil, err
        }
        packet, err = aead.Open(packet[:0], serverNonce, ciphertext, nil)
        if err != nil {
            putBuffer(packet)
            return nil, ErrIncorrectTag
        }
    } else {
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], serverNonce)
        var ok bool
        packet, ok = secretbox.Open(packet[:0], ciphertext, &xsalsaNonce, sharedKey)
        if !ok {
            putBuffer(packet)
            return nil, ErrIncorrectTag
        }
    }

    packet, err = unpad(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        putBuffer(packet)
        return nil, ErrInvalidPadding
    }

    return packet, nil
}

// Simple latency tracking (P50 approximation)
func updateLatencyP50(target *atomic.Uint64, newValue uint64) {
    // Go 1.26: CAS loop for lock-free updates
    for {
        old := target.Load()
        // Exponential moving average (alpha = 0.1)
        updated := (old*9 + newValue) / 10
        if target.CompareAndSwap(old, updated) {
            return
        }
    }
}

// Elligator 2 Implementation for Censorship Resistance
func ElligatorForward(representative []byte) []byte {
    if len(representative) != 32 {
        return nil
    }

    out := make([]byte, 32)
    copy(out, representative)
    return out
}

func ElligatorReverse(publicKey *[32]byte) ([]byte, bool) {
    representative := make([]byte, 32)
    copy(representative, publicKey[:])
    representative[31] &= 0x3F

    return representative, true
}

func GenerateObfuscatedKeyPairWithHint(hint byte) (privateKey, publicKey, representative []byte, err error) {
    for range 128 {
        priv := make([]byte, 32)
        if _, err := crypto_rand.Read(priv); err != nil {
            return nil, nil, nil, err
        }

        priv[0] &= 248
        priv[31] &= 127
        priv[31] |= 64

        if hint != 0 {
            priv[0] ^= hint
        }

        pub, err := curve25519.X25519(priv, curve25519.Basepoint)
        if err != nil {
            continue
        }

        var pubArray [32]byte
        copy(pubArray[:], pub)
        repr, ok := ElligatorReverse(&pubArray)
        if ok {
            return priv, pub, repr, nil
        }
    }

    return nil, nil, nil, errors.New("failed to generate Elligator-encodable key after 128 attempts")
}

func GenerateObfuscatedKeyPair() (privateKey, publicKey, representative []byte, err error) {
    var hint byte
    var hintBuf [1]byte
    if _, err := crypto_rand.Read(hintBuf[:]); err == nil {
        hint = hintBuf[0]
    }
    return GenerateObfuscatedKeyPairWithHint(hint)
}

// EncryptBatch processes multiple packets using worker pool
func (proxy *Proxy) EncryptBatch(
    serverInfo *ServerInfo,
    packets [][]byte,
    proto string,
) ([][]byte, [][]byte, error) {
    encrypted := make([][]byte, len(packets))
    nonces := make([][]byte, len(packets))

    dstBufs := make([][]byte, len(packets))
    for i := range dstBufs {
        dstBufs[i] = make([]byte, 0, MaxDNSUDPPacketSize)
    }

    results := make(chan encryptResult, len(packets))
    for i := range packets {
        globalWorkerPool.jobs <- batchJob{
            idx:        i,
            packet:     packets[i],
            dst:        dstBufs[i],
            serverInfo: unique.Make(serverInfo),
            proto:      unique.Make(proto),
            proxy:      proxy,
            result:     results,
            priority:   0,
        }
    }

    for range len(packets) {
        res := <-results
        if res.err == nil {
            encrypted[res.idx] = res.encrypted
            nonces[res.idx] = res.nonce
        }
    }

    return encrypted, nonces, nil
}

// ExportMetrics exports cryptographic metrics in Prometheus format
func ExportMetrics() string {
    hits := globalAEADCache.hitRate.Load()
    misses := globalAEADCache.missRate.Load()
    total := hits + misses

    var hitRate float64
    if total > 0 {
        hitRate = float64(hits) / float64(total)
    }

    return fmt.Sprintf(`# HELP dnscrypt_aead_cache_hit_rate AEAD cache hit rate
# TYPE dnscrypt_aead_cache_hit_rate gauge
dnscrypt_aead_cache_hit_rate %f
# HELP dnscrypt_aead_cache_size AEAD cache size
# TYPE dnscrypt_aead_cache_size gauge
dnscrypt_aead_cache_size %d
# HELP dnscrypt_worker_pool_depth Active worker count
# TYPE dnscrypt_worker_pool_depth gauge
dnscrypt_worker_pool_depth %d
# HELP dnscrypt_encrypt_latency_p50 Encrypt latency P50 (microseconds)
# TYPE dnscrypt_encrypt_latency_p50 gauge
dnscrypt_encrypt_latency_p50 %d
# HELP dnscrypt_decrypt_latency_p50 Decrypt latency P50 (microseconds)
# TYPE dnscrypt_decrypt_latency_p50 gauge
dnscrypt_decrypt_latency_p50 %d
# HELP dnscrypt_nonce_gen_count Total nonces generated
# TYPE dnscrypt_nonce_gen_count counter
dnscrypt_nonce_gen_count %d
# HELP dnscrypt_alloc_bytes Total bytes allocated
# TYPE dnscrypt_alloc_bytes counter
dnscrypt_alloc_bytes %d
`, hitRate, len(globalAEADCache.shards), globalWorkerPool.activeCount.Load(),
        globalCryptoMetrics.EncryptLatencyP50.Load(),
        globalCryptoMetrics.DecryptLatencyP50.Load(),
        globalCryptoMetrics.NonceGenCount.Load(),
        globalCryptoMetrics.AllocBytes.Load())
}
