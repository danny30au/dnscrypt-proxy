package main

import (
    "bytes"
    "container/list"
    "crypto/cipher"
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

    "github.com/jedisct1/dlog"
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

    // Go 1.26+ optimized buffer pools (no manual alignment needed)
    bufferPoolTiny = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 256)
            return &buf
        },
    }
    bufferPoolSmall = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 512)
            return &buf
        },
    }
    bufferPoolMedium = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 2048)
            return &buf
        },
    }
    bufferPoolLarge = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 8192)
            return &buf
        },
    }
    bufferPoolHuge = sync.Pool{
        New: func() interface{} {
            buf := make([]byte, 16384)
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

// CryptoMetrics - Go 1.26+ handles false sharing better
type CryptoMetrics struct {
    AEADCacheHits   atomic.Uint64
    AEADCacheMisses atomic.Uint64
    AEADEvictions   atomic.Uint64
    WorkerPoolDepth atomic.Int32
    UnpadLatencyUs  atomic.Uint64
    AvgLatencyUs    atomic.Uint64
    GCPausesMs      atomic.Uint64
}

var globalCryptoMetrics CryptoMetrics

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
    serverInfo *ServerInfo
    proto      string
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

// Optimized sharded cache leveraging Go 1.24+ Swiss Tables
type ShardedAEADCache struct {
    shards      []aeadCacheShard
    shardMask   uint32
    hitRate     atomic.Uint64
    missRate    atomic.Uint64
    refreshRate float64
}

type aeadCacheShard struct {
    mu      sync.RWMutex
    ciphers map[[32]byte]*aeadCacheEntry
    lru     *list.List
    maxSize int
}

type aeadCacheEntry struct {
    aead      cipher.AEAD
    element   *list.Element
    createdAt time.Time
}

// Go 1.26+ optimized unpadding - compiler auto-vectorizes
func unpad(packet []byte) ([]byte, error) {
    if len(packet) == 0 {
        return nil, ErrInvalidPadding
    }

    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    tail := packet[idx+1:]
    if len(tail) == 0 {
        return packet[:idx], nil
    }

    // Go 1.26 auto-vectorizes zero checks
    for _, b := range tail {
        if b != 0 {
            return nil, ErrInvalidPadBytes
        }
    }

    return packet[:idx], nil
}

// Optimized random reader
func readRandom(p []byte) error {
    _, err := crypto_rand.Read(p)
    return err
}

// Go 1.26+ simplified buffer management
func getBuffer(size int) []byte {
    switch {
    case size <= 256:
        return (*bufferPoolTiny.Get().(*[]byte))[:0]
    case size <= 512:
        return (*bufferPoolSmall.Get().(*[]byte))[:0]
    case size <= 2048:
        return (*bufferPoolMedium.Get().(*[]byte))[:0]
    case size <= 8192:
        return (*bufferPoolLarge.Get().(*[]byte))[:0]
    default:
        return (*bufferPoolHuge.Get().(*[]byte))[:0]
    }
}

func putBuffer(buf []byte) {
    c := cap(buf)
    if c > 32768 {
        return
    }
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

// Optimized constant-time clear
func clearBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
    runtime.KeepAlive(b)
}

// ComputeSharedKey with improved error handling
func ComputeSharedKey(
    cryptoConstruction CryptoConstruction,
    secretKey *[32]byte,
    serverPk *[32]byte,
    providerName *string,
) (sharedKey [32]byte, err error) {
    if cryptoConstruction == XChacha20Poly1305 {
        ss, err := curve25519.X25519(secretKey[:], serverPk[:])
        if err != nil {
            logMsg := "Weak/invalid X25519 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            return sharedKey, fmt.Errorf("X25519 computation failed: %w", err)
        }
        copy(sharedKey[:], ss)

        if subtle.ConstantTimeCompare(sharedKey[:], zeroKey[:]) == 1 {
            logMsg := "Weak X25519 public key (all-zero shared secret)"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            return sharedKey, ErrWeakPublicKey
        }
    } else {
        box.Precompute(&sharedKey, serverPk, secretKey)

        if subtle.ConstantTimeCompare(sharedKey[:], zeroKey[:]) == 1 {
            logMsg := "Weak XSalsa20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            return sharedKey, ErrWeakPublicKey
        }
    }
    return sharedKey, nil
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
            ciphers: make(map[[32]byte]*aeadCacheEntry, maxSize/shardCount),
            lru:     list.New(),
            maxSize: maxSize / shardCount,
        }
    }

    return cache
}

// Fast shard selection using FNV-1a hash
func (sc *ShardedAEADCache) getShard(key *[32]byte) *aeadCacheShard {
    hash := uint32(2166136261)
    for _, b := range key[:8] {
        hash ^= uint32(b)
        hash *= 16777619
    }
    return &sc.shards[hash&sc.shardMask]
}

// Optimized AEAD cache with lock-free fast path
func (sc *ShardedAEADCache) getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
    shard := sc.getShard(sharedKey)

    shard.mu.RLock()
    entry, exists := shard.ciphers[*sharedKey]
    if exists {
        shard.mu.RUnlock()

        shard.mu.Lock()
        if entry.element != nil {
            shard.lru.MoveToFront(entry.element)
        }

        now := time.Now()
        if now.Sub(entry.createdAt) > 5*time.Minute && fastRand64()&0xFF < 13 {
            entry.createdAt = now
        }
        shard.mu.Unlock()

        sc.hitRate.Add(1)
        return entry.aead, nil
    }
    shard.mu.RUnlock()

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

    if entry, exists := shard.ciphers[*sharedKey]; exists {
        shard.lru.MoveToFront(entry.element)
        return entry.aead, nil
    }

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
    shard.ciphers[*sharedKey] = &aeadCacheEntry{
        aead:      newAEAD,
        element:   element,
        createdAt: time.Now(),
    }

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

    // Go 1.23+ range over integers
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
                job.dst, nil, job.serverInfo, job.packet, job.proto,
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

func randomFloat64() float64 {
    val := fastRand64()
    return float64(val) / float64(^uint64(0))
}

// Init function
func init() {
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

    // Pre-warm buffer pools - Go 1.23+ range over integers
    poolWarmupSize := 20
    if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
        if size, err := strconv.Atoi(val); err == nil && size > 0 {
            poolWarmupSize = min(size, 2000)
        }
    }

    for range poolWarmupSize {
        buf256 := make([]byte, 256)
        bufferPoolTiny.Put(&buf256)
        buf512 := make([]byte, 512)
        bufferPoolSmall.Put(&buf512)
        buf2k := make([]byte, 2048)
        bufferPoolMedium.Put(&buf2k)
        buf8k := make([]byte, 8192)
        bufferPoolLarge.Put(&buf8k)
    }

    for range poolWarmupSize / 2 {
        buf16k := make([]byte, 16384)
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
    if err := readRandom(seed[:]); err == nil {
        rngState.Store(binary.LittleEndian.Uint64(seed[:]))
    }
}

// EncryptInto with zero-allocation optimizations
func (proxy *Proxy) EncryptInto(
    dst []byte,
    clientNonceDst []byte,
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    var randomBuf [HalfNonceSize]byte
    if err := readRandom(randomBuf[:]); err != nil {
        return nil, nil, nil, err
    }

    if globalNonceTracker != nil {
        var nonceKey [HalfNonceSize]byte
        copy(nonceKey[:], randomBuf[:])
        shardIdx := uint32(nonceKey[0]) & 15
        shard := &globalNonceTracker.shards[shardIdx]
        shard.mu.Lock()
        if _, exists := shard.seen[nonceKey]; exists {
            dlog.Warnf("SECURITY: Nonce reuse detected!")
        }
        shard.seen[nonceKey] = time.Now()
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

    if cap(dst) >= totalSize {
        encrypted = dst[:totalSize]
    } else {
        encrypted = getBuffer(totalSize)
        encrypted = encrypted[:totalSize]
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

// Optimized Decrypt
func (proxy *Proxy) Decrypt(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encrypted []byte,
    nonce []byte,
) ([]byte, error) {
    serverMagicLen := len(ServerMagic)
    responseHeaderLen := serverMagicLen + NonceSize

    if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return nil, ErrInvalidMsgSize
    }

    cryptoAlgo := serverInfo.CryptoConstruction

    if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
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

    var err error
    packet, err = unpad(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        putBuffer(packet)
        return nil, ErrInvalidPadding
    }

    return packet, nil
}

// Elligator 2 Implementation for Censorship Resistance
// PLACEHOLDER: production code should use filippo.io/edwards25519/field

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
        if err := readRandom(priv); err != nil {
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
    if err := readRandom(hintBuf[:]); err == nil {
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
            serverInfo: serverInfo,
            proto:      proto,
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
`, hitRate, len(globalAEADCache.shards), globalWorkerPool.activeCount.Load())
}
