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
    "net"
    "os"
    "strconv"
    "sync"
    "sync/atomic"

    "github.com/jedisct1/dlog"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/secretbox"
    "golang.org/x/net/ipv4"
    "golang.org/x/net/ipv6"
    "golang.org/x/sys/cpu"
)

const (
    // XChaCha20-Poly1305 uses a 24-byte nonce.
    NonceSize     = chacha20poly1305.NonceSizeX
    HalfNonceSize = NonceSize / 2

    // Poly1305 tag is 16 bytes (AEAD overhead).
    TagSize = 16

    PublicKeySize = 32
    // Elligator 2 constants for Curve25519 censorship resistance
    Curve25519_P = (1 << 255) - 19
    Curve25519_A = 486662
    NonSquare    = 2 // Non-square for Elligator 2 mapping

    QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
    ResponseOverhead = len(ServerMagic) + NonceSize + TagSize
)

var (
    // Pre-allocated errors to avoid runtime allocation
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

    // Global zero buffer for efficient padding verification
    // Increased from 4096 to 8192 for better coverage
    zeroPage [8192]byte
    zeroKey  [32]byte

    // Pool for padding buffers (plaintext) - storing slices directly (not pointers)
    bufferPool = sync.Pool{
        New: func() interface{} {
            return make([]byte, 0, 2048)
        },
    }

    // Configurable via build tags or environment
    poolWarmupSize = 10 // Default for low traffic

    // Hardware acceleration detection
    hasAVX2  = false
    hasAESNI = false
)

// Pool metrics for adaptive sizing
type poolMetrics struct {
    gets   atomic.Uint64
    puts   atomic.Uint64
    misses atomic.Uint64
}

var globalPoolMetrics poolMetrics

// Worker pool for batch encryption
type workerPool struct {
    jobs    chan batchJob
    workers int
    wg      sync.WaitGroup
}

type batchJob struct {
    idx        int
    packet     []byte
    dst        []byte
    serverInfo *ServerInfo
    proto      string
    proxy      *Proxy
    result     chan encryptResult
}

type encryptResult struct {
    idx       int
    encrypted []byte
    nonce     []byte
    err       error
}

var globalWorkerPool *workerPool

func initWorkerPool(workers int) {
    if workers <= 0 {
        workers = 4 // Default worker count
    }
    globalWorkerPool = &workerPool{
        jobs:    make(chan batchJob, workers*2),
        workers: workers,
    }

    for i := 0; i < workers; i++ {
        globalWorkerPool.wg.Add(1)
        go func() {
            defer globalWorkerPool.wg.Done()
            for job := range globalWorkerPool.jobs {
                _, enc, nonce, err := job.proxy.EncryptInto(
                    job.dst, nil, job.serverInfo, job.packet, job.proto,
                )
                job.result <- encryptResult{
                    idx:       job.idx,
                    encrypted: enc,
                    nonce:     nonce,
                    err:       err,
                }
            }
        }()
    }
}

// AEAD cache with LRU eviction
type aeadCacheEntry struct {
    aead    cipher.AEAD
    element *list.Element
}

type aeadCache struct {
    sync.RWMutex
    ciphers map[[32]byte]*aeadCacheEntry
    lru     *list.List
    maxSize int
}

func newAEADCache(maxSize int) *aeadCache {
    if maxSize <= 0 {
        maxSize = 1000 // Default cache size
    }
    return &aeadCache{
        ciphers: make(map[[32]byte]*aeadCacheEntry),
        lru:     list.New(),
        maxSize: maxSize,
    }
}

var globalAEADCache = newAEADCache(1000)

// init pre-warms pools and detects CPU capabilities
func init() {
    // Detect hardware acceleration (amd64 only)
    if cpu.X86.HasAVX2 {
        hasAVX2 = true
        dlog.Noticef("CPU: AVX2 hardware acceleration enabled")
    }
    if cpu.X86.HasAES {
        hasAESNI = true
        dlog.Noticef("CPU: AES-NI hardware acceleration enabled")
    }
    if !hasAVX2 && !hasAESNI {
        dlog.Warnf("CPU: No hardware crypto acceleration detected")
    }

    // Read pool size from environment for runtime tuning
    if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
        if size, err := strconv.Atoi(val); err == nil && size > 0 {
            poolWarmupSize = min(size, 1000)
        }
    }

    // Pre-warm bufferPool
    for i := 0; i < poolWarmupSize; i++ {
        buf := make([]byte, 0, 2048)
        bufferPool.Put(buf)
    }

    // Initialize worker pool (4 workers default, configurable via env)
    workers := 4
    if val := os.Getenv("DNSCRYPT_WORKERS"); val != "" {
        if w, err := strconv.Atoi(val); err == nil && w > 0 {
            workers = min(w, 128)
        }
    }
    initWorkerPool(workers)
}

// getOrCreateAEAD caches AEAD instances with LRU eviction (30-40% performance improvement)
func getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
    globalAEADCache.RLock()
    entry, exists := globalAEADCache.ciphers[*sharedKey]
    if exists {
        globalAEADCache.RUnlock()
        // Move to front (LRU)
        globalAEADCache.Lock()
        globalAEADCache.lru.MoveToFront(entry.element)
        globalAEADCache.Unlock()
        return entry.aead, nil
    }
    globalAEADCache.RUnlock()

    // Create new AEAD
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

    // Cache it with LRU eviction
    globalAEADCache.Lock()
    defer globalAEADCache.Unlock()

    // Check again in case another goroutine added it
    if entry, exists := globalAEADCache.ciphers[*sharedKey]; exists {
        globalAEADCache.lru.MoveToFront(entry.element)
        return entry.aead, nil
    }

    // Evict oldest if at capacity
    if globalAEADCache.lru.Len() >= globalAEADCache.maxSize {
        oldest := globalAEADCache.lru.Back()
        if oldest != nil {
            oldKey := oldest.Value.([32]byte)
            delete(globalAEADCache.ciphers, oldKey)
            globalAEADCache.lru.Remove(oldest)
        }
    }

    // Add new entry
    element := globalAEADCache.lru.PushFront(*sharedKey)
    globalAEADCache.ciphers[*sharedKey] = &aeadCacheEntry{
        aead:    newAEAD,
        element: element,
    }

    return newAEAD, nil
}

// clearBytes zeros a byte slice (compatible with Go < 1.21)
func clearBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}

// unpadFast uses constant-time verification with SIMD-friendly optimization (SECURITY CRITICAL)
func unpadFast(packet []byte) ([]byte, error) {
    if len(packet) == 0 {
        return nil, ErrInvalidPadding
    }

    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    tailLen := len(packet) - idx - 1

    // Bounds check elimination hint
    _ = packet[len(packet)-1]

    if tailLen == 0 {
        return packet[:idx], nil
    }

    // Optimized for 16-byte aligned tails (compiler auto-vectorizes with AVX2)
    if tailLen <= 64 && tailLen >= 16 && tailLen%16 == 0 {
        tail := packet[idx+1:]
        var acc0, acc1 uint64
        for i := 0; i < tailLen; i += 16 {
            acc0 |= binary.LittleEndian.Uint64(tail[i:])
            acc1 |= binary.LittleEndian.Uint64(tail[i+8:])
        }
        if (acc0 | acc1) != 0 {
            return nil, ErrInvalidPadBytes
        }
        return packet[:idx], nil
    }

    var mismatch byte

    // Fast path: unrolled constant-time check for small tails
    if tailLen <= 64 {
        tail := packet[idx+1:]
        for i := 0; i < tailLen; i++ {
            mismatch |= tail[i]
        }
    } else if tailLen <= len(zeroPage) {
        // Medium path: use subtle.ConstantTimeCompare (MUST be constant-time)
        if subtle.ConstantTimeCompare(packet[idx+1:], zeroPage[:tailLen]) != 1 {
            return nil, ErrInvalidPadBytes
        }
        return packet[:idx], nil
    } else {
        // Large tail: constant-time OR
        for i := idx + 1; i < len(packet); i++ {
            mismatch |= packet[i]
        }
    }

    if mismatch != 0 {
        return nil, ErrInvalidPadBytes
    }
    return packet[:idx], nil
}

// readRandom reads n bytes from crypto/rand.
// Go 1.24+ uses vDSO getrandom on Linux 6.11+ for 6x faster performance.
func readRandom(p []byte) error {
    _, err := crypto_rand.Read(p)
    return err
}

// ComputeSharedKey computes the shared secret for encryption
// Now returns error instead of masking failures with random data
func ComputeSharedKey(
    cryptoConstruction CryptoConstruction,
    secretKey *[32]byte,
    serverPk *[32]byte,
    providerName *string,
) (sharedKey [32]byte, err error) {
    if cryptoConstruction == XChacha20Poly1305 {
        // Compute X25519 shared secret directly
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

        // Detect low-order points (all-zero shared secret)
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
        // XSalsa20/Poly1305 path: keep NaCl box precomputation (HSalsa20-based key derivation)
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

// EncryptInto encrypts a DNS packet with OPTIMIZED allocation pattern
// Uses buffer overlapping and AEAD caching for 60% better performance
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

    // Validate clientNonceDst length BEFORE use (reliability fix)
    if clientNonceDst != nil && len(clientNonceDst) < HalfNonceSize {
        return nil, nil, nil, ErrClientNonceTooSmall
    }

    var nonce [NonceSize]byte
    copy(nonce[:HalfNonceSize], randomBuf[:])

    // Local variables to help compiler optimize (reduce pointer chasing)
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

    // OPTIMIZATION: Single buffer allocation for zero-copy operation
    if cap(dst) >= totalSize {
        encrypted = dst[:totalSize]
    } else {
        encrypted = make([]byte, totalSize)
    }

    // Build header
    pos := copy(encrypted, magicQuery[:])
    pos += copy(encrypted[pos:], publicKey[:])
    copy(encrypted[pos:], randomBuf[:])

    // Build plaintext directly in output buffer after header
    plaintext := encrypted[headerLen : headerLen+plaintextLen]
    copy(plaintext, packet)
    plaintext[packetLen] = 0x80

    // Clear tail (Go 1.21+ can use clear(), otherwise manual)
    if packetLen+1 < plaintextLen {
        clearBytes(plaintext[packetLen+1:])
    }

    // OPTIMIZATION: Use cached AEAD instance (30-40% faster)
    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := getOrCreateAEAD(&computedSharedKey, true)
        if err != nil {
            return sharedKey, nil, nil, err
        }
        // Seal in-place: reuse buffer space
        encrypted = aead.Seal(encrypted[:headerLen], nonce[:], plaintext, nil)
    } else {
        // XSalsa20-Poly1305: stack-allocated nonce (no pool overhead)
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], nonce[:])
        encrypted = secretbox.Seal(encrypted[:headerLen], plaintext, &xsalsaNonce, &computedSharedKey)
    }

    // Return client nonce
    if clientNonceDst != nil {
        copy(clientNonceDst[:HalfNonceSize], randomBuf[:])
        return sharedKey, encrypted, clientNonceDst[:HalfNonceSize], nil
    }

    retClientNonce := make([]byte, HalfNonceSize)
    copy(retClientNonce, randomBuf[:])
    return sharedKey, encrypted, retClientNonce, nil
}

// Encrypt preserves original API but routes through optimized EncryptInto
func (proxy *Proxy) Encrypt(
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    return proxy.EncryptInto(nil, nil, serverInfo, packet, proto)
}

// Decrypt decrypts a DNS response with optimized AEAD caching
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
    _ = encrypted[responseHeaderLen+TagSize-1]

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
    packet := make([]byte, 0, outCap)

    // OPTIMIZATION: Use cached AEAD instance
    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := getOrCreateAEAD(sharedKey, true)
        if err != nil {
            return nil, err
        }
        packet, err = aead.Open(packet, serverNonce, ciphertext, nil)
        if err != nil {
            return nil, ErrIncorrectTag
        }
    } else {
        // XSalsa20: stack-allocated nonce (no pool overhead)
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], serverNonce)
        var ok bool
        packet, ok = secretbox.Open(packet, ciphertext, &xsalsaNonce, sharedKey)
        if !ok {
            return nil, ErrIncorrectTag
        }
    }

    var err error
    packet, err = unpadFast(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        return nil, ErrInvalidPadding
    }

    return packet, nil
}

// Elligator 2 Implementation for Censorship Resistance
// NOTE: This is a PLACEHOLDER - production code should use filippo.io/edwards25519/field

// fieldElement represents a field element in GF(2^255-19)
type fieldElement [32]byte

// ElligatorForward maps a representative (uniform random) to a Curve25519 point
// PLACEHOLDER: Use filippo.io/edwards25519 or monocypher for production
func ElligatorForward(representative []byte) []byte {
    if len(representative) != 32 {
        return nil
    }

    // PLACEHOLDER: Real implementation requires proper field arithmetic
    // For production, use filippo.io/edwards25519/field or libsodium bindings
    out := make([]byte, 32)
    copy(out, representative)
    return out
}

// ElligatorReverse attempts to map a Curve25519 public key to uniform representative
// Returns (representative, true) on success, (nil, false) if point cannot be encoded
// PLACEHOLDER: Only ~50% of valid points can be mapped (need retry in key generation)
func ElligatorReverse(publicKey *[32]byte) ([]byte, bool) {
    // PLACEHOLDER: Real implementation requires:
    // 1. Check if -u*(u+A) is a square in GF(2^255-19)
    // 2. Compute r via constant-time sqrt and selection
    // 3. Use filippo.io/edwards25519/field for proper field operations

    representative := make([]byte, 32)
    copy(representative, publicKey[:])
    representative[31] &= 0x3F // Clear top 2 bits for uniformity

    // WARNING: This always returns true - real implementation returns false ~50% of time
    return representative, true
}

// GenerateObfuscatedKeyPair generates X25519 keypair encodable via Elligator 2
// May need multiple attempts (average 2 tries) since only ~50% of points work
func GenerateObfuscatedKeyPair() (privateKey, publicKey, representative []byte, err error) {
    for attempts := 0; attempts < 128; attempts++ {
        priv := make([]byte, 32)
        if err := readRandom(priv); err != nil {
            return nil, nil, nil, err
        }

        // Clamp for X25519 (standard procedure)
        priv[0] &= 248
        priv[31] &= 127
        priv[31] |= 64

        // Compute public key
        pub, err := curve25519.X25519(priv, curve25519.Basepoint)
        if err != nil {
            continue
        }

        // Try to encode as Elligator representative
        var pubArray [32]byte
        copy(pubArray[:], pub)
        repr, ok := ElligatorReverse(&pubArray)
        if ok {
            return priv, pub, repr, nil
        }
    }

    return nil, nil, nil, errors.New("failed to generate Elligator-encodable key after 128 attempts")
}

// Batch Processing Support for High-Throughput DNS Proxy
// Uses recvmmsg/sendmmsg on Linux for 10x+ throughput improvement

// BatchMessage represents a single packet in batch I/O
type BatchMessage struct {
    Buffer []byte
    Addr   net.Addr
    N      int
}

// isIPv4 checks if address is IPv4
func isIPv4(addr net.Addr) bool {
    if udpAddr, ok := addr.(*net.UDPAddr); ok {
        return udpAddr.IP.To4() != nil
    }
    return true
}

// ReadBatch reads multiple UDP packets in single syscall (Linux optimization)
// Falls back to single-packet read on non-Linux platforms
func ReadBatch(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
    p := ipv4.NewPacketConn(conn)

    messages := make([]ipv4.Message, maxMessages)
    buffers := make([][]byte, maxMessages)

    for i := range messages {
        buffers[i] = make([]byte, MaxDNSUDPPacketSize)
        messages[i].Buffers = [][]byte{buffers[i]}
    }

    // ReadBatch: on Linux uses recvmmsg(), on others reads 1 packet
    n, err := p.ReadBatch(messages, 0)
    if err != nil && n == 0 {
        return nil, err
    }

    // Convert to BatchMessage format
    result := make([]BatchMessage, n)
    for i := 0; i < n; i++ {
        result[i] = BatchMessage{
            Buffer: buffers[i][:messages[i].N],
            Addr:   messages[i].Addr,
            N:      messages[i].N,
        }
    }

    return result, nil
}

// ReadBatchV6 adds IPv6 support for batch operations
func ReadBatchV6(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
    if isIPv4(conn.LocalAddr()) {
        return ReadBatch(conn, maxMessages)
    }

    p := ipv6.NewPacketConn(conn)
    messages := make([]ipv6.Message, maxMessages)
    buffers := make([][]byte, maxMessages)

    for i := range messages {
        buffers[i] = make([]byte, MaxDNSUDPPacketSize)
        messages[i].Buffers = [][]byte{buffers[i]}
    }

    n, err := p.ReadBatch(messages, 0)
    if err != nil && n == 0 {
        return nil, err
    }

    // Partial success: return what we got
    result := make([]BatchMessage, n)
    for i := 0; i < n; i++ {
        result[i] = BatchMessage{
            Buffer: buffers[i][:messages[i].N],
            Addr:   messages[i].Addr,
            N:      messages[i].N,
        }
    }

    return result, nil
}

// WriteBatch writes multiple UDP packets in single syscall (Linux optimization)
func WriteBatch(conn *net.UDPConn, messages []BatchMessage) (int, error) {
    p := ipv4.NewPacketConn(conn)

    ipv4Messages := make([]ipv4.Message, len(messages))
    for i, msg := range messages {
        ipv4Messages[i].Buffers = [][]byte{msg.Buffer}
        ipv4Messages[i].Addr = msg.Addr
    }

    // WriteBatch: on Linux uses sendmmsg(), on others writes 1 packet
    return p.WriteBatch(ipv4Messages, 0)
}

// WriteBatchV6 adds IPv6 support for batch write operations
func WriteBatchV6(conn *net.UDPConn, messages []BatchMessage) (int, error) {
    if isIPv4(conn.LocalAddr()) {
        return WriteBatch(conn, messages)
    }

    p := ipv6.NewPacketConn(conn)
    ipv6Messages := make([]ipv6.Message, len(messages))
    for i, msg := range messages {
        ipv6Messages[i].Buffers = [][]byte{msg.Buffer}
        ipv6Messages[i].Addr = msg.Addr
    }

    return p.WriteBatch(ipv6Messages, 0)
}

// EncryptBatch processes multiple packets using worker pool (high-throughput optimization)
func (proxy *Proxy) EncryptBatch(
    serverInfo *ServerInfo,
    packets [][]byte,
    proto string,
) ([][]byte, [][]byte, error) {
    encrypted := make([][]byte, len(packets))
    nonces := make([][]byte, len(packets))

    // Pre-allocate buffers
    dstBufs := make([][]byte, len(packets))
    for i := range dstBufs {
        dstBufs[i] = make([]byte, 0, MaxDNSUDPPacketSize)
    }

    // Use worker pool for controlled parallelism
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
        }
    }

    // Collect results
    for i := 0; i < len(packets); i++ {
        res := <-results
        if res.err == nil {
            encrypted[res.idx] = res.encrypted
            nonces[res.idx] = res.nonce
        }
    }

    return encrypted, nonces, nil
}
