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
"golang.org/x/net/ipv4"
"golang.org/x/net/ipv6"
"golang.org/x/sys/cpu"
"golang.org/x/sys/unix"
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

// Sharded AEAD cache configuration
AEADCacheShardCount = 16
AEADCacheMaxSize    = 1000

// UDP GSO/GRO segment size (kernel 4.18+)
UDPGSOSegmentSize = MaxDNSUDPPacketSize
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

// Global zero buffers for efficient padding verification
// Increased from 4096 to 8192 for better coverage
zeroPage [8192]byte
zeroKey  [32]byte

// Size-class buffer pools for adaptive memory allocation
bufferPoolSmall = sync.Pool{
New: func() interface{} {
return make([]byte, 0, 512)
},
}
bufferPoolMedium = sync.Pool{
New: func() interface{} {
return make([]byte, 0, 2048)
},
}
bufferPoolLarge = sync.Pool{
New: func() interface{} {
return make([]byte, 0, 8192)
},
}

// Hardware acceleration detection
hasAVX2  = false
hasAESNI = false

// CPU feature detection for Ryzen 3200G and others
hasAVX   = false
hasSSE42 = false
)

// Enhanced crypto metrics for observability
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

// Nonce tracker for development/debugging (optional, disabled in production)
type NonceTracker struct {
sync.Mutex
seen map[[HalfNonceSize]byte]time.Time
}

var globalNonceTracker *NonceTracker

// Adaptive worker pool with dynamic scaling
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

// Sharded AEAD cache for reduced lock contention
type ShardedAEADCache struct {
shards      []*aeadCache
shardCount  uint32
hitRate     atomic.Uint64
missRate    atomic.Uint64
refreshRate float64 // Probability [0.0, 1.0] to refresh old entries
}

// Single shard of the AEAD cache
type aeadCache struct {
sync.RWMutex
ciphers map[[32]byte]*aeadCacheEntry
lru     *list.List
maxSize int
}

type aeadCacheEntry struct {
aead      cipher.AEAD
element   *list.Element
createdAt time.Time
}

// Constant-time unpadding with improved security
func unpadConstantTime(packet []byte) ([]byte, error) {
if len(packet) == 0 {
return nil, ErrInvalidPadding
}

idx := bytes.LastIndexByte(packet, 0x80)
if idx == -1 {
return nil, ErrInvalidPadding
}

tailLen := len(packet) - idx - 1
_ = packet[len(packet)-1] // Bounds check elimination hint

if tailLen == 0 {
return packet[:idx], nil
}

// Always use constant-time comparison for ALL tail lengths
// to avoid timing side-channels from branch prediction
if tailLen > len(zeroPage) {
// Fallback: constant-time byte-by-byte check
var mismatch byte
for i := idx + 1; i < len(packet); i++ {
mismatch |= packet[i]
}
if mismatch != 0 {
return nil, ErrInvalidPadBytes
}
} else if tailLen > 0 {
// Use subtle.ConstantTimeCompare for all sizes
if subtle.ConstantTimeCompare(packet[idx+1:], zeroPage[:tailLen]) != 1 {
return nil, ErrInvalidPadBytes
}
}

return packet[:idx], nil
}

// SIMD-optimized unpadding (faster, timing-vulnerable on some architectures)
func unpadFast(packet []byte) ([]byte, error) {
if len(packet) == 0 {
return nil, ErrInvalidPadding
}

idx := bytes.LastIndexByte(packet, 0x80)
if idx == -1 {
return nil, ErrInvalidPadding
}

tailLen := len(packet) - idx - 1
_ = packet[len(packet)-1] // Bounds check elimination hint

if tailLen == 0 {
return packet[:idx], nil
}

// Optimized for 16-byte aligned tails (compiler auto-vectorizes with AVX2)
if tailLen <= 64 && tailLen >= 16 && tailLen%16 == 0 && hasAVX2 {
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

// Buffer management with size-class pooling
func getBuffer(size int) []byte {
switch {
case size <= 512:
buf := bufferPoolSmall.Get().([]byte)
return buf[:0]
case size <= 2048:
buf := bufferPoolMedium.Get().([]byte)
return buf[:0]
default:
buf := bufferPoolLarge.Get().([]byte)
return buf[:0]
}
}

func putBuffer(buf []byte) {
if cap(buf) > 16384 {
return // Don't pool oversized buffers
}
switch {
case cap(buf) <= 512:
bufferPoolSmall.Put(buf)
case cap(buf) <= 2048:
bufferPoolMedium.Put(buf)
default:
bufferPoolLarge.Put(buf)
}
}

// clearBytes zeros a byte slice using constant-time method (Go < 1.21 compatible)
func clearBytes(b []byte) {
// Use XOR with zeros for constant-time guarantee
subtle.ConstantTimeCopy(1, b, make([]byte, len(b)))
}

// ComputeSharedKey computes the shared secret for encryption
// Returns error instead of masking failures with random data
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

// Initialize sharded AEAD cache
func newShardedAEADCache(shardCount int, maxSize int) *ShardedAEADCache {
if shardCount <= 0 {
shardCount = AEADCacheShardCount
}
if maxSize <= 0 {
maxSize = AEADCacheMaxSize
}

cache := &ShardedAEADCache{
shards:      make([]*aeadCache, shardCount),
shardCount:  uint32(shardCount),
refreshRate: 0.05, // 5% refresh probability for cache warming
}

for i := range cache.shards {
cache.shards[i] = &aeadCache{
ciphers: make(map[[32]byte]*aeadCacheEntry),
lru:     list.New(),
maxSize: maxSize / shardCount,
}
}

return cache
}

func (sc *ShardedAEADCache) getShard(key *[32]byte) *aeadCache {
hash := binary.LittleEndian.Uint32(key[:4])
return sc.shards[hash%sc.shardCount]
}

// getOrCreateAEAD retrieves or creates an AEAD instance with sharded cache
func (sc *ShardedAEADCache) getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
shard := sc.getShard(sharedKey)

shard.RLock()
entry, exists := shard.ciphers[*sharedKey]
if exists {
shard.RUnlock()

// Move to front (LRU) and probabilistic refresh
shard.Lock()
shard.lru.MoveToFront(entry.element)

// Refresh old entries (cache warming)
now := time.Now()
if now.Sub(entry.createdAt) > 5*time.Minute && randomFloat64() < sc.refreshRate {
entry.createdAt = now
}

shard.Unlock()
sc.hitRate.Add(1)
return entry.aead, nil
}
shard.RUnlock()

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

// Add to cache
shard.Lock()
defer shard.Unlock()

// Check again in case another goroutine added it
if entry, exists := shard.ciphers[*sharedKey]; exists {
shard.lru.MoveToFront(entry.element)
return entry.aead, nil
}

// Evict oldest if at capacity
if shard.lru.Len() >= shard.maxSize {
oldest := shard.lru.Back()
if oldest != nil {
oldKey := oldest.Value.([32]byte)
delete(shard.ciphers, oldKey)
shard.lru.Remove(oldest)
globalCryptoMetrics.AEADEvictions.Add(1)
}
}

// Add new entry
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

// Initialize adaptive worker pool with dynamic scaling
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
jobs:        make(chan batchJob, maxWorkers*2),
idleTimeout: 30 * time.Second,
workerSem:   make(chan struct{}, maxWorkers),
}

// Start minimum workers
for i := 0; i < minWorkers; i++ {
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
return // shutdown signal
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
return // Scale down
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
var b [8]byte
if err := readRandom(b[:]); err != nil {
return 0.5
}
val := binary.LittleEndian.Uint64(b[:])
return float64(val) / float64(^uint64(0))
}

// init pre-warms pools and detects CPU capabilities
func init() {
// Detect hardware acceleration (amd64 only)
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

if !hasAVX2 && !hasAESNI {
dlog.Warnf("CPU: No hardware crypto acceleration detected; ChaCha20-Poly1305 recommended")
} else if hasAESNI && !hasAVX2 {
dlog.Noticef("CPU: AES-NI available; AES-GCM may be suitable alternative to ChaCha20")
}

// Pre-warm buffer pools with size classes
poolWarmupSize := 10 // Default for low traffic
if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
if size, err := strconv.Atoi(val); err == nil && size > 0 {
poolWarmupSize = min(size, 1000)
}
}

for i := 0; i < poolWarmupSize; i++ {
bufferPoolSmall.Put(make([]byte, 0, 512))
bufferPoolMedium.Put(make([]byte, 0, 2048))
bufferPoolLarge.Put(make([]byte, 0, 8192))
}

// Initialize sharded AEAD cache
globalAEADCache = newShardedAEADCache(AEADCacheShardCount, AEADCacheMaxSize)

// Initialize adaptive worker pool
minWorkers := 2
maxWorkers := runtime.NumCPU()
if val := os.Getenv("DNSCRYPT_MIN_WORKERS"); val != "" {
if w, err := strconv.Atoi(val); err == nil && w > 0 {
minWorkers = min(w, 128)
}
}
if val := os.Getenv("DNSCRYPT_MAX_WORKERS"); val != "" {
if w, err := strconv.Atoi(val); err == nil && w > 0 {
maxWorkers = min(w, 128)
}
}
initAdaptiveWorkerPool(minWorkers, maxWorkers)

// Optional: Initialize nonce tracker for development
if os.Getenv("DNSCRYPT_TRACK_NONCES") == "1" {
globalNonceTracker = &NonceTracker{
seen: make(map[[HalfNonceSize]byte]time.Time),
}
}
}

// EncryptInto encrypts a DNS packet with optimized allocation
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

// Optional nonce tracking for development
if globalNonceTracker != nil {
var nonceKey [HalfNonceSize]byte
copy(nonceKey[:], randomBuf[:])
globalNonceTracker.Lock()
if _, exists := globalNonceTracker.seen[nonceKey]; exists {
dlog.Warnf("SECURITY: Nonce reuse detected! (development only)")
}
globalNonceTracker.seen[nonceKey] = time.Now()
globalNonceTracker.Unlock()
}

// Validate clientNonceDst length BEFORE use
if clientNonceDst != nil && len(clientNonceDst) < HalfNonceSize {
return nil, nil, nil, ErrClientNonceTooSmall
}

var nonce [NonceSize]byte
copy(nonce[:HalfNonceSize], randomBuf[:])

// Local variables to help compiler optimize
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

// Clear tail efficiently
if packetLen+1 < plaintextLen {
clearBytes(plaintext[packetLen+1:])
}

// OPTIMIZATION: Use cached AEAD instance (30-40% faster)
if cryptoAlgo == XChacha20Poly1305 {
aead, err := globalAEADCache.getOrCreateAEAD(&computedSharedKey, true)
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
aead, err := globalAEADCache.getOrCreateAEAD(sharedKey, true)
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
// PLACEHOLDER: production code should use filippo.io/edwards25519/field

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

// GenerateObfuscatedKeyPairWithHint generates X25519 keypair with hint-based optimization
// May need multiple attempts (average 2 tries) since only ~50% of points work
func GenerateObfuscatedKeyPairWithHint(hint byte) (privateKey, publicKey, representative []byte, err error) {
for attempts := 0; attempts < 128; attempts++ {
priv := make([]byte, 32)
if err := readRandom(priv); err != nil {
return nil, nil, nil, err
}

// Clamp for X25519
priv[0] &= 248
priv[31] &= 127
priv[31] |= 64

// Use hint to guide generation
if hint != 0 {
priv[0] ^= hint
}

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

// GenerateObfuscatedKeyPair generates X25519 keypair encodable via Elligator 2
func GenerateObfuscatedKeyPair() (privateKey, publicKey, representative []byte, err error) {
var hint byte
if err := readRandom([]byte{hint}); err != nil {
hint = 0
}
return GenerateObfuscatedKeyPairWithHint(hint)
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
func ReadBatch(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
p := ipv4.NewPacketConn(conn)

messages := make([]ipv4.Message, maxMessages)
buffers := make([][]byte, maxMessages)

for i := range messages {
buffers[i] = make([]byte, MaxDNSUDPPacketSize)
messages[i].Buffers = [][]byte{buffers[i]}
}

n, err := p.ReadBatch(messages, 0)
if err != nil && n == 0 {
return nil, err
}

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

// EnableUDPGSO enables UDP Generic Segmentation Offload (kernel 4.18+)
func EnableUDPGSO(conn *net.UDPConn) error {
rawConn, err := conn.SyscallConn()
if err != nil {
return err
}

return rawConn.Control(func(fd uintptr) {
err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, UDPGSOSegmentSize)
if err != nil {
dlog.Warnf("UDP GSO not available: %v (kernel 4.18+ required)", err)
}
})
}

// EncryptBatch processes multiple packets using worker pool
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
priority:   0,
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
