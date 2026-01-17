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
	"math"
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
	NonceSize     = chacha20poly1305.NonceSizeX
	HalfNonceSize = NonceSize / 2

	TagSize = 16

	PublicKeySize = 32

	Curve25519_P = (1 << 255) - 19
	Curve25519_A = 486662
	NonSquare    = 2

	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize

	AEADCacheShardCount = 16
	AEADCacheMaxSize    = 1000
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

	zeroPage [8192]byte
	zeroKey  [32]byte

	UDPGSOSegmentSize = 512

	// Buffer pools
	bufferPoolSmall  = sync.Pool{New: func() interface{} { return make([]byte, 0, 512) }}
	bufferPoolMedium = sync.Pool{New: func() interface{} { return make([]byte, 0, 2048) }}
	bufferPoolLarge  = sync.Pool{New: func() interface{} { return make([]byte, 0, 8192) }}

	// Batch buffer pool to reuse MaxDNSUDPPacketSize buffers
	batchBufferPool = sync.Pool{New: func() interface{} { return make([]byte, MaxDNSUDPPacketSize) }}

	// Pools for ipv4/ipv6 message wrappers
	ipv4MessagePool = sync.Pool{New: func() interface{} { return &ipv4.Message{} }}
	ipv6MessagePool = sync.Pool{New: func() interface{} { return &ipv6.Message{} }}

	hasAVX2  = false
	hasAESNI = false
	hasAVX   = false
	hasSSE42 = false
)

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

type NonceTracker struct {
	sync.Mutex
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
	scaleLock   sync.Mutex
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

type ShardedAEADCache struct {
	shards      []*aeadCache
	shardCount  uint32
	hitRate     atomic.Uint64
	missRate    atomic.Uint64
	refreshRate float64
}

type aeadCache struct {
	sync.RWMutex
	ciphers map[[32]byte]*aeadCacheEntry
	lru     *list.List
	maxSize int
	// local counter to avoid frequent global atomics
	localMisses uint64
}

type aeadCacheEntry struct {
	aead      cipher.AEAD
	element   *list.Element
	createdAt time.Time
}

// readRandom reads n bytes into p without extra allocations
func readRandom(p []byte) error {
	_, err := crypto_rand.Read(p)
	return err
}

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
		return
	}
	switch {
	case cap(buf) <= 512:
		bufferPoolSmall.Put(buf[:0])
	case cap(buf) <= 2048:
		bufferPoolMedium.Put(buf[:0])
	default:
		bufferPoolLarge.Put(buf[:0])
	}
}

// clearBytes zeros a byte slice using a pooled zero buffer to avoid allocations
func clearBytes(b []byte) {
	n := len(b)
	if n == 0 {
		return
	}
	// Use zeroPage directly when small
	if n <= len(zeroPage) {
		copy(b, zeroPage[:n])
		return
	}
	// For larger slices, copy in chunks
	off := 0
	for off < n {
		chunk := n - off
		if chunk > len(zeroPage) {
			chunk = len(zeroPage)
		}
		copy(b[off:off+chunk], zeroPage[:chunk])
		off += chunk
	}
}

// ComputeSharedKey computes the shared secret for encryption
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
		refreshRate: 0.05,
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

func (sc *ShardedAEADCache) getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
	shard := sc.getShard(sharedKey)

	// Fast read path
	shard.RLock()
	entry, exists := shard.ciphers[*sharedKey]
	if exists {
		// update LRU under write lock
		shard.RUnlock()
		shard.Lock()
		shard.lru.MoveToFront(entry.element)
		// probabilistic refresh without calling time.Now() every time
		if time.Since(entry.createdAt) > 5*time.Minute && randomFloat64() < sc.refreshRate {
			entry.createdAt = time.Now()
		}
		shard.Unlock()
		sc.hitRate.Add(1)
		return entry.aead, nil
	}
	shard.RUnlock()

	// Miss: create AEAD without holding shard lock
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

	// Insert under write lock
	shard.Lock()
	// double-check
	if entry, exists := shard.ciphers[*sharedKey]; exists {
		shard.lru.MoveToFront(entry.element)
		shard.Unlock()
		sc.hitRate.Add(1)
		return entry.aead, nil
	}
	// Evict if needed
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
	shard.Unlock()

	sc.missRate.Add(1)
	return newAEAD, nil
}

var globalAEADCache *ShardedAEADCache

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

	for i := 0; i < minWorkers; i++ {
		globalWorkerPool.activeCount.Add(1)
		go globalWorkerPool.worker()
	}
}

func (p *AdaptiveWorkerPool) worker() {
	// decrement activeCount when exiting
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
			_, enc, nonce, err := job.proxy.EncryptInto(job.dst, nil, job.serverInfo, job.packet, job.proto)
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
	// avoid concurrent scale-ups
	p.scaleLock.Lock()
	defer p.scaleLock.Unlock()
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
	// Convert to float64 in [0,1)
	return math.Float64frombits(val) / float64(^uint64(0))
}

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

	if !hasAVX2 && !hasAESNI {
		dlog.Warnf("CPU: No hardware crypto acceleration detected; ChaCha20-Poly1305 recommended")
	} else if hasAESNI && !hasAVX2 {
		dlog.Noticef("CPU: AES-NI available; AES-GCM may be suitable alternative to ChaCha20")
	}

	poolWarmupSize := 10
	if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			poolWarmupSize = min(size, 1000)
		}
	}

	for i := 0; i < poolWarmupSize; i++ {
		bufferPoolSmall.Put(make([]byte, 0, 512))
		bufferPoolMedium.Put(make([]byte, 0, 2048))
		bufferPoolLarge.Put(make([]byte, 0, 8192))
		batchBufferPool.Put(make([]byte, MaxDNSUDPPacketSize))
	}

	globalAEADCache = newShardedAEADCache(AEADCacheShardCount, AEADCacheMaxSize)

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

	if os.Getenv("DNSCRYPT_TRACK_NONCES") == "1" {
		globalNonceTracker = &NonceTracker{
			seen: make(map[[HalfNonceSize]byte]time.Time),
		}
	}

	if MaxDNSUDPPacketSize > 0 {
		UDPGSOSegmentSize = MaxDNSUDPPacketSize
	}
}

// EncryptInto encrypts a DNS packet with optimized allocation
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
		globalNonceTracker.Lock()
		if _, exists := globalNonceTracker.seen[nonceKey]; exists {
			dlog.Warnf("SECURITY: Nonce reuse detected! (development only)")
		}
		globalNonceTracker.seen[nonceKey] = time.Now()
		globalNonceTracker.Unlock()
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
		encrypted = make([]byte, totalSize)
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
		// Seal in-place
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

func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	return proxy.EncryptInto(nil, nil, serverInfo, packet, proto)
}

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

// Constant-time unpadding
func unpadConstantTime(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, ErrInvalidPadding
	}
	idx := bytes.LastIndexByte(packet, 0x80)
	if idx == -1 {
		return nil, ErrInvalidPadding
	}
	tailLen := len(packet) - idx - 1
	_ = packet[len(packet)-1]

	if tailLen == 0 {
		return packet[:idx], nil
	}
	if tailLen <= len(zeroPage) {
		if subtle.ConstantTimeCompare(packet[idx+1:], zeroPage[:tailLen]) != 1 {
			return nil, ErrInvalidPadBytes
		}
		return packet[:idx], nil
	}
	var mismatch byte
	for i := idx + 1; i < len(packet); i++ {
		mismatch |= packet[i]
	}
	if mismatch != 0 {
		return nil, ErrInvalidPadBytes
	}
	return packet[:idx], nil
}

func unpadFast(packet []byte) ([]byte, error) {
	// Same as constant-time but with small fast path for aligned tails when AVX2 available
	if len(packet) == 0 {
		return nil, ErrInvalidPadding
	}
	idx := bytes.LastIndexByte(packet, 0x80)
	if idx == -1 {
		return nil, ErrInvalidPadding
	}
	tailLen := len(packet) - idx - 1
	_ = packet[len(packet)-1]

	if tailLen == 0 {
		return packet[:idx], nil
	}

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

	if tailLen <= len(zeroPage) {
		if subtle.ConstantTimeCompare(packet[idx+1:], zeroPage[:tailLen]) != 1 {
			return nil, ErrInvalidPadBytes
		}
		return packet[:idx], nil
	}

	var mismatch byte
	for i := idx + 1; i < len(packet); i++ {
		mismatch |= packet[i]
	}
	if mismatch != 0 {
		return nil, ErrInvalidPadBytes
	}
	return packet[:idx], nil
}

// Elligator placeholders unchanged but kept for API compatibility
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
	for attempts := 0; attempts < 128; attempts++ {
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
	if err := readRandom([]byte{hint}); err != nil {
		hint = 0
	}
	return GenerateObfuscatedKeyPairWithHint(hint)
}

type BatchMessage struct {
	Buffer []byte
	Addr   net.Addr
	N      int
}

func isIPv4(addr net.Addr) bool {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.To4() != nil
	}
	return true
}

func ReadBatch(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
	p := ipv4.NewPacketConn(conn)

	// Preallocate messages and buffers from pools
	messages := make([]ipv4.Message, maxMessages)
	buffers := make([][]byte, maxMessages)

	for i := range messages {
		buf := batchBufferPool.Get().([]byte)
		buffers[i] = buf[:MaxDNSUDPPacketSize]
		messages[i].Buffers = [][]byte{buffers[i]}
	}

	n, err := p.ReadBatch(messages, 0)
	if err != nil && n == 0 {
		// return buffers to pool
		for i := 0; i < maxMessages; i++ {
			batchBufferPool.Put(buffers[i])
		}
		return nil, err
	}

	result := make([]BatchMessage, n)
	for i := 0; i < n; i++ {
		result[i] = BatchMessage{
			Buffer: buffers[i][:messages[i].N],
			Addr:   messages[i].Addr,
			N:      messages[i].N,
		}
		// Put back the underlying buffer slice header but keep the underlying array for reuse
		buffers[i] = buffers[i][:cap(buffers[i])]
		batchBufferPool.Put(buffers[i])
	}

	return result, nil
}

func ReadBatchV6(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
	if isIPv4(conn.LocalAddr()) {
		return ReadBatch(conn, maxMessages)
	}

	p := ipv6.NewPacketConn(conn)
	messages := make([]ipv6.Message, maxMessages)
	buffers := make([][]byte, maxMessages)

	for i := range messages {
		buf := batchBufferPool.Get().([]byte)
		buffers[i] = buf[:MaxDNSUDPPacketSize]
		messages[i].Buffers = [][]byte{buffers[i]}
	}

	n, err := p.ReadBatch(messages, 0)
	if err != nil && n == 0 {
		for i := 0; i < maxMessages; i++ {
			batchBufferPool.Put(buffers[i])
		}
		return nil, err
	}

	result := make([]BatchMessage, n)
	for i := 0; i < n; i++ {
		result[i] = BatchMessage{
			Buffer: buffers[i][:messages[i].N],
			Addr:   messages[i].Addr,
			N:      messages[i].N,
		}
		buffers[i] = buffers[i][:cap(buffers[i])]
		batchBufferPool.Put(buffers[i])
	}

	return result, nil
}

func WriteBatch(conn *net.UDPConn, messages []BatchMessage) (int, error) {
	p := ipv4.NewPacketConn(conn)

	ipv4Messages := make([]ipv4.Message, len(messages))
	for i, msg := range messages {
		ipv4Messages[i].Buffers = [][]byte{msg.Buffer}
		ipv4Messages[i].Addr = msg.Addr
	}

	return p.WriteBatch(ipv4Messages, 0)
}

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

func (proxy *Proxy) EncryptBatch(
	serverInfo *ServerInfo,
	packets [][]byte,
	proto string,
) ([][]byte, [][]byte, error) {
	n := len(packets)
	encrypted := make([][]byte, n)
	nonces := make([][]byte, n)

	// Pre-allocate dst buffers
	dstBufs := make([][]byte, n)
	for i := range dstBufs {
		dstBufs[i] = getBuffer(MaxDNSUDPPacketSize)
	}

	// Preallocate result channel with capacity n
	results := make(chan encryptResult, n)

	// Submit jobs
	for i := range packets {
		// scale up if queue is filling
		if len(globalWorkerPool.jobs) > cap(globalWorkerPool.jobs)/2 {
			globalWorkerPool.scaleUp()
		}
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
	for i := 0; i < n; i++ {
		res := <-results
		if res.err == nil {
			encrypted[res.idx] = res.encrypted
			nonces[res.idx] = res.nonce
		}
		// return dst buffer to pool if not used
		if res.encrypted == nil && dstBufs[res.idx] != nil {
			putBuffer(dstBufs[res.idx])
		}
	}

	return encrypted, nonces, nil
}

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
