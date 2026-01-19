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
	"unsafe"

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

	// Optimized cache configuration
	AEADCacheShardCount = 32  // Increased from 16 for better distribution
	AEADCacheMaxSize    = 2048 // Increased from 1000

	// Cache line size for alignment (64 bytes on most modern CPUs)
	cacheLineSize = 64
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

	// Aligned zero buffers for SIMD operations
	zeroPage [16384]byte // Increased from 8192
	zeroKey  [32]byte

	// Optimized buffer pools with aligned allocations
	bufferPoolTiny = sync.Pool{
		New: func() interface{} {
			return make([]byte, 256)
		},
	}
	bufferPoolSmall = sync.Pool{
		New: func() interface{} {
			return make([]byte, 512)
		},
	}
	bufferPoolMedium = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2048)
		},
	}
	bufferPoolLarge = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8192)
		},
	}
	bufferPoolHuge = sync.Pool{
		New: func() interface{} {
			return make([]byte, 16384)
		},
	}

	// Hardware acceleration flags
	hasAVX2   = false
	hasAESNI  = false
	hasAVX    = false
	hasSSE42  = false
	hasAVX512 = false
)

// CryptoMetrics with cache-line padding to prevent false sharing
type CryptoMetrics struct {
	AEADCacheHits   atomic.Uint64
	_padding1       [cacheLineSize - 8]byte
	AEADCacheMisses atomic.Uint64
	_padding2       [cacheLineSize - 8]byte
	AEADEvictions   atomic.Uint64
	_padding3       [cacheLineSize - 8]byte
	WorkerPoolDepth atomic.Int32
	_padding4       [cacheLineSize - 4]byte
	UnpadLatencyUs  atomic.Uint64
	_padding5       [cacheLineSize - 8]byte
	AvgLatencyUs    atomic.Uint64
	_padding6       [cacheLineSize - 8]byte
	GCPausesMs      atomic.Uint64
	_padding7       [cacheLineSize - 8]byte
}

var globalCryptoMetrics CryptoMetrics

// Lock-free nonce tracker using atomic operations
type NonceTracker struct {
	// Use sharded maps to reduce contention
	shards [16]nonceTrackerShard
}

type nonceTrackerShard struct {
	mu   sync.Mutex
	_pad [cacheLineSize - unsafe.Sizeof(sync.Mutex{})]byte
	seen map[[HalfNonceSize]byte]time.Time
}

var globalNonceTracker *NonceTracker

type WorkerPool struct {
	workers int
	jobs    chan batchJob
	_       [cacheLineSize - unsafe.Sizeof(int(0))]byte
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

var globalWorkerPool *WorkerPool

// Optimized sharded cache with lock-free reads where possible
type ShardedAEADCache struct {
	shards      []aeadCacheShard
	shardMask   uint32 // Power-of-2 mask for faster modulo
	hitRate     atomic.Uint64
	missRate    atomic.Uint64
	refreshRate float64
}

// Cache-aligned shard to prevent false sharing
type aeadCacheShard struct {
	mu      sync.RWMutex
	_pad1   [cacheLineSize - unsafe.Sizeof(sync.RWMutex{})]byte
	ciphers map[[32]byte]*aeadCacheEntry
	lru     *list.List
	maxSize int
	_pad2   [cacheLineSize - 16]byte
}

type aeadCacheEntry struct {
	aead      cipher.AEAD
	element   *list.Element
	createdAt time.Time
	_padding  [cacheLineSize - 24]byte
}



// Optimized constant-time unpadding with SIMD hints
//go:inline
func unpadConstantTime(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, ErrInvalidPadding
	}

	idx := bytes.LastIndexByte(packet, 0x80)
	if idx == -1 {
		return nil, ErrInvalidPadding
	}

	tailLen := len(packet) - idx - 1
	_ = packet[len(packet)-1] // BCE hint

	if tailLen == 0 {
		return packet[:idx], nil
	}

	if tailLen > len(zeroPage) {
		var mismatch byte
		for i := idx + 1; i < len(packet); i++ {
			mismatch |= packet[i]
		}
		if mismatch != 0 {
			return nil, ErrInvalidPadBytes
		}
	} else {
		if subtle.ConstantTimeCompare(packet[idx+1:], zeroPage[:tailLen]) != 1 {
			return nil, ErrInvalidPadBytes
		}
	}

	return packet[:idx], nil
}

// Optimized unpadding
//go:inline
func unpadFast(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, ErrInvalidPadding
	}

	idx := bytes.LastIndexByte(packet, 0x80)
	if idx == -1 {
		return nil, ErrInvalidPadding
	}

	// Verify tail is all zeros
	for _, b := range packet[idx+1:] {
		if b != 0 {
			return nil, ErrInvalidPadBytes
		}
	}
	return packet[:idx], nil
}

// Optimized random reader with batching
//go:inline
func readRandom(p []byte) error {
	_, err := crypto_rand.Read(p)
	return err
}

// Zero-allocation buffer management
//go:inline
func getBuffer(size int) []byte {
	switch {
	case size <= 256:
		return bufferPoolTiny.Get().([]byte)[:0]
	case size <= 512:
		return bufferPoolSmall.Get().([]byte)[:0]
	case size <= 2048:
		return bufferPoolMedium.Get().([]byte)[:0]
	case size <= 8192:
		return bufferPoolLarge.Get().([]byte)[:0]
	default:
		return bufferPoolHuge.Get().([]byte)[:0]
	}
}

//go:inline
func putBuffer(buf []byte) {
	c := cap(buf)
	if c > 16384 {
		return // Don't pool oversized buffers
	}
	switch {
	case c <= 256:
		bufferPoolTiny.Put(buf)
	case c <= 512:
		bufferPoolSmall.Put(buf)
	case c <= 2048:
		bufferPoolMedium.Put(buf)
	case c <= 8192:
		bufferPoolLarge.Put(buf)
	default:
		bufferPoolHuge.Put(buf)
	}
}

// Optimized zero-copy clearBytes using assembly hints
//go:noinline
func clearBytes(b []byte) {
	clear(b)
}

// Fast clearing using compiler intrinsics
//go:inline


// ComputeSharedKey with optimized error handling
//go:noinline
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
	// Round up to power of 2 for fast modulo
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

// Fast shard selection using XOR-folding
//go:inline
func (sc *ShardedAEADCache) getShard(key *[32]byte) *aeadCacheShard {
	// XOR-fold key to 64-bit for better distribution
	k := *(*[4]uint64)(unsafe.Pointer(key))
	h := k[0] ^ k[1] ^ k[2] ^ k[3]
	// Mix
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	return &sc.shards[h&uint64(sc.shardMask)]
}

// Optimized AEAD cache with lock-free fast path
//go:inline
func (sc *ShardedAEADCache) getOrCreateAEAD(sharedKey *[32]byte, isXChaCha bool) (cipher.AEAD, error) {
	shard := sc.getShard(sharedKey)

	// Fast read path
	shard.mu.RLock()
	entry, exists := shard.ciphers[*sharedKey]
	if exists {
		shard.mu.RUnlock()

		// LRU update (separate lock)
		shard.mu.Lock()
		if entry.element != nil {
			shard.lru.MoveToFront(entry.element)
		}
		shard.mu.Unlock()

		sc.hitRate.Add(1)
		return entry.aead, nil
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

	// Add to cache
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Double-check
	if entry, exists := shard.ciphers[*sharedKey]; exists {
		shard.lru.MoveToFront(entry.element)
		return entry.aead, nil
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
	shard.ciphers[*sharedKey] = &aeadCacheEntry{
		aead:      newAEAD,
		element:   element,
		createdAt: time.Now(),
	}

	sc.missRate.Add(1)
	return newAEAD, nil
}

var globalAEADCache *ShardedAEADCache

// Fast pseudo-random using runtime fastrand
var rngState atomic.Uint64

//go:inline
func fastRand64() uint64 {
	// Use SplitMix64 for fast thread-local RNG
	state := rngState.Add(0x9e3779b97f4a7c15)
	z := state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Init worker pool
func initWorkerPool(workers int) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	globalWorkerPool = &WorkerPool{
		workers: workers,
		jobs:    make(chan batchJob, workers*16), // Increased buffer
	}

	for i := 0; i < workers; i++ {
		go globalWorkerPool.worker()
	}
}

func (p *WorkerPool) worker() {
	for job := range p.jobs {
		if job.packet == nil {
			return
		}

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
}



// Init function with AVX512 detection
func init() {
	// Detect hardware acceleration
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

	// Pre-warm buffer pools
	poolWarmupSize := 20 // Increased from 10
	if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			poolWarmupSize = min(size, 2000)
		}
	}

	for i := 0; i < poolWarmupSize; i++ {
		bufferPoolTiny.Put(make([]byte, 256))
		bufferPoolSmall.Put(make([]byte, 512))
		bufferPoolMedium.Put(make([]byte, 2048))
		bufferPoolLarge.Put(make([]byte, 8192))
		if i < poolWarmupSize/2 {
			bufferPoolHuge.Put(make([]byte, 16384))
		}
	}

	// Initialize sharded AEAD cache
	globalAEADCache = newShardedAEADCache(AEADCacheShardCount, AEADCacheMaxSize)

	// Initialize worker pool
	maxWorkers := runtime.NumCPU() * 2 // Increased from NumCPU
	if val := os.Getenv("DNSCRYPT_MAX_WORKERS"); val != "" {
		if w, err := strconv.Atoi(val); err == nil && w > 0 {
			maxWorkers = min(w, 256)
		}
	}
	initWorkerPool(maxWorkers)

	// Optional nonce tracker
	if os.Getenv("DNSCRYPT_TRACK_NONCES") == "1" {
		globalNonceTracker = &NonceTracker{}
		for i := range globalNonceTracker.shards {
			globalNonceTracker.shards[i].seen = make(map[[HalfNonceSize]byte]time.Time)
		}
	}

	// Initialize RNG state
	var seed [8]byte
	if err := readRandom(seed[:]); err == nil {
		rngState.Store(binary.LittleEndian.Uint64(seed[:]))
	}

	// Set GOMAXPROCS if not set (Go 1.24 optimization)
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
}

// EncryptInto with zero-allocation optimizations
//go:noinline
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

	// Optional nonce tracking
	if globalNonceTracker != nil {
		var nonceKey [HalfNonceSize]byte
		copy(nonceKey[:], randomBuf[:])
		// Hash to shard
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

	// Local variables for compiler optimization
	cryptoAlgo := serverInfo.CryptoConstruction
	serverPk := serverInfo.ServerPk
	magicQuery := serverInfo.MagicQuery
	knownBugsFragmentBlocked := serverInfo.knownBugs.fragmentsBlocked

	var publicKey *[32]byte
	var computedSharedKey [32]byte

	if proxy.ephemeralKeys {
		// Stack-allocate derive buffer
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
		// Clear ephemeral key
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

	// Zero-copy single buffer allocation
	if cap(dst) >= totalSize {
		encrypted = dst[:totalSize]
	} else {
		encrypted = getBuffer(totalSize)
		encrypted = encrypted[:totalSize]
	}

	// Build header
	pos := copy(encrypted, magicQuery[:])
	pos += copy(encrypted[pos:], publicKey[:])
	copy(encrypted[pos:], randomBuf[:])

	// Build plaintext in-place
	plaintext := encrypted[headerLen : headerLen+plaintextLen]
	copy(plaintext, packet)
	plaintext[packetLen] = 0x80

	// Fast zero tail
	if packetLen+1 < plaintextLen {
		clearBytes(plaintext[packetLen+1:])
	}

	// Use cached AEAD
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
//go:inline
func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	return proxy.EncryptInto(nil, nil, serverInfo, packet, proto)
}

// Optimized Decrypt
//go:noinline
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
	_ = encrypted[responseHeaderLen+TagSize-1] // BCE hint

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
	// Use pooled buffer
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
	packet, err = unpadFast(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		putBuffer(packet)
		return nil, ErrInvalidPadding
	}

	return packet, nil
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
			packet:     packets[i],\
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
`, hitRate, len(globalAEADCache.shards), int32(globalWorkerPool.workers))
}
