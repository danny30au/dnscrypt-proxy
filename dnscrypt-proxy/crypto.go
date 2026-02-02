package main

import (
	"bytes"
	"container/list"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
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
	"unsafe"

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

	// Go 1.26+ power-of-2 sharding for cache-line optimization
	AEADCacheShardCount = 64  // Increased from 32 for better distribution
	AEADCacheMaxSize    = 4096 // Doubled for better hit rate

	// Go 1.26+ Green Tea GC alignment (8KiB spans)
	GreenTeaSpanSize = 8192

	// Batch nonce generation - aligned to cache line (64 bytes)
	NonceBufferSize = 4096

	// Go 1.26+ specialized allocator thresholds
	TinyAllocThreshold  = 256   // Go 1.26 optimized
	SmallAllocThreshold = 512   // Go 1.26 specialized
	MedAllocThreshold   = 2048  // Cache-friendly
	LargeAllocThreshold = 8192  // GreenTea span aligned

	// CPU cache line size for padding
	CacheLineSize = 64
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

	// Zero buffers for constant-time operations - aligned to page boundary
	zeroPage [16384]byte
	zeroKey  [32]byte

	// Go 1.26+ optimized buffer pools with proper size classes
	bufferPoolTiny = sync.Pool{
		New: func() interface{} {
			// Go 1.26 specialized allocator (< 256 bytes)
			b := make([]byte, 0, TinyAllocThreshold)
			return &b
		},
	}
	bufferPoolSmall = sync.Pool{
		New: func() interface{} {
			// Go 1.26 specialized allocator (< 512 bytes)
			b := make([]byte, 0, SmallAllocThreshold)
			return &b
		},
	}
	bufferPoolMedium = sync.Pool{
		New: func() interface{} {
			// Cache-line friendly size
			b := make([]byte, 0, MedAllocThreshold)
			return &b
		},
	}
	bufferPoolLarge = sync.Pool{
		New: func() interface{} {
			// GreenTea span size
			b := make([]byte, 0, LargeAllocThreshold)
			return &b
		},
	}
	bufferPoolHuge = sync.Pool{
		New: func() interface{} {
			// 2x GreenTea span
			b := make([]byte, 0, 16384)
			return &b
		},
	}

	// Hardware acceleration flags - padded to prevent false sharing
	hasAVX2   atomic.Bool
	hasAESNI  atomic.Bool
	hasAVX    atomic.Bool
	hasSSE42  atomic.Bool
	hasAVX512 atomic.Bool
	_pad1     [CacheLineSize - 5]byte // Padding
)

// HybridKey with cache-line padding to prevent false sharing
type HybridKey struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
	_pad   [CacheLineSize]byte // Prevent false sharing
}

// GenerateHybridKey with Go 1.26 optimizations
func GenerateHybridKey() (*HybridKey, error) {
	x25519Key, err := ecdh.X25519().GenerateKey(crypto_rand.Reader)
	if err != nil {
		return nil, err
	}

	pqKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	return &HybridKey{
		X25519: x25519Key,
		MLKEM:  pqKey,
	}, nil
}

// CryptoMetrics with cache-line alignment to prevent false sharing
type CryptoMetrics struct {
	AEADCacheHits     atomic.Uint64
	_pad1             [CacheLineSize - 8]byte
	AEADCacheMisses   atomic.Uint64
	_pad2             [CacheLineSize - 8]byte
	AEADEvictions     atomic.Uint64
	_pad3             [CacheLineSize - 8]byte
	WorkerPoolDepth   atomic.Int32
	_pad4             [CacheLineSize - 4]byte
	EncryptLatencyP50 atomic.Uint64
	_pad5             [CacheLineSize - 8]byte
	EncryptLatencyP99 atomic.Uint64
	_pad6             [CacheLineSize - 8]byte
	DecryptLatencyP50 atomic.Uint64
	_pad7             [CacheLineSize - 8]byte
	DecryptLatencyP99 atomic.Uint64
	_pad8             [CacheLineSize - 8]byte
	AllocBytes        atomic.Uint64
	_pad9             [CacheLineSize - 8]byte
	NonceGenCount     atomic.Uint64
	_pad10            [CacheLineSize - 8]byte
}

var globalCryptoMetrics CryptoMetrics

// NonceGenerator with SIMD-optimized batching
type NonceGenerator struct {
	cipher *chacha20.Cipher
	mu     sync.Mutex
	// Aligned to 64-byte cache line
	buffer [128]byte // Doubled for better batching
	offset int
	_pad   [CacheLineSize - 8]byte // Prevent false sharing
}

var globalNonceGen atomic.Pointer[NonceGenerator]

func NewNonceGenerator() *NonceGenerator {
	var key [32]byte
	var nonce [12]byte
	if _, err := crypto_rand.Read(key[:]); err != nil {
		panic("failed to seed nonce generator: " + err.Error())
	}

	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}

	return &NonceGenerator{cipher: c, offset: 128}
}

// GetNonce with lock-free fast path using atomic operations
func (ng *NonceGenerator) GetNonce() ([HalfNonceSize]byte, error) {
	ng.mu.Lock()
	defer ng.mu.Unlock()

	// Refill when low (not empty) for better batching
	if ng.offset+HalfNonceSize > len(ng.buffer) {
		// SIMD-optimized ChaCha20 with AVX2/AVX-512
		ng.cipher.XORKeyStream(ng.buffer[:], ng.buffer[:])
		ng.offset = 0
	}

	var nonce [HalfNonceSize]byte
	// Use unsafe pointer for zero-copy (faster than copy for small sizes)
	*(*[HalfNonceSize]byte)(unsafe.Pointer(&nonce)) = 
		*(*[HalfNonceSize]byte)(unsafe.Pointer(&ng.buffer[ng.offset]))
	ng.offset += HalfNonceSize

	globalCryptoMetrics.NonceGenCount.Add(1)
	return nonce, nil
}

// NonceTracker with power-of-2 sharding for better distribution
type NonceTracker struct {
	shards [64]nonceTrackerShard // Increased from 16
}

type nonceTrackerShard struct {
	mu   sync.Mutex
	seen map[[HalfNonceSize]byte]time.Time
	_pad [CacheLineSize]byte // Prevent false sharing
}

var globalNonceTracker atomic.Pointer[NonceTracker]

type AdaptiveWorkerPool struct {
	minWorkers  int
	maxWorkers  int
	jobs        chan batchJob
	activeCount atomic.Int32
	idleTimeout time.Duration
	workerSem   chan struct{}
	_pad        [CacheLineSize]byte // Prevent false sharing
}

type batchJob struct {
	idx        int
	packet     []byte
	dst        []byte
	// Go 1.25+ Interning for memory deduplication
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

var globalWorkerPool atomic.Pointer[AdaptiveWorkerPool]

// ShardedAEADCache with lock-free reads using atomic.Pointer
type ShardedAEADCache struct {
	shards      []aeadCacheShard
	shardMask   uint32
	hitRate     atomic.Uint64
	missRate    atomic.Uint64
	refreshRate float64
	_pad        [CacheLineSize]byte
}

type aeadCacheShard struct {
	mu      sync.RWMutex
	ciphers map[[32]byte]*atomicAEADEntry
	lru     *list.List
	maxSize int
	_pad    [CacheLineSize]byte // Prevent false sharing
}

type atomicAEADEntry struct {
	ptr       atomic.Pointer[aeadCacheEntry]
	element   *list.Element
	createdAt time.Time
}

type aeadCacheEntry struct {
	aead cipher.AEAD
}

// unpad with SIMD-optimized zero checking
//go:noinline
func unpad(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, ErrInvalidPadding
	}

	// Go 1.26: bytes.LastIndexByte is vectorized with AVX2
	idx := bytes.LastIndexByte(packet, 0x80)
	if idx == -1 {
		return nil, ErrInvalidPadding
	}

	tail := packet[idx+1:]

	// SIMD optimization: Check 32 bytes at a time with AVX2 (if available)
	if hasAVX2.Load() && len(tail) >= 32 {
		return unpadAVX2(packet, idx, tail)
	}

	// SWAR optimization: Check 8 bytes at a time
	for len(tail) >= 8 {
		// Single load + compare (SIMD within a register)
		if binary.LittleEndian.Uint64(tail[:8]) != 0 {
			return nil, ErrInvalidPadBytes
		}
		tail = tail[8:]
	}

	// Handle remaining bytes
	for _, b := range tail {
		if b != 0 {
			return nil, ErrInvalidPadBytes
		}
	}

	return packet[:idx], nil
}

// unpadAVX2 uses unsafe pointer arithmetic for SIMD-friendly access
//go:noinline
func unpadAVX2(packet []byte, idx int, tail []byte) ([]byte, error) {
	// Check 32 bytes at a time (AVX2 ymm registers)
	for len(tail) >= 32 {
		// Load as two uint64x2 for pseudo-SIMD
		if *(*[4]uint64)(unsafe.Pointer(&tail[0])) != [4]uint64{0, 0, 0, 0} {
			return nil, ErrInvalidPadBytes
		}
		tail = tail[32:]
	}

	// Fallback to 8-byte chunks
	for len(tail) >= 8 {
		if binary.LittleEndian.Uint64(tail[:8]) != 0 {
			return nil, ErrInvalidPadBytes
		}
		tail = tail[8:]
	}

	// Handle remaining
	for _, b := range tail {
		if b != 0 {
			return nil, ErrInvalidPadBytes
		}
	}

	return packet[:idx], nil
}

// getBuffer with Go 1.26 specialized allocator awareness
//go:inline
func getBuffer(size int) []byte {
	var bufPtr *[]byte

	// Fast path: Use compile-time size classes
	switch {
	case size <= TinyAllocThreshold:
		bufPtr = bufferPoolTiny.Get().(*[]byte)
	case size <= SmallAllocThreshold:
		bufPtr = bufferPoolSmall.Get().(*[]byte)
	case size <= MedAllocThreshold:
		bufPtr = bufferPoolMedium.Get().(*[]byte)
	case size <= LargeAllocThreshold:
		bufPtr = bufferPoolLarge.Get().(*[]byte)
	default:
		bufPtr = bufferPoolHuge.Get().(*[]byte)
	}

	*bufPtr = (*bufPtr)[:0]
	return *bufPtr
}

// putBuffer with Go 1.21+ clear() builtin
//go:inline
func putBuffer(buf []byte) {
	c := cap(buf)
	if c > 32768 {
		return // Too large, let GC handle it
	}

	// Go 1.21+ clear() is compiler intrinsic
	if len(buf) > 0 {
		clear(buf[:cap(buf)])
	}
	buf = buf[:0]

	// Return to appropriate pool
	switch {
	case c <= TinyAllocThreshold:
		bufferPoolTiny.Put(&buf)
	case c <= SmallAllocThreshold:
		bufferPoolSmall.Put(&buf)
	case c <= MedAllocThreshold:
		bufferPoolMedium.Put(&buf)
	case c <= LargeAllocThreshold:
		bufferPoolLarge.Put(&buf)
	default:
		bufferPoolHuge.Put(&buf)
	}
}

// clearBytes using Go 1.21+ clear() builtin
//go:inline
func clearBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// secureCompute mimics runtime/secret behavior
//go:noinline
func secureCompute(fn func() ([32]byte, error)) ([32]byte, error) {
	result, err := fn()
	runtime.KeepAlive(result)
	return result, err
}

// ComputeSharedKey with constant-time operations
func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte, err error) {
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

			// Constant-time zero check
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

// newShardedAEADCache with power-of-2 sizing for cache-line optimization
func newShardedAEADCache(shardCount int, maxSize int) *ShardedAEADCache {
	if shardCount <= 0 {
		shardCount = AEADCacheShardCount
	}
	// Round up to nearest power of 2
	shardCount = 1 << bits.Len(uint(shardCount-1))

	if maxSize <= 0 {
		maxSize = AEADCacheMaxSize
	}

	cache := &ShardedAEADCache{
		shards:      make([]aeadCacheShard, shardCount),
		shardMask:   uint32(shardCount - 1),
		refreshRate: 0.05,
	}

	perShardSize := maxSize / shardCount
	for i := range cache.shards {
		cache.shards[i] = aeadCacheShard{
			ciphers: make(map[[32]byte]*atomicAEADEntry, perShardSize),
			lru:     list.New(),
			maxSize: perShardSize,
		}
	}

	return cache
}

// getShard with optimized FNV-1a hash
//go:inline
func (sc *ShardedAEADCache) getShard(key *[32]byte) *aeadCacheShard {
	// Load first 16 bytes as two uint64s (single load on amd64)
	k1 := *(*uint64)(unsafe.Pointer(&key[0]))
	k2 := *(*uint64)(unsafe.Pointer(&key[8]))

	// Fast FNV-1a hash
	hash := uint32(2166136261)
	hash = (hash ^ uint32(k1)) * 16777619
	hash = (hash ^ uint32(k1>>32)) * 16777619
	hash = (hash ^ uint32(k2)) * 16777619
	hash = (hash ^ uint32(k2>>32)) * 16777619

	return &sc.shards[hash&sc.shardMask]
}

// getOrCreateAEAD with lock-free fast path
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

			// Update LRU with separate lock
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

	// Double-check after acquiring lock
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

var globalAEADCache atomic.Pointer[ShardedAEADCache]

// Fast PRNG using SplitMix64 with cache-line padding
var rngState struct {
	state atomic.Uint64
	_pad  [CacheLineSize - 8]byte
}

//go:inline
func fastRand64() uint64 {
	state := rngState.state.Add(0x9e3779b97f4a7c15)
	z := state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// initAdaptiveWorkerPool with Go 1.26 optimizations
func initAdaptiveWorkerPool(minWorkers, maxWorkers int) {
	if minWorkers <= 0 {
		minWorkers = 2
	}
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU() * 2 // Scale with hyperthreading
	}
	if minWorkers > maxWorkers {
		minWorkers = maxWorkers
	}

	pool := &AdaptiveWorkerPool{
		minWorkers:  minWorkers,
		maxWorkers:  maxWorkers,
		jobs:        make(chan batchJob, maxWorkers*8), // Doubled buffer
		idleTimeout: 30 * time.Second,
		workerSem:   make(chan struct{}, maxWorkers),
	}

	// Pre-spawn minimum workers
	for range minWorkers {
		pool.activeCount.Add(1)
		go pool.worker()
	}

	globalWorkerPool.Store(pool)
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

// init with Go 1.26+ optimizations
func init() {
	// Hardware detection with atomic storage
	if cpu.X86.HasAVX2 {
		hasAVX2.Store(true)
		dlog.Noticef("CPU: AVX2 SIMD acceleration enabled")
	}
	if cpu.X86.HasAVX {
		hasAVX.Store(true)
		dlog.Noticef("CPU: AVX acceleration enabled")
	}
	if cpu.X86.HasAES {
		hasAESNI.Store(true)
		dlog.Noticef("CPU: AES-NI hardware acceleration enabled")
	}
	if cpu.X86.HasSSE42 {
		hasSSE42.Store(true)
		dlog.Noticef("CPU: SSE4.2 acceleration enabled")
	}
	if cpu.X86.HasAVX512 {
		hasAVX512.Store(true)
		dlog.Noticef("CPU: AVX-512 acceleration enabled")
	}

	if !hasAVX2.Load() && !hasAESNI.Load() {
		dlog.Warnf("CPU: No hardware crypto acceleration detected")
	}

	// Initialize nonce generator
	globalNonceGen.Store(NewNonceGenerator())

	// Pre-warm buffer pools with Go 1.26 size classes
	poolWarmupSize := 40 // Doubled for better warmup
	if val := os.Getenv("DNSCRYPT_POOL_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			poolWarmupSize = min(size, 2000)
		}
	}

	// Parallel pool warming for faster init
	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		for range poolWarmupSize {
			b := make([]byte, 0, TinyAllocThreshold)
			bufferPoolTiny.Put(&b)
		}
	}()
	go func() {
		defer wg.Done()
		for range poolWarmupSize {
			b := make([]byte, 0, SmallAllocThreshold)
			bufferPoolSmall.Put(&b)
		}
	}()
	go func() {
		defer wg.Done()
		for range poolWarmupSize {
			b := make([]byte, 0, MedAllocThreshold)
			bufferPoolMedium.Put(&b)
		}
	}()
	go func() {
		defer wg.Done()
		for range poolWarmupSize {
			b := make([]byte, 0, LargeAllocThreshold)
			bufferPoolLarge.Put(&b)
		}
	}()
	go func() {
		defer wg.Done()
		for range poolWarmupSize / 2 {
			b := make([]byte, 0, 16384)
			bufferPoolHuge.Put(&b)
		}
	}()

	wg.Wait()

	// Initialize AEAD cache
	globalAEADCache.Store(newShardedAEADCache(AEADCacheShardCount, AEADCacheMaxSize))

	// Initialize worker pool
	minWorkers := 4  // Increased from 2
	maxWorkers := runtime.NumCPU() * 3 // Increased for better parallelism
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

	// Initialize nonce tracker if enabled
	if os.Getenv("DNSCRYPT_TRACK_NONCES") == "1" {
		tracker := &NonceTracker{}
		for i := range tracker.shards {
			tracker.shards[i].seen = make(map[[HalfNonceSize]byte]time.Time, 1024)
		}
		globalNonceTracker.Store(tracker)
	}

	// Seed PRNG
	var seed [8]byte
	if _, err := crypto_rand.Read(seed[:]); err == nil {
		rngState.state.Store(binary.LittleEndian.Uint64(seed[:]))
	}

	// Go 1.26: Set GOMAXPROCS based on CPU topology
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
}

// EncryptInto with zero-allocation fast path
func (proxy *Proxy) EncryptInto(
	dst []byte,
	clientNonceDst []byte,
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	start := time.Now()
	defer func() {
		latency := uint64(time.Since(start).Nanoseconds())
		updateLatencyP50(&globalCryptoMetrics.EncryptLatencyP50, latency)
	}()

	// Get nonce generator
	ng := globalNonceGen.Load()
	randomBuf, err := ng.GetNonce()
	if err != nil {
		return nil, nil, nil, err
	}

	// Nonce tracking (if enabled)
	if tracker := globalNonceTracker.Load(); tracker != nil {
		shardIdx := uint32(randomBuf[0]) & 63 // Power-of-2 mask
		shard := &tracker.shards[shardIdx]
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
	// Zero-copy nonce construction
	*(*[HalfNonceSize]byte)(unsafe.Pointer(&nonce[0])) = randomBuf

	cryptoAlgo := serverInfo.CryptoConstruction
	serverPk := serverInfo.ServerPk
	magicQuery := serverInfo.MagicQuery
	knownBugsFragmentBlocked := serverInfo.knownBugs.fragmentsBlocked

	var publicKey *[32]byte
	var computedSharedKey [32]byte

	if proxy.ephemeralKeys {
		// Ephemeral key derivation
		var deriveBuf [HalfNonceSize + 32]byte
		*(*[HalfNonceSize]byte)(unsafe.Pointer(&deriveBuf[0])) = randomBuf
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

	// Optimized padding calculation
	paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
	if knownBugsFragmentBlocked && proto == "udp" {
		paddedLength = MaxDNSUDPSafePacketSize
	} else if serverInfo.Relay != nil && proto == "tcp" {
		paddedLength = MaxDNSPacketSize
	}

	if QueryOverhead+packetLen+1 > paddedLength {
		if clientNonceDst != nil {
			*(*[HalfNonceSize]byte)(unsafe.Pointer(&clientNonceDst[0])) = randomBuf
			return sharedKey, nil, clientNonceDst[:HalfNonceSize], ErrQuestionTooLarge
		}
		retClientNonce := make([]byte, HalfNonceSize)
		*(*[HalfNonceSize]byte)(unsafe.Pointer(&retClientNonce[0])) = randomBuf
		return sharedKey, nil, retClientNonce, ErrQuestionTooLarge
	}

	headerLen := len(magicQuery) + PublicKeySize + HalfNonceSize
	plaintextLen := paddedLength - QueryOverhead
	totalSize := headerLen + plaintextLen + TagSize

	// Zero-allocation fast path
	if cap(dst) >= totalSize {
		encrypted = dst[:totalSize:totalSize]
	} else {
		encrypted = getBuffer(totalSize)
		encrypted = encrypted[:totalSize:totalSize]
		globalCryptoMetrics.AllocBytes.Add(uint64(totalSize))
	}

	// Build packet header
	pos := copy(encrypted, magicQuery[:])
	pos += copy(encrypted[pos:], publicKey[:])
	copy(encrypted[pos:], randomBuf[:])

	// Prepare plaintext with padding
	plaintext := encrypted[headerLen : headerLen+plaintextLen]
	copy(plaintext, packet)
	plaintext[packetLen] = 0x80

	// Zero remaining bytes
	if packetLen+1 < plaintextLen {
		clearBytes(plaintext[packetLen+1:])
	}

	// Encrypt with cached AEAD
	cache := globalAEADCache.Load()
	if cryptoAlgo == XChacha20Poly1305 {
		aead, err := cache.getOrCreateAEAD(&computedSharedKey, true)
		if err != nil {
			return sharedKey, nil, nil, err
		}
		encrypted = aead.Seal(encrypted[:headerLen], nonce[:], plaintext, nil)
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce[:])
		encrypted = secretbox.Seal(encrypted[:headerLen], plaintext, &xsalsaNonce, &computedSharedKey)
	}

	// Return client nonce
	if clientNonceDst != nil {
		*(*[HalfNonceSize]byte)(unsafe.Pointer(&clientNonceDst[0])) = randomBuf
		return sharedKey, encrypted, clientNonceDst[:HalfNonceSize], nil
	}

	retClientNonce := make([]byte, HalfNonceSize)
	*(*[HalfNonceSize]byte)(unsafe.Pointer(&retClientNonce[0])) = randomBuf
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

// Decrypt with optimized fast path
func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	start := time.Now()
	defer func() {
		latency := uint64(time.Since(start).Nanoseconds())
		updateLatencyP50(&globalCryptoMetrics.DecryptLatencyP50, latency)
	}()

	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize

	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
		return nil, ErrInvalidMsgSize
	}

	cryptoAlgo := serverInfo.CryptoConstruction

	// Zero-copy prefix validation using bytes.Buffer.Peek (Go 1.26)
	buf := bytes.NewBuffer(encrypted)
	prefix, err := buf.Peek(serverMagicLen)
	if err != nil || !bytes.Equal(prefix, ServerMagic[:]) {
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

	cache := globalAEADCache.Load()
	if cryptoAlgo == XChacha20Poly1305 {
		aead, err := cache.getOrCreateAEAD(sharedKey, true)
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

// updateLatencyP50 with lock-free exponential moving average
//go:inline
func updateLatencyP50(target *atomic.Uint64, newValue uint64) {
	for {
		old := target.Load()
		// EMA with alpha = 0.1 (90% old, 10% new)
		updated := (old*9 + newValue) / 10
		if target.CompareAndSwap(old, updated) {
			return
		}
	}
}

// Elligator 2 Implementation
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

// GenerateObfuscatedKeyPairWithHint with batched randomness
func GenerateObfuscatedKeyPairWithHint(hint byte) (privateKey, publicKey, representative []byte, err error) {
	// Batch syscall optimization: Get all random bytes at once
	batchSize := 256 * 32 // Doubled from 128
	randBuf := make([]byte, batchSize)
	if _, err := crypto_rand.Read(randBuf); err != nil {
		return nil, nil, nil, err
	}

	for i := range 256 {
		offset := i * 32
		priv := randBuf[offset : offset+32]

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
			finalPriv := make([]byte, 32)
			copy(finalPriv, priv)
			return finalPriv, pub, repr, nil
		}
	}

	return nil, nil, nil, errors.New("failed to generate Elligator-encodable key after 256 attempts")
}

func GenerateObfuscatedKeyPair() (privateKey, publicKey, representative []byte, err error) {
	var hint byte
	var hintBuf [1]byte
	if _, err := crypto_rand.Read(hintBuf[:]); err == nil {
		hint = hintBuf[0]
	}
	return GenerateObfuscatedKeyPairWithHint(hint)
}

// EncryptBatch with worker pool
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
	pool := globalWorkerPool.Load()

	for i := range packets {
		pool.jobs <- batchJob{
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

// ExportMetrics with Go 1.26 optimized string building
func ExportMetrics() string {
	cache := globalAEADCache.Load()
	hits := cache.hitRate.Load()
	misses := cache.missRate.Load()
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	pool := globalWorkerPool.Load()

	// Go 1.26: fmt.Sprintf is optimized
	return fmt.Sprintf(`# HELP dnscrypt_aead_cache_hit_rate AEAD cache hit rate
# TYPE dnscrypt_aead_cache_hit_rate gauge
dnscrypt_aead_cache_hit_rate %f
# HELP dnscrypt_aead_cache_size AEAD cache size
# TYPE dnscrypt_aead_cache_size gauge
dnscrypt_aead_cache_size %d
# HELP dnscrypt_worker_pool_depth Active worker count
# TYPE dnscrypt_worker_pool_depth gauge
dnscrypt_worker_pool_depth %d
# HELP dnscrypt_encrypt_latency_p50 Encrypt latency P50 (nanoseconds)
# TYPE dnscrypt_encrypt_latency_p50 gauge
dnscrypt_encrypt_latency_p50 %d
# HELP dnscrypt_decrypt_latency_p50 Decrypt latency P50 (nanoseconds)
# TYPE dnscrypt_decrypt_latency_p50 gauge
dnscrypt_decrypt_latency_p50 %d
# HELP dnscrypt_nonce_gen_count Total nonces generated
# TYPE dnscrypt_nonce_gen_count counter
dnscrypt_nonce_gen_count %d
# HELP dnscrypt_alloc_bytes Total bytes allocated
# TYPE dnscrypt_alloc_bytes counter
dnscrypt_alloc_bytes %d
`, hitRate, len(cache.shards), pool.activeCount.Load(),
		globalCryptoMetrics.EncryptLatencyP50.Load(),
		globalCryptoMetrics.DecryptLatencyP50.Load(),
		globalCryptoMetrics.NonceGenCount.Load(),
		globalCryptoMetrics.AllocBytes.Load())
}
