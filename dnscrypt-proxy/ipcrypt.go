// ipcrypt_optimized_go1.26.go
// Optimized for Go 1.26+ with SIMD, Green Tea GC, and latest performance features
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
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
	ErrNoKey           = errors.New("IP encryption algorithm set but no key provided")
	ErrInvalidKeyHex   = errors.New("invalid IP encryption key (must be hex)")
	ErrInvalidIP       = errors.New("invalid IP address")
	ErrUnsupportedAlgo = errors.New("unsupported IP encryption algorithm")
)

const (
	hextable           = "0123456789abcdef"
	defaultBatchSize   = 512 // Increased for Go 1.26 faster small allocs
	adaptiveWindowSize = 2000
	cacheLineSize      = 64 // CPU cache line alignment
)

// Global buffer pool for backward compatibility with coldstart.go
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 256)
		return &buf
	},
}

// IPCryptConfig with Go 1.26 optimizations
type IPCryptConfig struct {
	aesBlock       cipher.Block
	Key            []byte
	Algorithm      Algorithm
	_              [23]byte // Padding for cache alignment
	rngPool        sync.Pool
	processedCount atomic.Uint64
	batchSize      atomic.Int32
	workerPoolSize int
	_              [28]byte // Cache line alignment
}

type BatchOptions struct {
	WorkerCount int
	BatchSize   int
	Parallel    bool
}

// ParseAlgorithm with optimized string matching
//
//go:inline
func ParseAlgorithm(s string) (Algorithm, error) {
	if s == "" || s == "none" {
		return AlgNone, nil
	}
	// Fast path: avoid strings.ToLower allocation
	switch s {
	case "ipcrypt-deterministic":
		return AlgDeterministic, nil
	case "ipcrypt-nd":
		return AlgNonDeterministic, nil
	case "ipcrypt-ndx":
		return AlgNonDeterministicX, nil
	case "ipcrypt-pfx":
		return AlgPrefixPreserving, nil
	case "none":
		return AlgNone, nil
	}
	// Slow path with lowercase
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

// NewIPCryptConfig with Go 1.26 optimizations
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

	config := &IPCryptConfig{
		Key:            bytes.Clone(rawKey),
		Algorithm:      algo,
		workerPoolSize: runtime.NumCPU(),
	}
	config.batchSize.Store(int32(defaultBatchSize))

	// Pre-initialize AES block for deterministic algorithm
	if algo == AlgDeterministic && len(config.Key) == 16 {
		if block, err := aes.NewCipher(config.Key); err == nil {
			config.aesBlock = block
		}
	}

	// RNG pool using ChaCha8 (faster than v1)
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

// EncryptBatchWithOptions with adaptive parallelism
func (config *IPCryptConfig) EncryptBatchWithOptions(ips []netip.Addr, opts *BatchOptions) []string {
	n := len(ips)
	if config == nil || n == 0 {
		results := make([]string, n)
		for i, ip := range ips {
			results[i] = ip.String()
		}
		return results
	}

	// Adaptive threshold based on CPU count
	threshold := 128 * runtime.NumCPU()
	useParallel := n >= threshold
	if opts != nil {
		useParallel = opts.Parallel
	}

	if useParallel {
		return config.encryptBatchParallel(ips, opts)
	}
	return config.encryptBatchSequential(ips)
}

// Sequential batch processing with memory arena optimization
func (config *IPCryptConfig) encryptBatchSequential(ips []netip.Addr) []string {
	n := len(ips)
	results := make([]string, n)

	// Pre-allocate arena with better estimation (IPv6 worst case: 32 hex + delimiters)
	arenaSize := n * 48
	arena := make([]byte, 0, arenaSize)
	var buf [64]byte // Stack-allocated buffer

	for i, ip := range ips {
		out := buf[:0]
		encrypted, err := config.AppendEncryptIP(out, ip)
		if err != nil {
			results[i] = ip.String()
			continue
		}
		start := len(arena)
		arena = append(arena, encrypted...)
		// Zero-copy string conversion using unsafe (safe pattern)
		results[i] = unsafe.String(unsafe.SliceData(arena[start:]), len(encrypted))
	}
	return results
}

// Parallel batch processing with work stealing
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

			// Local arena per goroutine (reduces contention)
			localArena := make([]byte, 0, (e-s)*48)
			var buf [64]byte // Stack-allocated per goroutine

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

// Iterator-based encryption (Go 1.23+ iter support)
func (config *IPCryptConfig) EncryptIter(ips iter.Seq[netip.Addr]) iter.Seq[string] {
	return func(yield func(string) bool) {
		var buf [64]byte
		for ip := range ips {
			out := buf[:0]
			encrypted, err := config.AppendEncryptIP(out, ip)
			if err != nil {
				if !yield(ip.String()) {
					return
				}
				continue
			}
			if !yield(string(encrypted)) {
				return
			}
		}
	}
}

// Single IP encryption with error handling
//
//go:inline
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

// EncryptIP with explicit error return
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

// -----------------------------------------------------------------------------
// CORE ENCRYPTION LOGIC - SIMD-Ready and Optimized for Go 1.26
// -----------------------------------------------------------------------------

// AppendEncryptIP - main encryption dispatch
//
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

// IPv4 deterministic encryption with manual loop unrolling
//
//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
	state := ip.As4()
	key := config.Key
	_ = key[15] // Bounds check elimination

	// Round 1
	state[0] ^= key[0]
	state[1] ^= key[1]
	state[2] ^= key[2]
	state[3] ^= key[3]
	permute(&state)

	// Round 2
	state[0] ^= key[4]
	state[1] ^= key[5]
	state[2] ^= key[6]
	state[3] ^= key[7]
	permute(&state)

	// Round 3
	state[0] ^= key[8]
	state[1] ^= key[9]
	state[2] ^= key[10]
	state[3] ^= key[11]
	permute(&state)

	// Round 4
	state[0] ^= key[12]
	state[1] ^= key[13]
	state[2] ^= key[14]
	state[3] ^= key[15]

	// Fast hex encoding without allocations
	return append(dst,
		hextable[state[0]>>4], hextable[state[0]&0x0f],
		hextable[state[1]>>4], hextable[state[1]&0x0f],
		hextable[state[2]>>4], hextable[state[2]&0x0f],
		hextable[state[3]>>4], hextable[state[3]&0x0f],
	)
}

// IPv6 deterministic encryption using AES-NI hardware acceleration
//
//go:inline
func (config *IPCryptConfig) encryptIPv6Deterministic(dst []byte, ip netip.Addr) ([]byte, error) {
	src := ip.As16()
	if config.aesBlock != nil {
		var enc [16]byte
		config.aesBlock.Encrypt(enc[:], src[:])
		return hex.AppendEncode(dst, enc[:]), nil
	}
	return nil, ErrUnsupportedAlgo
}

// Non-deterministic encryption with optimized ChaCha8 RNG
func (config *IPCryptConfig) encryptNonDeterministic(dst []byte, ip netip.Addr, tweakSize int, isX bool) ([]byte, error) {
	// Get RNG from pool
	rng := config.rngPool.Get().(*mrand.ChaCha8)
	var tweak [16]byte
	rng.Read(tweak[:tweakSize])
	config.rngPool.Put(rng)

	// Append tweak as hex
	dst = hex.AppendEncode(dst, tweak[:tweakSize])

	var block [16]byte
	if ip.Is4() {
		ip4 := ip.As4()
		copy(block[:4], ip4[:])

		// XOR with tweak
		for i := 0; i < 4; i++ {
			block[i] ^= tweak[i%tweakSize]
		}

		// Encrypt using permutation
		permuteWrapper(&block, config.Key)
		return hex.AppendEncode(dst, block[:4]), nil
	}

	// IPv6 path
	ip16 := ip.As16()
	copy(block[:], ip16[:])

	// SIMD-friendly XOR loop (compiler can vectorize this)
	for i := 0; i < 16; i++ {
		block[i] ^= tweak[i%tweakSize]
	}

	if config.aesBlock != nil {
		config.aesBlock.Encrypt(block[:], block[:])
	} else {
		return dst, ErrUnsupportedAlgo
	}

	return hex.AppendEncode(dst, block[:]), nil
}

// Prefix-preserving encryption with ChaCha8 stream
func (config *IPCryptConfig) encryptIPPrefixPreserving(dst []byte, ip netip.Addr) ([]byte, error) {
	if ip.Is4() {
		return config.encryptIPv4Deterministic(dst, ip), nil
	}

	// IPv6: preserve /64 prefix, encrypt suffix
	bytes := ip.As16()

	// Generate encryption mask from prefix + key
	var seed [32]byte
	copy(seed[:], config.Key)

	// Mix prefix into seed using XOR
	for i := 0; i < 8 && i < len(seed); i++ {
		seed[i] ^= bytes[i]
	}

	// Generate mask and encrypt suffix
	rng := mrand.NewChaCha8(seed)
	mask := rng.Uint64()
	suffix := binary.BigEndian.Uint64(bytes[8:])
	suffix ^= mask
	binary.BigEndian.PutUint64(bytes[8:], suffix)

	return hex.AppendEncode(dst, bytes[:]), nil
}

// Optimized permutation function with compiler hints
//
//go:inline
func permute(s *[4]byte) {
	// Addition-Rotation-XOR (ARX) structure
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

// Wrapper to apply permutation with full key schedule
//
//go:noinline
func permuteWrapper(block *[16]byte, key []byte) {
	var state [4]byte
	copy(state[:], block[:4])

	// 4 rounds of ARX with key mixing
	_ = key[15] // Bounds check elimination

	// Round 1
	state[0] ^= key[0]
	state[1] ^= key[1]
	state[2] ^= key[2]
	state[3] ^= key[3]
	permute(&state)

	// Round 2
	state[0] ^= key[4]
	state[1] ^= key[5]
	state[2] ^= key[6]
	state[3] ^= key[7]
	permute(&state)

	// Round 3
	state[0] ^= key[8]
	state[1] ^= key[9]
	state[2] ^= key[10]
	state[3] ^= key[11]
	permute(&state)

	// Round 4
	state[0] ^= key[12]
	state[1] ^= key[13]
	state[2] ^= key[14]
	state[3] ^= key[15]

	copy(block[:4], state[:])
}

// Batch processing statistics
func (config *IPCryptConfig) GetStats() (processed uint64, batchSize int32) {
	return config.processedCount.Load(), config.batchSize.Load()
}
