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
    mrand "math/rand/v2"
    "net/netip"
    "strings"
    "sync"
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

const hextable = "0123456789abcdef"

// IPCryptConfig optimized for cache-line alignment (64 bytes)
type IPCryptConfig struct {
    aesBlock  cipher.Block // 16 bytes (interface = pointer + type)
    Key       []byte       // 24 bytes (slice header)
    Algorithm Algorithm    // 1 byte
    _         [7]byte      // padding to 48 bytes
    rngPool   sync.Pool    // 16 bytes
}

// ParseAlgorithm uses a more efficient string comparison approach
func ParseAlgorithm(s string) (Algorithm, error) {
    // Early return for common cases avoids ToLower allocation
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
    
    // Fallback to case-insensitive comparison only if needed
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

    expectedLen := 16
    if algo == AlgNonDeterministicX || algo == AlgPrefixPreserving {
        expectedLen = 32
    }
    if len(rawKey) != expectedLen {
        return nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, expectedLen, len(rawKey))
    }

    key := bytes.Clone(rawKey)

    config := &IPCryptConfig{
        Key:       key,
        Algorithm: algo,
    }

    // Pre-initialize AES cipher for deterministic IPv6 encryption
    // Go 1.26 automatically uses AES-NI hardware acceleration on x86
    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

    // Optimized pool with pre-seeded RNGs (Go 1.26 improves small allocations)
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

// AppendEncryptIP encrypts an IP address and appends the result to dst.
// Hot path optimized for Go 1.26's improved small allocation performance.
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

// encryptNonDeterministic consolidates both NonDeterministic and NonDeterministicX
// to reduce code duplication and improve instruction cache efficiency
//
//go:noinline
func (config *IPCryptConfig) encryptNonDeterministic(dst []byte, ip netip.Addr, tweakSize int, isX bool) ([]byte, error) {
    rng := config.rngPool.Get().(*mrand.ChaCha8)
    
    var tweak [16]byte // Maximum size needed
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

// encryptIPv4Deterministic handles deterministic IPv4 encryption inline.
// Go 1.26's improved vectorization and small object allocation optimizes this.
//
//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
    state := ip.As4()
    key := config.Key

    // Bounds check elimination hint for compiler
    _ = key[15]
    
    // Unrolled 4-round cipher with manual key XOR and permutation
    // Go 1.26 vectorization will optimize this on amd64
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

    // Optimized hex encoding with manual unrolling
    // Go 1.26 small allocation optimization helps here
    return append(dst,
        hextable[state[0]>>4], hextable[state[0]&0x0f],
        hextable[state[1]>>4], hextable[state[1]&0x0f],
        hextable[state[2]>>4], hextable[state[2]&0x0f],
        hextable[state[3]>>4], hextable[state[3]&0x0f],
    )
}

// encryptIPv6Deterministic handles deterministic IPv6 encryption.
// Hardware AES-NI acceleration automatically enabled in Go 1.26+
//
//go:inline
func (config *IPCryptConfig) encryptIPv6Deterministic(dst []byte, ip netip.Addr) ([]byte, error) {
    src := ip.As16()
    
    // Fast path: use pre-initialized AES cipher with hardware acceleration
    if config.aesBlock != nil {
        var enc [16]byte
        config.aesBlock.Encrypt(enc[:], src[:])
        return hex.AppendEncode(dst, enc[:]), nil
    }
    
    // Fallback: use external library
    encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
    if err != nil {
        return dst, err
    }
    return hex.AppendEncode(dst, encrypted), nil
}

// encryptIPPrefixPreserving handles prefix-preserving encryption.
// Optimized to avoid unnecessary allocations
//
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

// permute applies the ipcrypt permutation function.
// Optimized for Go 1.26's SIMD vectorization on amd64.
//
//go:inline
//go:nosplit
func permute(s *[4]byte) {
    // First stage: parallel operations
    s[0] += s[1]
    s[2] += s[3]
    s[1] = (s[1] << 2) | (s[1] >> 6)
    s[3] = (s[3] << 5) | (s[3] >> 3)
    
    // Second stage: XOR operations
    s[1] ^= s[0]
    s[3] ^= s[2]
    
    // Third stage: rotations and swaps
    s[0] = (s[0] << 4) | (s[0] >> 4)
    s[2] = (s[2] << 4) | (s[2] >> 4)
    
    // Fourth stage: final operations
    s[0] += s[3]
    s[2] ^= s[1]
    s[1] = (s[1] << 3) | (s[1] >> 5)
    s[3] = (s[3] << 7) | (s[3] >> 1)
    
    // Final stage: combine
    s[3] += s[2]
    s[1] ^= s[3]
    s[0] ^= s[1]
}

// EncryptIP encrypts a net.IP and returns the hex-encoded result as a string.
// Zero-copy conversion optimized for Go 1.26's escape analysis.
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
    
    // Zero-copy []byte to string conversion
    // Safe because res won't be modified after this
    return unsafe.String(unsafe.SliceData(res), len(res)), nil
}

// EncryptIPString encrypts an IP address string.
// Returns original string on error for defensive behavior.
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
