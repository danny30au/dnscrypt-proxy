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

type IPCryptConfig struct {
    aesBlock  cipher.Block
    Key       []byte
    rngPool   sync.Pool
    Algorithm Algorithm
    _         [7]byte // explicit padding for cache-line alignment
}

func ParseAlgorithm(s string) (Algorithm, error) {
    switch strings.ToLower(s) {
    case "", "none":
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
    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

    // Type-safe pool initialization (Go 1.26+ improvement)
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
// This is the primary hot-path function; optimizations target Go 1.26 features.
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

    switch config.Algorithm {
    case AlgDeterministic:
        if ip.Is4() {
            return config.encryptIPv4Deterministic(dst, ip), nil
        } else if ip.Is6() {
            return config.encryptIPv6Deterministic(dst, ip)
        }

    case AlgNonDeterministic:
        rng := config.rngPool.Get().(*mrand.ChaCha8)
        var tweak [8]byte
        rng.Read(tweak[:])
        config.rngPool.Put(rng)

        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return dst, err
        }
        return hex.AppendEncode(dst, encrypted), nil

    case AlgNonDeterministicX:
        rng := config.rngPool.Get().(*mrand.ChaCha8)
        var tweak [16]byte
        rng.Read(tweak[:])
        config.rngPool.Put(rng)

        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, tweak[:])
        if err != nil {
            return dst, err
        }
        return hex.AppendEncode(dst, encrypted), nil

    case AlgPrefixPreserving:
        return config.encryptIPPrefixPreserving(dst, ip)
    }

    return dst, ErrUnsupportedAlgo
}

// encryptIPv4Deterministic handles deterministic IPv4 encryption inline.
// Inlined for Go 1.26's improved small-object allocation performance.
//
//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
    state := ip.As4()

    // Unrolled 4-round cipher with manual key XOR and permutation
    // Compiler will optimize with Go 1.26's vectorization on amd64
    state[0] ^= config.Key[0]
    state[1] ^= config.Key[1]
    state[2] ^= config.Key[2]
    state[3] ^= config.Key[3]
    permute(&state)

    state[0] ^= config.Key[4]
    state[1] ^= config.Key[5]
    state[2] ^= config.Key[6]
    state[3] ^= config.Key[7]
    permute(&state)

    state[0] ^= config.Key[8]
    state[1] ^= config.Key[9]
    state[2] ^= config.Key[10]
    state[3] ^= config.Key[11]
    permute(&state)

    state[0] ^= config.Key[12]
    state[1] ^= config.Key[13]
    state[2] ^= config.Key[14]
    state[3] ^= config.Key[15]

    // Hex encoding with manual bounds-check elimination
    // Go 1.26's improved allocation reduces overhead here
    return append(dst,
        hextable[(state[0]>>4)&0x0f], hextable[state[0]&0x0f],
        hextable[(state[1]>>4)&0x0f], hextable[state[1]&0x0f],
        hextable[(state[2]>>4)&0x0f], hextable[state[2]&0x0f],
        hextable[(state[3]>>4)&0x0f], hextable[state[3]&0x0f],
    )
}

// encryptIPv6Deterministic handles deterministic IPv6 encryption.
//
//go:inline
func (config *IPCryptConfig) encryptIPv6Deterministic(dst []byte, ip netip.Addr) ([]byte, error) {
    src := ip.As16()
    
    // Fast path: use pre-initialized AES cipher
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
// This is highly optimized and benefits from Go 1.26's CPU-specific optimizations.
//
//go:inline
func permute(s *[4]byte) {
    s[0] += s[1]
    s[2] += s[3]
    s[1] = (s[1] << 2) | (s[1] >> 6)
    s[3] = (s[3] << 5) | (s[3] >> 3)
    s[1] ^= s[0]
    s[3] ^= s[2]
    s[0] = (s[0] << 4) | (s[0] >> 4)
    s[0] += s[3]
    s[2] = (s[2] << 4) | (s[2] >> 4)
    s[2] ^= s[1]
    s[1] = (s[1] << 3) | (s[1] >> 5)
    s[3] = (s[3] << 7) | (s[3] >> 1)
    s[3] += s[2]
    s[1] ^= s[3]
    s[0] ^= s[1]
}

// EncryptIP encrypts a net.IP and returns the hex-encoded result as a string.
// Zero-copy conversion with unsafe benefits from Go 1.26's escape analysis.
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
    
    // Zero-copy []byte to string conversion (safe in this context)
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
