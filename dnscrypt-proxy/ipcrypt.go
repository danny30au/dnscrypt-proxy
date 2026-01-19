// ipcrypt.go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand" // Alias to avoid conflict
    "encoding/hex"
    "errors"
    "fmt"
    mrand "math/rand/v2" // Alias for ChaCha8
    "net"
    "net/netip"
    "strings"
    "sync"

    ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// Algorithm type constants to avoid string comparisons in hot paths
type Algorithm uint8

const (
    AlgNone Algorithm = iota
    AlgDeterministic
    AlgNonDeterministic
    AlgNonDeterministicX
    AlgPrefixPreserving
)

// Common errors pre-allocated to avoid runtime allocation
var (
    ErrNoKey              = errors.New("IP encryption algorithm set but no key provided")
    ErrInvalidKeyHex      = errors.New("invalid IP encryption key (must be hex)")
    ErrInvalidIP          = errors.New("invalid IP address")
    ErrTweakGen           = errors.New("failed to generate random tweak")
    ErrUnsupportedAlgo    = errors.New("unsupported IP encryption algorithm")
    ErrEncryptionDisabled = errors.New("encryption disabled")
)

// IPCryptConfig holds the configuration for IP address encryption.
type IPCryptConfig struct {
    Key       []byte
    Algorithm Algorithm

    // Optimization: Pre-computed AES block for IPv6 (AlgDeterministic)
    // IPv6 uses AES-128 (16 byte key).
    aesBlock cipher.Block

    // Optimization: Pool of RNGs for tweaks to avoid locking and syscall overhead.
    // Stores *mrand.ChaCha8
    rngPool sync.Pool
}

// ParseAlgorithm converts string algorithm name to Algorithm enum.
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
        return AlgNone, fmt.Errorf("%w: %s", ErrUnsupportedAlgo, s)
    }
}

// NewIPCryptConfig creates a new IPCryptConfig with optimized structures.
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

    key, err := hex.DecodeString(keyHex)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidKeyHex, err)
    }

    // Validate key length immediately based on algorithm
    expectedLen := 16
    if algo == AlgNonDeterministicX || algo == AlgPrefixPreserving {
        expectedLen = 32
    }
    if len(key) != expectedLen {
        return nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, expectedLen, len(key))
    }

    config := &IPCryptConfig{
        Key:       key,
        Algorithm: algo,
    }

    // Optimization: Pre-compute AES cipher for IPv6 Deterministic mode.
    // Standard ipcrypt-deterministic uses AES-128 for IPv6.
    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

    // Initialize object pool for RNGs.
    // We use math/rand/v2 ChaCha8 which is fast and secure enough for tweaks.
    // We seed each new instance with crypto/rand to ensure uniqueness.
    config.rngPool = sync.Pool{
        New: func() interface{} {
            var seed [32]byte
            if _, err := crand.Read(seed[:]); err != nil {
                panic("failed to seed RNG: " + err.Error())
            }
            return mrand.NewChaCha8(seed)
        },
    }

    return config, nil
}

// AppendEncryptIP appends the encrypted IP (as hex) to dst.
// This is the high-performance zero-allocation method.
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

    ensureSpace := func(rawLen int) []byte {
        hexLen := hex.EncodedLen(rawLen)
        if cap(dst)-len(dst) < hexLen {
            newDst := make([]byte, len(dst), len(dst)+hexLen)
            copy(newDst, dst)
            dst = newDst
        }
        return dst
    }

    switch config.Algorithm {
    case AlgDeterministic:
        if ip.Is4() {
            src := ip.As4()
            encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
            if err != nil {
                return dst, err
            }
            dst = ensureSpace(len(encrypted))
            n := hex.Encode(dst[len(dst):], encrypted)
            return dst[:len(dst)+n], nil
        } else if ip.Is6() {
            if config.aesBlock != nil {
                src := ip.As16()
                dst = ensureSpace(16)
                var enc [16]byte
                config.aesBlock.Encrypt(enc[:], src[:])
                n := hex.Encode(dst[len(dst):], enc[:])
                return dst[:len(dst)+n], nil
            }
            src := ip.As16()
            encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
            if err != nil {
                return dst, err
            }
            dst = ensureSpace(len(encrypted))
            n := hex.Encode(dst[len(dst):], encrypted)
            return dst[:len(dst)+n], nil
        }

    case AlgNonDeterministic:
        rng := config.rngPool.Get().(*mrand.ChaCha8)
        defer config.rngPool.Put(rng)

        var tweak [8]byte
        rng.Read(tweak[:])

        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return dst, err
        }
        dst = ensureSpace(len(encrypted))
        n := hex.Encode(dst[len(dst):], encrypted)
        return dst[:len(dst)+n], nil

    case AlgNonDeterministicX:
        rng := config.rngPool.Get().(*mrand.ChaCha8)
        defer config.rngPool.Put(rng)

        var tweak [16]byte
        rng.Read(tweak[:])

        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, tweak[:])
        if err != nil {
            return dst, err
        }
        dst = ensureSpace(len(encrypted))
        n := hex.Encode(dst[len(dst):], encrypted)
        return dst[:len(dst)+n], nil

    case AlgPrefixPreserving:
        src := ip.AsSlice()
        encrypted, err := ipcrypt.EncryptIPPfx(src, config.Key)
        if err != nil {
            return dst, err
        }
        dst = ensureSpace(len(encrypted))
        n := hex.Encode(dst[len(dst):], encrypted)
        return dst[:len(dst)+n], nil
    }

    return dst, ErrUnsupportedAlgo
}

// EncryptIP is a compatibility wrapper for code passing net.IP.
func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
    if config == nil {
        return ip.String(), nil
    }
    addr, ok := netip.FromSlice(ip)
    if !ok {
        return "", ErrInvalidIP
    }
    // Append to empty buffer and convert to string
    res, err := config.AppendEncryptIP(nil, addr)
    if err != nil {
        return "", err
    }
    return string(res), nil
}

// EncryptIPString is a compatibility wrapper for code passing string IPs.
// This fixes the 'ipCryptConfig.EncryptIPString undefined' error.
func (config *IPCryptConfig) EncryptIPString(ipStr string) (string, error) {
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
    return string(res), nil
}
