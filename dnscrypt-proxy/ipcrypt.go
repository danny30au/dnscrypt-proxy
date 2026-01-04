package main

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "strings"
    "sync"

    "github.com/jedisct1/dlog"
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
// Includes thread-safe object pool for zero-allocation tweak generation.
type IPCryptConfig struct {
    Key       []byte
    Algorithm Algorithm
    tweakPool sync.Pool
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

    // Initialize object pool for tweaks based on algorithm to reduce GC pressure
    switch algo {
    case AlgNonDeterministic:
        config.tweakPool = sync.Pool{
            New: func() interface{} {
                t := new([8]byte)
                return t
            },
        }
    case AlgNonDeterministicX:
        config.tweakPool = sync.Pool{
            New: func() interface{} {
                t := new([16]byte)
                return t
            },
        }
    }

    return config, nil
}

// EncryptIP encrypts a net.IP using the configured encryption.
func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
    if config == nil {
        return ip.String(), nil
    }

    switch config.Algorithm {
    case AlgDeterministic:
        encrypted, err := ipcrypt.EncryptIP(config.Key, ip)
        if err != nil {
            return "", err
        }
        return encrypted.String(), nil

    case AlgNonDeterministic:
        // Use pooled buffer for tweak to avoid allocation
        tweak := config.tweakPool.Get().(*[8]byte)
        defer config.tweakPool.Put(tweak)

        if _, err := rand.Read(tweak[:]); err != nil {
            return "", ErrTweakGen
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return "", err
        }
        return hex.EncodeToString(encrypted), nil

    case AlgNonDeterministicX:
        tweak := config.tweakPool.Get().(*[16]byte)
        defer config.tweakPool.Put(tweak)

        if _, err := rand.Read(tweak[:]); err != nil {
            return "", ErrTweakGen
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, tweak[:])
        if err != nil {
            return "", err
        }
        return hex.EncodeToString(encrypted), nil

    case AlgPrefixPreserving:
        encrypted, err := ipcrypt.EncryptIPPfx(ip, config.Key)
        if err != nil {
            return "", err
        }
        return encrypted.String(), nil

    default:
        return "", ErrUnsupportedAlgo
    }
}

// EncryptIPString encrypts an IP address string.
// Optimized to avoid parsing overhead for non-deterministic modes.
func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
    if config == nil || ipStr == "" {
        return ipStr
    }

    switch config.Algorithm {
    case AlgNonDeterministic:
        tweak := config.tweakPool.Get().(*[8]byte)
        defer config.tweakPool.Put(tweak)

        if _, err := rand.Read(tweak[:]); err != nil {
            dlog.Warnf("Failed to generate tweak: %v", err)
            return ipStr
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ipStr, config.Key, tweak[:])
        if err != nil {
            dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
            return ipStr
        }
        return hex.EncodeToString(encrypted)

    case AlgNonDeterministicX:
        tweak := config.tweakPool.Get().(*[16]byte)
        defer config.tweakPool.Put(tweak)

        if _, err := rand.Read(tweak[:]); err != nil {
            dlog.Warnf("Failed to generate tweak: %v", err)
            return ipStr
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ipStr, config.Key, tweak[:])
        if err != nil {
            dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
            return ipStr
        }
        return hex.EncodeToString(encrypted)

    case AlgDeterministic, AlgPrefixPreserving:
        addr, err := netip.ParseAddr(ipStr)
        if err != nil {
            return ipStr
        }

        // Convert netip.Addr to net.IP (slice) as required by library
        ip16 := addr.As16()
        ipSlice := ip16[:]

        if config.Algorithm == AlgDeterministic {
            encrypted, err := ipcrypt.EncryptIP(config.Key, net.IP(ipSlice))
            if err != nil {
                dlog.Warnf("Failed to encrypt IP: %v", err)
                return ipStr
            }
            return encrypted.String()
        } else {
            encrypted, err := ipcrypt.EncryptIPPfx(net.IP(ipSlice), config.Key)
            if err != nil {
                dlog.Warnf("Failed to encrypt IP: %v", err)
                return ipStr
            }
            return encrypted.String()
        }

    default:
        return ipStr
    }
}

// DecryptIP decrypts an encrypted IP address string.
func (config *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
    if config == nil {
        return encryptedStr, nil
    }

    switch config.Algorithm {
    case AlgDeterministic:
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ip16 := addr.As16()
        decrypted, err := ipcrypt.DecryptIP(config.Key, net.IP(ip16[:]))
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    case AlgNonDeterministic:
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        // Optimized conversion (avoid fmt.Sprintf reflection)
        return string(decrypted), nil

    case AlgNonDeterministicX:
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        // Optimized conversion
        return string(decrypted), nil

    case AlgPrefixPreserving:
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ip16 := addr.As16()
        decrypted, err := ipcrypt.DecryptIPPfx(net.IP(ip16[:]), config.Key)
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    default:
        return "", ErrUnsupportedAlgo
    }
}
