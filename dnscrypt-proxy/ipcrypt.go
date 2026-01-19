// ipcrypt.go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "math/rand/v2"
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
    // Stores *rand.ChaCha8
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
    // We only do this if the key is 16 bytes (AES-128 requirement).
    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

    // Initialize object pool for RNGs.
    // We use math/rand/v2 ChaCha8 which is fast (user-space) and cryptographically strong enough for tweaks.
    // We seed each new instance with crypto/rand to ensure uniqueness.
    config.rngPool = sync.Pool{
        New: func() interface{} {
            var seed [32]byte
            if _, err := rand.Read(seed[:]); err != nil {
                // Fallback or panic in extreme case; rand.Read shouldn't fail on modern OS
                panic("failed to seed RNG: " + err.Error())
            }
            return rand.NewChaCha8(seed)
        },
    }

    return config, nil
}

// AppendEncryptIP appends the encrypted IP (as hex) to dst.
// This avoids allocating a new string or return buffer.
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

    // Helper to ensure dst has enough space for hex encoding
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
            // IPv4: Use library implementation of ipcrypt (4-byte cipher)
            // netip.Addr.As4() returns [4]byte (stack allocated)
            src := ip.As4()
            
            // Library requires slice, but we pass slice of stack array (no heap alloc usually)
            encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
            if err != nil {
                return dst, err
            }
            
            dst = ensureSpace(len(encrypted))
            n := hex.Encode(dst[len(dst):], encrypted)
            return dst[:len(dst)+n], nil
        } else if ip.Is6() {
            // IPv6: Use optimized AES path (Zero Allocation)
            // AES-128 block size is 16 bytes, same as IPv6
            if config.aesBlock != nil {
                src := ip.As16()
                dst = ensureSpace(16)
                
                // Direct encryption into the destination buffer's capacity would be complex due to hex expansion.
                // We encrypt into a stack buffer first.
                var enc [16]byte
                config.aesBlock.Encrypt(enc[:], src[:])
                
                n := hex.Encode(dst[len(dst):], enc[:])
                return dst[:len(dst)+n], nil
            }
            // Fallback if aesBlock setup failed (unlikely)
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
        // Get fast RNG from pool
        rng := config.rngPool.Get().(*rand.ChaCha8)
        defer config.rngPool.Put(rng)

        var tweak [8]byte
        rng.Read(tweak[:])

        // Library requires string input for ND mode. 
        // This is the only unavoidable allocation without modifying the library.
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return dst, err
        }

        dst = ensureSpace(len(encrypted))
        n := hex.Encode(dst[len(dst):], encrypted)
        return dst[:len(dst)+n], nil

    case AlgNonDeterministicX:
        rng := config.rngPool.Get().(*rand.ChaCha8)
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
        // Pfx mode likely requires net.IP slice
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
