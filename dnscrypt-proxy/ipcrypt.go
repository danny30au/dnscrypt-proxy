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
    "net"
    "net/netip"
    "strings"
    "sync"
    "unsafe"

    ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// Algorithm type constants
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
    Key       []byte       // 24 bytes
    aesBlock  cipher.Block // 16 bytes
    Algorithm Algorithm    // 1 byte
    // padding for alignment
    _         [7]byte
    
    // rngPool is accessed concurrently (R/W). Isolate it to prevent false sharing
    // with the read-only fields above on highly concurrent systems.
    rngPool   sync.Pool    // 48 bytes (aligned)
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
        // Optimization: Return static error for unknown algo to prevent alloc DoS
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

    if algo == AlgDeterministic && len(key) == 16 {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        config.aesBlock = block
    }

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

func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
    if config == nil {
        return ip.AppendTo(dst), nil
    }

    switch config.Algorithm {
    case AlgDeterministic:
        if ip.Is4() {
            state := ip.As4()
            
            state[0] ^= config.Key[0]; state[1] ^= config.Key[1]
            state[2] ^= config.Key[2]; state[3] ^= config.Key[3]
            permute(&state)

            state[0] ^= config.Key[4]; state[1] ^= config.Key[5]
            state[2] ^= config.Key[6]; state[3] ^= config.Key[7]
            permute(&state)

            state[0] ^= config.Key[8]; state[1] ^= config.Key[9]
            state[2] ^= config.Key[10]; state[3] ^= config.Key[11]
            permute(&state)

            state[0] ^= config.Key[12]; state[1] ^= config.Key[13]
            state[2] ^= config.Key[14]; state[3] ^= config.Key[15]
            
            // OPTIMIZATION: Bounds-check elimination hint & 0x0F
            // Applying & 0x0F to the shift results proves to compiler index is 0..15
            return append(dst,
                hextable[(state[0]>>4)&0x0f], hextable[state[0]&0x0f],
                hextable[(state[1]>>4)&0x0f], hextable[state[1]&0x0f],
                hextable[(state[2]>>4)&0x0f], hextable[state[2]&0x0f],
                hextable[(state[3]>>4)&0x0f], hextable[state[3]&0x0f],
            ), nil

        } else if ip.Is6() {
            if config.aesBlock != nil {
                src := ip.As16()
                var enc [16]byte
                config.aesBlock.Encrypt(enc[:], src[:])
                return hex.AppendEncode(dst, enc[:]), nil
            }
            src := ip.As16()
            encrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
            if err != nil {
                return dst, err
            }
            return hex.AppendEncode(dst, encrypted), nil
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
        var buf [16]byte
        var inputSlice []byte
        if ip.Is4() {
            a4 := ip.As4()
            copy(buf[:], a4[:])
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

    return dst, ErrUnsupportedAlgo
}

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

func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
    if config == nil {
        return ip.String(), nil
    }
    addr, ok := netip.AddrFromSlice(ip)
    if !ok {
        return "", ErrInvalidIP
    }
    res, err := config.AppendEncryptIP(nil, addr)
    if err != nil {
        return "", err
    }
    return unsafe.String(unsafe.SliceData(res), len(res)), nil
}

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
