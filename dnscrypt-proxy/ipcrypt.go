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
\tAlgNone Algorithm = iota
\tAlgDeterministic
\tAlgNonDeterministic
\tAlgNonDeterministicX
\tAlgPrefixPreserving
)

var (
\tErrNoKey              = errors.New("IP encryption algorithm set but no key provided")
\tErrInvalidKeyHex      = errors.New("invalid IP encryption key (must be hex)")
\tErrInvalidIP          = errors.New("invalid IP address")
\tErrTweakGen           = errors.New("failed to generate random tweak")
\tErrUnsupportedAlgo    = errors.New("unsupported IP encryption algorithm")
\tErrEncryptionDisabled = errors.New("encryption disabled")
)

const hextable = "0123456789abcdef"

type IPCryptConfig struct {
\taesBlock  cipher.Block
\tKey       []byte
\trngPool   sync.Pool
\tAlgorithm Algorithm
\t_         [7]byte // explicit padding for cache-line alignment
}

func ParseAlgorithm(s string) (Algorithm, error) {
\tswitch strings.ToLower(s) {
\tcase "", "none":
\t\treturn AlgNone, nil
\tcase "ipcrypt-deterministic":
\t\treturn AlgDeterministic, nil
\tcase "ipcrypt-nd":
\t\treturn AlgNonDeterministic, nil
\tcase "ipcrypt-ndx":
\t\treturn AlgNonDeterministicX, nil
\tcase "ipcrypt-pfx":
\t\treturn AlgPrefixPreserving, nil
\tdefault:
\t\treturn AlgNone, ErrUnsupportedAlgo
\t}
}

func NewIPCryptConfig(keyHex string, algorithm string) (*IPCryptConfig, error) {
\talgo, err := ParseAlgorithm(algorithm)
\tif err != nil {
\t\treturn nil, err
\t}
\tif algo == AlgNone {
\t\treturn nil, nil
\t}
\tif keyHex == "" {
\t\treturn nil, ErrNoKey
\t}

\trawKey, err := hex.DecodeString(keyHex)
\tif err != nil {
\t\treturn nil, fmt.Errorf("%w: %v", ErrInvalidKeyHex, err)
\t}

\texpectedLen := 16
\tif algo == AlgNonDeterministicX || algo == AlgPrefixPreserving {
\t\texpectedLen = 32
\t}
\tif len(rawKey) != expectedLen {
\t\treturn nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, expectedLen, len(rawKey))
\t}

\tkey := bytes.Clone(rawKey)

\tconfig := &IPCryptConfig{
\t\tKey:       key,
\t\tAlgorithm: algo,
\t}

\t// Pre-initialize AES cipher for deterministic IPv6 encryption
\tif algo == AlgDeterministic && len(key) == 16 {
\t\tblock, err := aes.NewCipher(key)
\t\tif err != nil {
\t\t\treturn nil, err
\t\t}
\t\tconfig.aesBlock = block
\t}

\t// Type-safe pool initialization (Go 1.26+ improvement)
\tconfig.rngPool = sync.Pool{
\t\tNew: func() any {
\t\t\tvar seed [32]byte
\t\t\tif _, err := crand.Read(seed[:]); err != nil {
\t\t\t\tpanic("failed to seed RNG: " + err.Error())
\t\t\t}
\t\t\treturn mrand.NewChaCha8(seed)
\t\t},
\t}

\treturn config, nil
}

// AppendEncryptIP encrypts an IP address and appends the result to dst.
// This is the primary hot-path function; optimizations target Go 1.26 features.
func (config *IPCryptConfig) AppendEncryptIP(dst []byte, ip netip.Addr) ([]byte, error) {
\tif config == nil {
\t\treturn ip.AppendTo(dst), nil
\t}

\tswitch config.Algorithm {
\tcase AlgDeterministic:
\t\tif ip.Is4() {
\t\t\treturn config.encryptIPv4Deterministic(dst, ip), nil
\t\t} else if ip.Is6() {
\t\t\treturn config.encryptIPv6Deterministic(dst, ip)
\t\t}

\tcase AlgNonDeterministic:
\t\trng := config.rngPool.Get().(*mrand.ChaCha8)
\t\tvar tweak [8]byte
\t\trng.Read(tweak[:])
\t\tconfig.rngPool.Put(rng)

\t\tencrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
\t\tif err != nil {
\t\t\treturn dst, err
\t\t}
\t\treturn hex.AppendEncode(dst, encrypted), nil

\tcase AlgNonDeterministicX:
\t\trng := config.rngPool.Get().(*mrand.ChaCha8)
\t\tvar tweak [16]byte
\t\trng.Read(tweak[:])
\t\tconfig.rngPool.Put(rng)

\t\tencrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, tweak[:])
\t\tif err != nil {
\t\t\treturn dst, err
\t\t}
\t\treturn hex.AppendEncode(dst, encrypted), nil

\tcase AlgPrefixPreserving:
\t\treturn config.encryptIPPrefixPreserving(dst, ip)
\t}

\treturn dst, ErrUnsupportedAlgo
}

// encryptIPv4Deterministic handles deterministic IPv4 encryption inline.
// Inlined for Go 1.26's improved small-object allocation performance.
//
//go:inline
func (config *IPCryptConfig) encryptIPv4Deterministic(dst []byte, ip netip.Addr) []byte {
\tstate := ip.As4()

\t// Unrolled 4-round cipher with manual key XOR and permutation
\t// Compiler will optimize with Go 1.26's vectorization on amd64
\tstate[0] ^= config.Key[0]
\tstate[1] ^= config.Key[1]
\tstate[2] ^= config.Key[2]
\tstate[3] ^= config.Key[3]
\tpermute(&state)

\tstate[0] ^= config.Key[4]
\tstate[1] ^= config.Key[5]
\tstate[2] ^= config.Key[6]
\tstate[3] ^= config.Key[7]
\tpermute(&state)

\tstate[0] ^= config.Key[8]
\tstate[1] ^= config.Key[9]
\tstate[2] ^= config.Key[10]
\tstate[3] ^= config.Key[11]
\tpermute(&state)

\tstate[0] ^= config.Key[12]
\tstate[1] ^= config.Key[13]
\tstate[2] ^= config.Key[14]
\tstate[3] ^= config.Key[15]

\t// Hex encoding with manual bounds-check elimination
\t// Go 1.26's improved allocation reduces overhead here
\treturn append(dst,
\t\thextable[(state[0]>>4)&0x0f], hextable[state[0]&0x0f],
\t\thextable[(state[1]>>4)&0x0f], hextable[state[1]&0x0f],
\t\thextable[(state[2]>>4)&0x0f], hextable[state[2]&0x0f],
\t\thextable[(state[3]>>4)&0x0f], hextable[state[3]&0x0f],
\t)
}

// encryptIPv6Deterministic handles deterministic IPv6 encryption.
//
//go:inline
func (config *IPCryptConfig) encryptIPv6Deterministic(dst []byte, ip netip.Addr) ([]byte, error) {
\tsrc := ip.As16()
\t
\t// Fast path: use pre-initialized AES cipher
\tif config.aesBlock != nil {
\t\tvar enc [16]byte
\t\tconfig.aesBlock.Encrypt(enc[:], src[:])
\t\treturn hex.AppendEncode(dst, enc[:]), nil
\t}
\t
\t// Fallback: use external library
\tencrypted, err := ipcrypt.EncryptIP(config.Key, src[:])
\tif err != nil {
\t\treturn dst, err
\t}
\treturn hex.AppendEncode(dst, encrypted), nil
}

// encryptIPPrefixPreserving handles prefix-preserving encryption.
//
//go:inline
func (config *IPCryptConfig) encryptIPPrefixPreserving(dst []byte, ip netip.Addr) ([]byte, error) {
\tvar buf [16]byte
\tvar inputSlice []byte
\t
\tif ip.Is4() {
\t\ta4 := ip.As4()
\t\tcopy(buf[:4], a4[:])
\t\tinputSlice = buf[:4]
\t} else {
\t\ta16 := ip.As16()
\t\tcopy(buf[:], a16[:])
\t\tinputSlice = buf[:16]
\t}
\t
\tencrypted, err := ipcrypt.EncryptIPPfx(inputSlice, config.Key)
\tif err != nil {
\t\treturn dst, err
\t}
\treturn hex.AppendEncode(dst, encrypted), nil
}

// permute applies the ipcrypt permutation function.
// This is highly optimized and benefits from Go 1.26's CPU-specific optimizations.
//
//go:inline
func permute(s *[4]byte) {
\ts[0] += s[1]
\ts[2] += s[3]
\ts[1] = (s[1] << 2) | (s[1] >> 6)
\ts[3] = (s[3] << 5) | (s[3] >> 3)
\ts[1] ^= s[0]
\ts[3] ^= s[2]
\ts[0] = (s[0] << 4) | (s[0] >> 4)
\ts[0] += s[3]
\ts[2] = (s[2] << 4) | (s[2] >> 4)
\ts[2] ^= s[1]
\ts[1] = (s[1] << 3) | (s[1] >> 5)
\ts[3] = (s[3] << 7) | (s[3] >> 1)
\ts[3] += s[2]
\ts[1] ^= s[3]
\ts[0] ^= s[1]
}

// EncryptIP encrypts a net.IP and returns the hex-encoded result as a string.
// Zero-copy conversion with unsafe benefits from Go 1.26's escape analysis.
func (config *IPCryptConfig) EncryptIP(ipStr string) (string, error) {
\tif config == nil {
\t\treturn ipStr, nil
\t}
\t
\taddr, err := netip.ParseAddr(ipStr)
\tif err != nil {
\t\treturn "", fmt.Errorf("%w: %v", ErrInvalidIP, err)
\t}
\t
\tres, err := config.AppendEncryptIP(nil, addr)
\tif err != nil {
\t\treturn "", err
\t}
\t
\t// Zero-copy []byte to string conversion (safe in this context)
\treturn unsafe.String(unsafe.SliceData(res), len(res)), nil
}

// EncryptIPString encrypts an IP address string.
// Returns original string on error for defensive behavior.
func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
\tif config == nil {
\t\treturn ipStr
\t}
\t
\taddr, err := netip.ParseAddr(ipStr)
\tif err != nil {
\t\treturn ipStr
\t}
\t
\tres, err := config.AppendEncryptIP(nil, addr)
\tif err != nil {
\t\treturn ipStr
\t}
\t
\treturn unsafe.String(unsafe.SliceData(res), len(res))
}
