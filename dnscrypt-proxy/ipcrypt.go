package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jedisct1/dlog"
	ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// Algorithm represents the type of IP encryption algorithm.
// Go 1.26: Using typed constants for better type safety and documentation.
type Algorithm string

// Supported IP encryption algorithms with their characteristics
const (
	// AlgorithmNone disables encryption (passthrough mode)
	AlgorithmNone Algorithm = "none"

	// AlgorithmDeterministic uses deterministic encryption (same IP → same encrypted IP)
	// Key size: 16 bytes (128-bit)
	// Output: Valid IP address format
	// Use case: Log correlation while maintaining privacy
	AlgorithmDeterministic Algorithm = "ipcrypt-deterministic"

	// AlgorithmNonDeterministic uses non-deterministic encryption with 8-byte tweak
	// Key size: 16 bytes (128-bit)
	// Output: Hex-encoded binary (not valid IP format)
	// Use case: Maximum privacy, no correlation
	AlgorithmNonDeterministic Algorithm = "ipcrypt-nd"

	// AlgorithmNonDeterministicX uses extended non-deterministic encryption with 16-byte tweak
	// Key size: 32 bytes (256-bit)
	// Output: Hex-encoded binary (not valid IP format)
	// Use case: Maximum security with longer tweak
	AlgorithmNonDeterministicX Algorithm = "ipcrypt-ndx"

	// AlgorithmPrefixPreserving preserves IP address prefixes during encryption
	// Key size: 32 bytes (256-bit)
	// Output: Valid IP address format with preserved prefix
	// Use case: Network topology analysis while maintaining privacy
	AlgorithmPrefixPreserving Algorithm = "ipcrypt-pfx"
)

// algorithmKeySize maps algorithms to their required key sizes in bytes
var algorithmKeySize = map[Algorithm]int{
	AlgorithmDeterministic:     16, // 128-bit
	AlgorithmNonDeterministic:  16, // 128-bit
	AlgorithmNonDeterministicX: 32, // 256-bit
	AlgorithmPrefixPreserving:  32, // 256-bit
}

// Common errors for IP encryption operations
var (
	ErrInvalidKey       = errors.New("invalid encryption key")
	ErrInvalidKeyLength = errors.New("incorrect key length for algorithm")
	ErrInvalidAlgorithm = errors.New("unsupported encryption algorithm")
	ErrInvalidIP        = errors.New("invalid IP address")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
)

// IPCryptConfig holds the configuration for IP address encryption.
// Go 1.26: Immutable after creation, thread-safe for concurrent use.
type IPCryptConfig struct {
	key       []byte    // Encryption key (private, not exported)
	algorithm Algorithm // Algorithm type
}

// NewIPCryptConfig creates a new IPCryptConfig from configuration values.
// Returns nil when encryption is disabled (algorithm is "none" or empty).
// Go 1.26: Validates configuration at construction time for fail-fast behavior.
func NewIPCryptConfig(keyHex string, algorithmStr string) (*IPCryptConfig, error) {
	// Normalize algorithm string
	algorithmStr = strings.TrimSpace(algorithmStr)
	if algorithmStr == "" {
		algorithmStr = string(AlgorithmNone)
	}

	algorithm := Algorithm(strings.ToLower(algorithmStr))

	// Return nil for disabled encryption (not an error)
	if algorithm == AlgorithmNone {
		return nil, nil
	}

	// Validate algorithm is known
	requiredKeySize, isValidAlgorithm := algorithmKeySize[algorithm]
	if !isValidAlgorithm {
		return nil, fmt.Errorf("%w: %q (supported: %s)",
			ErrInvalidAlgorithm,
			algorithmStr,
			getSupportedAlgorithms())
	}

	// Key is required for non-none algorithms
	if keyHex == "" {
		return nil, fmt.Errorf("encryption algorithm %q requires a key: %w",
			algorithm, ErrInvalidKey)
	}

	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("%w (must be hexadecimal): %w", ErrInvalidKey, err)
	}

	// Validate key length
	if len(key) != requiredKeySize {
		return nil, fmt.Errorf("%w: %s requires %d bytes (%d hex chars), got %d bytes",
			ErrInvalidKeyLength,
			algorithm,
			requiredKeySize,
			requiredKeySize*2,
			len(key))
	}

	// Create immutable config
	config := &IPCryptConfig{
		key:       key,
		algorithm: algorithm,
	}

	return config, nil
}

// Algorithm returns the configured encryption algorithm.
func (c *IPCryptConfig) Algorithm() Algorithm {
	if c == nil {
		return AlgorithmNone
	}
	return c.algorithm
}

// IsEnabled returns true if encryption is enabled (not nil and not "none").
func (c *IPCryptConfig) IsEnabled() bool {
	return c != nil && c.algorithm != AlgorithmNone
}

// EncryptIP encrypts an IP address using the configured encryption.
// Go 1.26: Optimized with strategy pattern for algorithm dispatch.
func (c *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
	// Passthrough when encryption disabled
	if c == nil {
		return ip.String(), nil
	}

	// Validate input
	if ip == nil || len(ip) == 0 {
		return "", fmt.Errorf("%w: nil or empty IP", ErrInvalidIP)
	}

	// Dispatch to algorithm-specific implementation
	switch c.algorithm {
	case AlgorithmDeterministic:
		return c.encryptDeterministic(ip)

	case AlgorithmNonDeterministic:
		return c.encryptNonDeterministic(ip, 8)

	case AlgorithmNonDeterministicX:
		return c.encryptNonDeterministic(ip, 16)

	case AlgorithmPrefixPreserving:
		return c.encryptPrefixPreserving(ip)

	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// EncryptAddr encrypts a netip.Addr using the configured encryption.
// Go 1.26: Zero-allocation IP operations using netip.Addr.
func (c *IPCryptConfig) EncryptAddr(addr netip.Addr) (string, error) {
	if c == nil {
		return addr.String(), nil
	}

	if !addr.IsValid() {
		return "", fmt.Errorf("%w: invalid netip.Addr", ErrInvalidIP)
	}

	// Convert to net.IP for ipcrypt library compatibility
	ip := addr.AsSlice()
	return c.EncryptIP(ip)
}

// EncryptIPString encrypts an IP address string.
// Returns the original string if it's not a valid IP or encryption fails.
// Go 1.26: Uses netip.ParseAddr for faster parsing and better type safety.
func (c *IPCryptConfig) EncryptIPString(ipStr string) string {
	if c == nil || ipStr == "" {
		return ipStr
	}

	// Try parsing with netip.ParseAddr first (faster)
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		encrypted, err := c.EncryptAddr(addr)
		if err != nil {
			dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
			return "[encrypted]"
		}
		return encrypted
	}

	// Fallback to net.ParseIP for compatibility
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Not a valid IP, return as-is (might be hostname or other format)
		return ipStr
	}

	encrypted, err := c.EncryptIP(ip)
	if err != nil {
		dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
		return "[encrypted]"
	}

	return encrypted
}

// DecryptIP decrypts an encrypted IP address string.
// Go 1.26: Returns error for proper error handling instead of silent failures.
func (c *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
	// Passthrough when encryption disabled
	if c == nil {
		return encryptedStr, nil
	}

	// Validate input
	if encryptedStr == "" {
		return "", fmt.Errorf("%w: empty encrypted string", ErrInvalidIP)
	}

	// Dispatch to algorithm-specific implementation
	switch c.algorithm {
	case AlgorithmDeterministic:
		return c.decryptDeterministic(encryptedStr)

	case AlgorithmNonDeterministic:
		return c.decryptNonDeterministic(encryptedStr)

	case AlgorithmNonDeterministicX:
		return c.decryptNonDeterministicX(encryptedStr)

	case AlgorithmPrefixPreserving:
		return c.decryptPrefixPreserving(encryptedStr)

	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// encryptDeterministic encrypts using deterministic algorithm.
func (c *IPCryptConfig) encryptDeterministic(ip net.IP) (string, error) {
	encrypted, err := ipcrypt.EncryptIP(c.key, ip)
	if err != nil {
		return "", fmt.Errorf("%w (deterministic): %w", ErrEncryptionFailed, err)
	}
	return encrypted.String(), nil
}

// encryptNonDeterministic encrypts using non-deterministic algorithm with specified tweak size.
// Go 1.26: Unified implementation for both nd and ndx modes.
func (c *IPCryptConfig) encryptNonDeterministic(ip net.IP, tweakSize int) (string, error) {
	// Generate cryptographically secure random tweak
	tweak := make([]byte, tweakSize)
	if _, err := rand.Read(tweak); err != nil {
		return "", fmt.Errorf("failed to generate random tweak: %w", err)
	}

	var encrypted []byte
	var err error

	if tweakSize == 8 {
		encrypted, err = ipcrypt.EncryptIPNonDeterministic(ip.String(), c.key, tweak)
	} else {
		encrypted, err = ipcrypt.EncryptIPNonDeterministicX(ip.String(), c.key, tweak)
	}

	if err != nil {
		return "", fmt.Errorf("%w (non-deterministic): %w", ErrEncryptionFailed, err)
	}

	// Return as hex-encoded string (includes tweak)
	return hex.EncodeToString(encrypted), nil
}

// encryptPrefixPreserving encrypts using prefix-preserving algorithm.
func (c *IPCryptConfig) encryptPrefixPreserving(ip net.IP) (string, error) {
	encrypted, err := ipcrypt.EncryptIPPfx(ip, c.key)
	if err != nil {
		return "", fmt.Errorf("%w (prefix-preserving): %w", ErrEncryptionFailed, err)
	}
	return encrypted.String(), nil
}

// decryptDeterministic decrypts using deterministic algorithm.
func (c *IPCryptConfig) decryptDeterministic(encryptedStr string) (string, error) {
	// Parse encrypted IP
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: invalid encrypted IP format: %s", ErrInvalidIP, encryptedStr)
	}

	decrypted, err := ipcrypt.DecryptIP(c.key, ip)
	if err != nil {
		return "", fmt.Errorf("%w (deterministic): %w", ErrDecryptionFailed, err)
	}

	return decrypted.String(), nil
}

// decryptNonDeterministic decrypts using non-deterministic algorithm (8-byte tweak).
func (c *IPCryptConfig) decryptNonDeterministic(encryptedStr string) (string, error) {
	// Decode hex-encoded encrypted data
	encrypted, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}

	decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, c.key)
	if err != nil {
		return "", fmt.Errorf("%w (non-deterministic): %w", ErrDecryptionFailed, err)
	}

	return decrypted, nil
}

// decryptNonDeterministicX decrypts using extended non-deterministic algorithm (16-byte tweak).
func (c *IPCryptConfig) decryptNonDeterministicX(encryptedStr string) (string, error) {
	// Decode hex-encoded encrypted data
	encrypted, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}

	decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, c.key)
	if err != nil {
		return "", fmt.Errorf("%w (extended non-deterministic): %w", ErrDecryptionFailed, err)
	}

	return decrypted, nil
}

// decryptPrefixPreserving decrypts using prefix-preserving algorithm.
func (c *IPCryptConfig) decryptPrefixPreserving(encryptedStr string) (string, error) {
	// Parse encrypted IP
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: invalid encrypted IP format: %s", ErrInvalidIP, encryptedStr)
	}

	decrypted, err := ipcrypt.DecryptIPPfx(ip, c.key)
	if err != nil {
		return "", fmt.Errorf("%w (prefix-preserving): %w", ErrDecryptionFailed, err)
	}

	return decrypted.String(), nil
}

// getSupportedAlgorithms returns a comma-separated list of supported algorithms.
func getSupportedAlgorithms() string {
	algorithms := []string{
		string(AlgorithmNone),
		string(AlgorithmDeterministic),
		string(AlgorithmNonDeterministic),
		string(AlgorithmNonDeterministicX),
		string(AlgorithmPrefixPreserving),
	}
	return strings.Join(algorithms, ", ")
}
