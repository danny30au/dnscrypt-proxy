package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Cryptographic constants for DNSCrypt protocol
// Go 1.26: Well-documented constants for protocol compliance
const (
	// NonceSize is the size of nonces in bytes (192 bits)
	NonceSize = 24

	// HalfNonceSize is used for client nonce generation (96 bits)
	HalfNonceSize = NonceSize / 2

	// TagSize is the authentication tag size for AEAD ciphers (128 bits)
	TagSize = 16

	// PublicKeySize is the size of public keys in bytes (256 bits)
	PublicKeySize = 32

	// QueryOverhead is the total overhead added to encrypted queries
	// Structure: ClientMagic + PublicKey + HalfNonce + Tag
	QueryOverhead = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize

	// ResponseOverhead is the total overhead for encrypted responses
	// Structure: ServerMagic + Nonce + Tag + Nonce + Tag
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize + NonceSize + TagSize

	// paddingDelimiter marks the start of padding (ISO/IEC 7816-4)
	paddingDelimiter = 0x80
)

// Sentinel errors for better error handling and testing
var (
	ErrInvalidPaddingShort     = errors.New("invalid padding: packet too short")
	ErrInvalidPaddingDelimiter = errors.New("invalid padding: delimiter not found")
	ErrQuestionTooLarge        = errors.New("question too large; cannot be padded")
	ErrInvalidMessageSize      = errors.New("invalid message size or prefix")
	ErrUnexpectedNonce         = errors.New("unexpected nonce mismatch")
	ErrMessageTooShort         = errors.New("message too short for decryption")
	ErrIncorrectTag            = errors.New("incorrect authentication tag")
	ErrIncorrectPadding        = errors.New("incorrect padding after decryption")
	ErrWeakPublicKey           = errors.New("weak public key detected")
)

// pad applies ISO/IEC 7816-4 padding to a packet to reach minSize.
// Go 1.26: Preallocates buffer for better performance.
func pad(packet []byte, minSize int) []byte {
	currentLen := len(packet)
	if currentLen >= minSize {
		// Already at or above minimum size, just add delimiter
		return append(packet, paddingDelimiter)
	}

	// Preallocate exact size needed (single allocation)
	result := make([]byte, minSize)
	copy(result, packet)
	result[currentLen] = paddingDelimiter

	// Remaining bytes are already zero from make()
	return result
}

// unpad removes ISO/IEC 7816-4 padding from a packet.
// Go 1.26: Cleaner loop structure with explicit bounds checking.
func unpad(packet []byte) ([]byte, error) {
	length := len(packet)

	// Search backwards for padding delimiter
	for i := length - 1; i >= 0; i-- {
		switch packet[i] {
		case paddingDelimiter:
			// Found delimiter - return unpadded data
			return packet[:i], nil

		case 0x00:
			// Valid padding byte, continue searching
			continue

		default:
			// Invalid padding byte
			return nil, ErrInvalidPaddingDelimiter
		}
	}

	// No delimiter found in entire packet
	return nil, ErrInvalidPaddingShort
}

// isZeroKey checks if a key consists only of zero bytes.
// Go 1.26: Constant-time comparison for security.
func isZeroKey(key []byte) bool {
	var result byte
	for i := 0; i < len(key); i++ {
		result |= key[i]
	}
	return result == 0
}

// ComputeSharedKey computes a shared secret key using X25519 key exchange.
// Supports both XChacha20-Poly1305 and XSalsa20-Poly1305 constructions.
// Go 1.26: Better error handling and clearer logic flow.
func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		// XChacha20-Poly1305: HChaCha20(X25519(sk, pk), 00...00)
		dhKey, err := curve25519.X25519(secretKey[:], serverPk[:])
		if err != nil {
			if providerName != nil {
				dlog.Criticalf("[%v] Weak XChaCha20 public key", *providerName)
			} else {
				dlog.Critical("Weak XChaCha20 public key")
			}
			return
		}

		// Apply HChaCha20 with zero nonce
		var zeroNonce [16]byte
		subKey, err := chacha20.HChaCha20(dhKey, zeroNonce[:])
		if err != nil {
			dlog.Fatal(err)
		}

		copy(sharedKey[:], subKey)
	} else {
		// XSalsa20-Poly1305: Use NaCl box precomputation
		box.Precompute(&sharedKey, serverPk, secretKey)

		// Validate shared key is non-zero (security check)
		if isZeroKey(sharedKey[:]) {
			if providerName != nil {
				dlog.Criticalf("[%v] Weak XSalsa20 public key", *providerName)
			} else {
				dlog.Critical("Weak XSalsa20 public key")
			}

			// Generate random key as fallback (prevents protocol failure)
			if _, err := rand.Read(sharedKey[:]); err != nil {
				dlog.Fatal(err)
			}
		}
	}

	return sharedKey
}

// Encrypt encrypts a DNS packet using the DNSCrypt protocol.
// Returns the shared key, encrypted packet, client nonce, and any error.
// Go 1.26: Improved structure with helper functions and better error handling.
func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	// Generate random client nonce
	clientNonce = make([]byte, HalfNonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// Full nonce starts with client nonce
	nonce := make([]byte, NonceSize)
	copy(nonce, clientNonce)

	// Compute or retrieve public key and shared key
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		publicKey, sharedKey, err = proxy.generateEphemeralKeys(serverInfo, clientNonce)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ephemeral key generation failed: %w", err)
		}
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}

	// Calculate padding length
	paddedLength, err := proxy.calculatePaddedLength(serverInfo, packet, proto)
	if err != nil {
		return sharedKey, nil, clientNonce, err
	}

	// Build encrypted packet
	encrypted = proxy.buildEncryptedPacket(serverInfo, publicKey, clientNonce, packet, paddedLength, nonce, sharedKey)

	return sharedKey, encrypted, clientNonce, nil
}

// generateEphemeralKeys creates ephemeral keys for forward secrecy.
// Go 1.26: Extracted for clarity and testability.
func (proxy *Proxy) generateEphemeralKeys(
	serverInfo *ServerInfo,
	clientNonce []byte,
) (*[PublicKeySize]byte, *[32]byte, error) {
	// Derive ephemeral secret key from client nonce and proxy secret
	h := sha512.New512_256()
	h.Write(clientNonce)
	h.Write(proxy.proxySecretKey[:])

	var ephSk [32]byte
	h.Sum(ephSk[:0])

	// Compute ephemeral public key
	var ephPk [PublicKeySize]byte
	curve25519.ScalarBaseMult(&ephPk, &ephSk)

	// Compute shared key using ephemeral secret
	computedSharedKey := ComputeSharedKey(
		serverInfo.CryptoConstruction,
		&ephSk,
		&serverInfo.ServerPk,
		nil,
	)

	// Zero out ephemeral secret key (Go 1.21+ clear is more efficient)
	clear(ephSk[:])

	return &ephPk, &computedSharedKey, nil
}

// calculatePaddedLength determines the appropriate padding for the protocol.
// Go 1.26: Extracted for clarity and better error messages.
func (proxy *Proxy) calculatePaddedLength(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (int, error) {
	minQuestionSize := QueryOverhead + len(packet)

	if proto == "udp" {
		// Use question size estimator for UDP
		minQuestionSize = max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
	} else {
		// Add random padding for TCP (up to 255 bytes)
		var randomPad [1]byte
		if _, err := rand.Read(randomPad[:]); err != nil {
			return 0, fmt.Errorf("failed to generate random padding: %w", err)
		}
		minQuestionSize += int(randomPad[0])
	}

	// Calculate padded length (round up to 64-byte boundary)
	paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)

	// Adjust for known bugs and relay configuration
	if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
		paddedLength = MaxDNSUDPSafePacketSize
	} else if serverInfo.Relay != nil && proto == "tcp" {
		paddedLength = MaxDNSPacketSize
	}

	// Validate packet fits with padding
	if QueryOverhead+len(packet)+1 > paddedLength {
		return 0, ErrQuestionTooLarge
	}

	return paddedLength, nil
}

// buildEncryptedPacket constructs the final encrypted packet.
// Go 1.26: Preallocates buffer and uses efficient append operations.
func (proxy *Proxy) buildEncryptedPacket(
	serverInfo *ServerInfo,
	publicKey *[PublicKeySize]byte,
	clientNonce []byte,
	packet []byte,
	paddedLength int,
	nonce []byte,
	sharedKey *[32]byte,
) []byte {
	// Preallocate encrypted buffer with known size
	estimatedSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + paddedLength
	encrypted := make([]byte, 0, estimatedSize)

	// Build header: MagicQuery + PublicKey + ClientNonce
	encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
	encrypted = append(encrypted, publicKey[:]...)
	encrypted = append(encrypted, clientNonce...)

	// Apply padding to packet
	padded := pad(packet, paddedLength-QueryOverhead)

	// Encrypt based on construction type
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		encrypted = proxy.encryptXChaCha20(encrypted, padded, nonce, sharedKey)
	} else {
		encrypted = proxy.encryptXSalsa20(encrypted, padded, nonce, sharedKey)
	}

	return encrypted
}

// encryptXChaCha20 encrypts using XChaCha20-Poly1305.
// Go 1.26: Extracted for clarity, handles tag separately as per protocol.
func (proxy *Proxy) encryptXChaCha20(
	encrypted []byte,
	padded []byte,
	nonce []byte,
	sharedKey *[32]byte,
) []byte {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		// This should never happen with valid key
		dlog.Fatalf("Failed to create XChaCha20-Poly1305 cipher: %v", err)
		return encrypted
	}

	// Encrypt and get ciphertext with tag
	ctWithTag := aead.Seal(nil, nonce, padded, nil)

	// Split tag and ciphertext (protocol requirement)
	tagOffset := len(ctWithTag) - TagSize
	tag := ctWithTag[tagOffset:]
	ct := ctWithTag[:tagOffset]

	// Append tag first, then ciphertext
	encrypted = append(encrypted, tag...)
	encrypted = append(encrypted, ct...)

	return encrypted
}

// encryptXSalsa20 encrypts using XSalsa20-Poly1305 (NaCl secretbox).
// Go 1.26: Extracted for clarity and consistency.
func (proxy *Proxy) encryptXSalsa20(
	encrypted []byte,
	padded []byte,
	nonce []byte,
	sharedKey *[32]byte,
) []byte {
	var xsalsaNonce [24]byte
	copy(xsalsaNonce[:], nonce)

	// NaCl secretbox.Seal appends to first argument
	return secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
}

// Decrypt decrypts a DNS response using the DNSCrypt protocol.
// Go 1.26: Improved validation and error handling with better structure.
func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	// Validate response structure
	if err := proxy.validateResponse(encrypted, nonce); err != nil {
		return encrypted, err
	}

	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]

	// Decrypt based on construction type
	var packet []byte
	var err error

	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		packet, err = proxy.decryptXChaCha20(encrypted[responseHeaderLen:], serverNonce, sharedKey)
	} else {
		packet, err = proxy.decryptXSalsa20(encrypted[responseHeaderLen:], serverNonce, sharedKey)
	}

	if err != nil {
		return encrypted, err
	}

	// Remove padding and validate
	packet, err = unpad(packet)
	if err != nil {
		return encrypted, fmt.Errorf("%w: %w", ErrIncorrectPadding, err)
	}

	if len(packet) < MinDNSPacketSize {
		return encrypted, fmt.Errorf("%w: packet size %d < minimum %d",
			ErrIncorrectPadding, len(packet), MinDNSPacketSize)
	}

	return packet, nil
}

// validateResponse performs initial validation of encrypted response.
// Go 1.26: Extracted for clarity and better error messages.
func (proxy *Proxy) validateResponse(encrypted []byte, nonce []byte) error {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	minResponseSize := responseHeaderLen + TagSize + int(MinDNSPacketSize)
	maxResponseSize := responseHeaderLen + TagSize + int(MaxDNSPacketSize)

	// Check size bounds
	encryptedLen := len(encrypted)
	if encryptedLen < minResponseSize || encryptedLen > maxResponseSize {
		return fmt.Errorf("%w: size %d not in range [%d, %d]",
			ErrInvalidMessageSize, encryptedLen, minResponseSize, maxResponseSize)
	}

	// Verify server magic
	if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return fmt.Errorf("%w: invalid magic prefix", ErrInvalidMessageSize)
	}

	// Verify nonce matches
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return ErrUnexpectedNonce
	}

	return nil
}

// decryptXChaCha20 decrypts using XChaCha20-Poly1305.
// Go 1.26: Handles protocol-specific tag+ciphertext format.
func (proxy *Proxy) decryptXChaCha20(
	tagAndCt []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	// Validate minimum length
	if len(tagAndCt) < TagSize {
		return nil, ErrMessageTooShort
	}

	// Protocol sends tag first, then ciphertext
	tag := tagAndCt[:TagSize]
	ct := tagAndCt[TagSize:]

	// AEAD expects ciphertext + tag, so reconstruct
	stdFormat := make([]byte, 0, len(ct)+len(tag))
	stdFormat = append(stdFormat, ct...)
	stdFormat = append(stdFormat, tag...)

	// Decrypt and verify
	packet, err := aead.Open(nil, serverNonce, stdFormat, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIncorrectTag, err)
	}

	return packet, nil
}

// decryptXSalsa20 decrypts using XSalsa20-Poly1305 (NaCl secretbox).
// Go 1.26: Consistent with encryption counterpart.
func (proxy *Proxy) decryptXSalsa20(
	ciphertext []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	var xsalsaServerNonce [24]byte
	copy(xsalsaServerNonce[:], serverNonce)

	packet, ok := secretbox.Open(nil, ciphertext, &xsalsaServerNonce, sharedKey)
	if !ok {
		return nil, ErrIncorrectTag
	}

	return packet, nil
}
