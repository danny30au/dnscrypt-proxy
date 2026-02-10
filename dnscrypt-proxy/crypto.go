package main

import (	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	NonceSize        = 24
	HalfNonceSize    = NonceSize / 2
	TagSize          = 16
	PublicKeySize    = 32
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize + NonceSize + TagSize
)

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		// Replicate xsecretbox.SharedKey logic: HChaCha20(X25519(sk, pk), 00...00)
		dhKey, err := curve25519.X25519(secretKey[:], serverPk[:])
		if err != nil {
			dlog.Criticalf("[%v] Weak XChaCha20 public key", providerName)
			return
		}
		var nonce [16]byte // Zero nonce for HChaCha20
		subKey, err := chacha20.HChaCha20(dhKey, nonce[:])
		if err != nil {
			dlog.Fatal(err)
		}
		copy(sharedKey[:], subKey)
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
		c := byte(0)
		for i := 0; i < 32; i++ {
			c |= sharedKey[i]
		}
		if c == 0 {
			dlog.Criticalf("[%v] Weak XSalsa20 public key", providerName)
			if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
				dlog.Fatal(err)
			}
		}
	}
	return sharedKey
}

func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	if _, err := crypto_rand.Read(clientNonce); err != nil {
		return nil, nil, nil, err
	}
	copy(nonce, clientNonce)
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		h := sha512.New512_256()
		h.Write(clientNonce)
		h.Write(proxy.proxySecretKey[:])
		var ephSk [32]byte
		h.Sum(ephSk[:0])
		var xPublicKey [PublicKeySize]byte
		curve25519.ScalarBaseMult(&xPublicKey, &ephSk)
		publicKey = &xPublicKey
		xsharedKey := ComputeSharedKey(serverInfo.CryptoConstruction, &ephSk, &serverInfo.ServerPk, nil)
		sharedKey = &xsharedKey
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}
	minQuestionSize := QueryOverhead + len(packet)
	if proto == "udp" {
		minQuestionSize = Max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
	} else {
		var xpad [1]byte
		if _, err := crypto_rand.Read(xpad[:]); err != nil {
			return nil, nil, nil, err
		}
		minQuestionSize += int(xpad[0])
	}
	paddedLength := Min(MaxDNSUDPPacketSize, (Max(minQuestionSize, QueryOverhead)+1+63)&^63)
	if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
		paddedLength = MaxDNSUDPSafePacketSize
	} else if serverInfo.Relay != nil && proto == "tcp" {
		paddedLength = MaxDNSPacketSize
	}
	if QueryOverhead+len(packet)+1 > paddedLength {
		err = errors.New("Question too large; cannot be padded")
		return sharedKey, encrypted, clientNonce, err
	}
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength-QueryOverhead)

	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		aead, err := chacha20poly1305.NewX(sharedKey[:])
		if err != nil {
			return nil, nil, nil, err
		}
		ctWithTag := aead.Seal(nil, nonce, padded, nil)
		tag := ctWithTag[len(ctWithTag)-16:]
		ct := ctWithTag[:len(ctWithTag)-16]
		encrypted = append(encrypted, tag...)
		encrypted = append(encrypted, ct...)
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return sharedKey, encrypted, clientNonce, err
}

func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error

	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		aead, errNew := chacha20poly1305.NewX(sharedKey[:])
		if errNew != nil {
			return encrypted, errNew
		}
		tagAndCt := encrypted[responseHeaderLen:]
		if len(tagAndCt) < TagSize {
			return encrypted, errors.New("Message too short")
		}
		tag := tagAndCt[:TagSize]
		ct := tagAndCt[TagSize:]

		stdCt := make([]byte, 0, len(ct)+len(tag))
		stdCt = append(stdCt, ct...)
		stdCt = append(stdCt, tag...)

		packet, err = aead.Open(nil, serverNonce, stdCt, nil)
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}

	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
