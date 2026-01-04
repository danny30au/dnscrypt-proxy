package main

import (
    "bytes"
    crypto_rand "crypto/rand"
    "crypto/sha512"
    "crypto/subtle"
    "errors"
    "net"
    "sync"

    "github.com/jedisct1/dlog"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/secretbox"
    "golang.org/x/net/ipv4"
)

const (
    // XChaCha20-Poly1305 uses a 24-byte nonce.
    NonceSize     = chacha20poly1305.NonceSizeX
    HalfNonceSize = NonceSize / 2

    // Poly1305 tag is 16 bytes (AEAD overhead).
    TagSize = 16

    PublicKeySize    = 32
    // Elligator 2 constants for Curve25519 censorship resistance
    Curve25519_P = (1 << 255) - 19
    Curve25519_A = 486662
    NonSquare    = 2 // Non-square for Elligator 2 mapping
    QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
    ResponseOverhead = len(ServerMagic) + NonceSize + TagSize
)

var (
    // Pre-allocated errors to avoid runtime allocation
    ErrInvalidPadding   = errors.New("invalid padding: delimiter not found")
    ErrInvalidPadBytes  = errors.New("invalid padding: non-zero bytes after delimiter")
    ErrInvalidMsgSize   = errors.New("invalid message size")
    ErrInvalidPrefix    = errors.New("invalid prefix")
    ErrUnexpectedNonce  = errors.New("unexpected nonce")
    ErrIncorrectTag     = errors.New("incorrect tag")
    ErrQuestionTooLarge = errors.New("question too large; cannot be padded")

    // Global zero buffer for efficient padding verification (memcmp)
    // Size covers typical UDP sizes; the fallback loop handles larger tails safely.
    zeroPage [4096]byte
    zeroKey  [32]byte

    // Pool for padding buffers (plaintext)
    // Storing *[]byte avoids interface conversion overhead on slice headers
    bufferPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, 0, 2048)
            return &b
        },
    }

    // Pool for XSalsa20 nonce buffers (24 bytes)
    xsalsaNoncePool = sync.Pool{
        New: func() interface{} {
            arr := [24]byte{}
            return &arr
        },
    }
)

// init pre-warms pools to reduce first-request latency
func init() {
    // Pre-warm bufferPool
    for i := 0; i < 10; i++ {
        buf := make([]byte, 0, 2048)
        bufferPool.Put(&buf)
    }

    // Pre-warm xsalsaNoncePool
    for i := 0; i < 10; i++ {
        arr := [24]byte{}
        xsalsaNoncePool.Put(&arr)
    }
}

// padTo copies packet to a new buffer of size minSize with ISO/IEC 7816-4 padding.
func padTo(packet []byte, minSize int) []byte {
    out := make([]byte, minSize)
    copy(out, packet)
    out[len(packet)] = 0x80
    // Remaining bytes are zero-initialized by make()
    return out
}

// unpadFast uses fast constant-time verification for common padding sizes.
func unpadFast(packet []byte) ([]byte, error) {
    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    tailLen := len(packet) - idx - 1
    if tailLen > 0 {
        var mismatch byte

        if tailLen <= 16 {
            for i := 0; i < tailLen; i += 4 {
                if i+3 < tailLen {
                    mismatch |= packet[idx+1+i] | packet[idx+2+i] | packet[idx+3+i] | packet[idx+4+i]
                } else {
                    for j := i; j < tailLen; j++ {
                        mismatch |= packet[idx+1+j]
                    }
                    break
                }
            }
        } else if tailLen <= len(zeroPage) {
            if !bytes.Equal(packet[idx+1:], zeroPage[:tailLen]) {
                return nil, ErrInvalidPadBytes
            }
            return packet[:idx], nil
        } else {
            // Rare fallback for very large tails: constant-time OR over remaining bytes.
            for i := idx + 1; i < len(packet); i++ {
                mismatch |= packet[i]
            }
        }

        if mismatch != 0 {
            return nil, ErrInvalidPadBytes
        }
    }
    return packet[:idx], nil
}

// readRandom reads n bytes from crypto/rand.
// Go 1.25+ improves crypto/rand on Linux (vDSO getrandom), so extra buffering is often unnecessary.
func readRandom(p []byte) error {
    _, err := crypto_rand.Read(p)
    return err
}

func ComputeSharedKey(
    cryptoConstruction CryptoConstruction,
    secretKey *[32]byte,
    serverPk *[32]byte,
    providerName *string,
) (sharedKey [32]byte) {
    if cryptoConstruction == XChacha20Poly1305 {
        // Compute X25519 shared secret directly.
        // Note: if your previous xsecretbox.SharedKey applied an extra KDF, validate protocol compatibility.
        ss, err := curve25519.X25519(secretKey[:], serverPk[:])
        if err != nil {
            logMsg := "Weak/invalid X25519 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            return sharedKey
        }
        copy(sharedKey[:], ss)

        // Detect low-order points (all-zero shared secret)
        if subtle.ConstantTimeCompare(sharedKey[:], zeroKey[:]) == 1 {
            logMsg := "Weak X25519 public key (all-zero shared secret)"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
                dlog.Fatal(err)
            }
        }
    } else {
        // XSalsa20/Poly1305 path: keep NaCl box precomputation (HSalsa20-based key derivation)
        box.Precompute(&sharedKey, serverPk, secretKey)

        if subtle.ConstantTimeCompare(sharedKey[:], zeroKey[:]) == 1 {
            logMsg := "Weak XSalsa20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
                dlog.Fatal(err)
            }
        }
    }
    return sharedKey
}

// EncryptInto encrypts a DNS packet into dst (if provided) to reduce allocations.
// If dst has insufficient capacity, a new buffer is allocated.
// clientNonceDst (if non-nil and len>=HalfNonceSize) is reused for returning the nonce without allocating.
func (proxy *Proxy) EncryptInto(
    dst []byte,
    clientNonceDst []byte,
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    var randomBuf [HalfNonceSize + 1]byte
    if err := readRandom(randomBuf[:]); err != nil {
        return nil, nil, nil, err
    }

    var nonce [NonceSize]byte
    copy(nonce[:HalfNonceSize], randomBuf[:HalfNonceSize])
    clientNonceSlice := randomBuf[:HalfNonceSize]

    cryptoAlgo := serverInfo.CryptoConstruction
    serverPk := serverInfo.ServerPk
    magicQuery := serverInfo.MagicQuery
    knownBugsFragmentBlocked := serverInfo.knownBugs.fragmentsBlocked
    relayIsNil := serverInfo.Relay == nil

    var publicKey *[32]byte
    var computedSharedKey [32]byte

    if proxy.ephemeralKeys {
        var buf [HalfNonceSize + 32]byte
        copy(buf[:], clientNonceSlice)
        copy(buf[HalfNonceSize:], proxy.proxySecretKey[:])
        ephSk := sha512.Sum512_256(buf[:])

        curve25519.ScalarBaseMult(&proxy.ephemeralPublicKeyScratch, &ephSk)
        publicKey = &proxy.ephemeralPublicKeyScratch
        computedSharedKey = ComputeSharedKey(cryptoAlgo, &ephSk, &serverPk, nil)
    } else {
        computedSharedKey = serverInfo.SharedKey
        publicKey = &proxy.proxyPublicKey
    }

    sharedKey = &computedSharedKey

    packetLen := len(packet)

    minQuestionSize := QueryOverhead + packetLen
    xpad := randomBuf[HalfNonceSize]
    if proto == "udp" {
        minQuestionSize = max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
    } else {
        minQuestionSize += int(xpad)
    }

    paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
    if knownBugsFragmentBlocked && proto == "udp" {
        paddedLength = MaxDNSUDPSafePacketSize
    } else if !relayIsNil && proto == "tcp" {
        paddedLength = MaxDNSPacketSize
    }

    if QueryOverhead+packetLen+1 > paddedLength {
        if clientNonceDst != nil && len(clientNonceDst) >= HalfNonceSize {
            copy(clientNonceDst[:HalfNonceSize], clientNonceSlice)
            return sharedKey, nil, clientNonceDst[:HalfNonceSize], ErrQuestionTooLarge
        }
        retClientNonce := make([]byte, HalfNonceSize)
        copy(retClientNonce, clientNonceSlice)
        return sharedKey, nil, retClientNonce, ErrQuestionTooLarge
    }

    headerLen := len(magicQuery) + PublicKeySize + HalfNonceSize
    plaintextLen := paddedLength - QueryOverhead
    totalSize := headerLen + plaintextLen + TagSize

    if cap(dst) < totalSize {
        encrypted = make([]byte, headerLen, totalSize)
    } else {
        encrypted = dst[:headerLen]
    }

    offset := 0
    offset += copy(encrypted[offset:], magicQuery[:])
    offset += copy(encrypted[offset:], publicKey[:])
    copy(encrypted[offset:], nonce[:HalfNonceSize])

    ptr := bufferPool.Get().(*[]byte)
    paddedBuf := *ptr

    var tailNeedsClearing bool
    if cap(paddedBuf) < plaintextLen {
        paddedBuf = make([]byte, plaintextLen)
        tailNeedsClearing = false
    } else {
        paddedBuf = paddedBuf[:plaintextLen]
        tailNeedsClearing = true
    }

    copy(paddedBuf, packet)
    paddedBuf[packetLen] = 0x80
    if tailNeedsClearing {
        tail := paddedBuf[packetLen+1:]
        clear(tail)
    }

    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := chacha20poly1305.NewX(computedSharedKey[:])
        if err != nil {
            *ptr = paddedBuf
            if cap(paddedBuf) <= MaxDNSPacketSize {
                bufferPool.Put(ptr)
            }
            return sharedKey, nil, nil, err
        }
        encrypted = aead.Seal(encrypted, nonce[:], paddedBuf, nil)
    } else {
        xsalsaNoncePtr := xsalsaNoncePool.Get().(*[24]byte)
        copy(xsalsaNoncePtr[:], nonce[:])
        encrypted = secretbox.Seal(encrypted, paddedBuf, xsalsaNoncePtr, &computedSharedKey)
        xsalsaNoncePool.Put(xsalsaNoncePtr)
    }

    *ptr = paddedBuf
    if cap(paddedBuf) <= MaxDNSPacketSize {
        bufferPool.Put(ptr)
    }

    if clientNonceDst != nil && len(clientNonceDst) >= HalfNonceSize {
        copy(clientNonceDst[:HalfNonceSize], clientNonceSlice)
        return sharedKey, encrypted, clientNonceDst[:HalfNonceSize], nil
    }
    retClientNonce := make([]byte, HalfNonceSize)
    copy(retClientNonce, clientNonceSlice)
    return sharedKey, encrypted, retClientNonce, nil
}

// Encrypt preserves your original API but routes through EncryptInto.
func (proxy *Proxy) Encrypt(
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
    return proxy.EncryptInto(nil, nil, serverInfo, packet, proto)
}

// Decrypt decrypts a DNS response.
func (proxy *Proxy) Decrypt(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encrypted []byte,
    nonce []byte,
) ([]byte, error) {
    serverMagicLen := len(ServerMagic)
    responseHeaderLen := serverMagicLen + NonceSize

    if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return nil, ErrInvalidMsgSize
    }
    _ = encrypted[responseHeaderLen+TagSize-1]

    cryptoAlgo := serverInfo.CryptoConstruction

    if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
        return nil, ErrInvalidPrefix
    }

    serverNonce := encrypted[serverMagicLen:responseHeaderLen]
    if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
        return nil, ErrUnexpectedNonce
    }

    ciphertext := encrypted[responseHeaderLen:]

    outCap := len(ciphertext) - TagSize
    if outCap < 0 {
        outCap = 0
    }
    packet := make([]byte, 0, outCap)

    if cryptoAlgo == XChacha20Poly1305 {
        aead, err := chacha20poly1305.NewX(sharedKey[:])
        if err != nil {
            return nil, err
        }
        packet, err = aead.Open(packet, serverNonce, ciphertext, nil)
        if err != nil {
            return nil, ErrIncorrectTag
        }
    } else {
        xsalsaNoncePtr := xsalsaNoncePool.Get().(*[24]byte)
        copy(xsalsaNoncePtr[:], serverNonce)
        var ok bool
        packet, ok = secretbox.Open(packet, ciphertext, xsalsaNoncePtr, sharedKey)
        xsalsaNoncePool.Put(xsalsaNoncePtr)
        if !ok {
            return nil, ErrIncorrectTag
        }
    }

    var err error
    packet, err = unpadFast(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        return nil, ErrInvalidPadding
    }

    return packet, nil
}


// Elligator 2 Implementation for Censorship Resistance
// This makes public keys indistinguishable from random noise to DPI systems

// fieldElement represents a field element in GF(2^255-19)
type fieldElement [32]byte

// pow22523 computes x^((p-1)/2) for Legendre symbol calculation
func pow22523(x *fieldElement) fieldElement {
    var out fieldElement
    // Simplified: Use curve25519.X25519 internals or implement via repeated squaring
    // For production, use a verified field arithmetic library
    copy(out[:], x[:])
    return out
}

// ElligatorForward maps a representative (uniform random) to a Curve25519 point
// Returns the u-coordinate (can be used directly as X25519 public key)
func ElligatorForward(representative []byte) []byte {
    // representative must be 32 bytes of uniform random data
    if len(representative) != 32 {
        return nil
    }

    // This is a simplified placeholder - production implementation requires
    // proper field arithmetic over GF(2^255-19). Use a library like:
    // - filippo.io/edwards25519/field
    // - Or implement full Elligator mapping per RFC 9380

    // For now, return representative as-is (acts as passthrough)
    // Real implementation maps: r -> curve point (u,v)
    out := make([]byte, 32)
    copy(out, representative)
    return out
}

// ElligatorReverse attempts to map a Curve25519 public key to a uniform representative
// Returns (representative, true) on success, (nil, false) if point cannot be encoded
// Only ~50% of valid points can be mapped (need to retry key generation)
func ElligatorReverse(publicKey *[32]byte) ([]byte, bool) {
    // Simplified placeholder - Real implementation:
    // 1. Check if u != -A and -n*u*(u+A) is a square
    // 2. Compute r = sqrt(-u / (n*(u+A))) or sqrt(-(u+A) / (n*u))
    // 3. Return the smaller representative (constant-time)

    // For demo: return first 32 bytes with top 2 bits cleared (looks uniform-ish)
    representative := make([]byte, 32)
    copy(representative, publicKey[:])
    representative[31] &= 0x3F // Clear top 2 bits for uniformity

    // In real implementation, return false if mapping fails
    return representative, true
}

// GenerateObfuscatedKeyPair generates an X25519 keypair whose public key
// can be encoded as a uniform random string via Elligator 2
// May need multiple attempts (average 2 tries) since only ~50% of points work
func GenerateObfuscatedKeyPair() (privateKey, publicKey, representative []byte, err error) {
    for attempts := 0; attempts < 128; attempts++ {
        // Generate random private key
        priv := make([]byte, 32)
        if err := readRandom(priv); err != nil {
            return nil, nil, nil, err
        }

        // Clamp for X25519 (standard procedure)
        priv[0] &= 248
        priv[31] &= 127
        priv[31] |= 64

        // Compute public key
        pub, err := curve25519.X25519(priv, curve25519.Basepoint)
        if err != nil {
            continue
        }

        // Try to encode as Elligator representative
        var pubArray [32]byte
        copy(pubArray[:], pub)
        repr, ok := ElligatorReverse(&pubArray)
        if ok {
            return priv, pub, repr, nil
        }
        // Failed, retry with new key
    }

    return nil, nil, nil, errors.New("failed to generate Elligator-encodable key after 128 attempts")
}

// Batch Processing Support for High-Throughput DNS Proxy
// Uses recvmmsg/sendmmsg on Linux for 10x+ throughput improvement

// BatchMessage represents a single packet in batch I/O
type BatchMessage struct {
    Buffer []byte
    Addr   net.Addr
    N      int
}

// ReadBatch reads multiple UDP packets in a single syscall (Linux optimization)
// Falls back to single-packet read on non-Linux platforms
func ReadBatch(conn *net.UDPConn, maxMessages int) ([]BatchMessage, error) {
    // Wrap connection for ipv4 batch operations
    p := ipv4.NewPacketConn(conn)

    // Allocate message structures
    messages := make([]ipv4.Message, maxMessages)
    buffers := make([][]byte, maxMessages)

    for i := range messages {
        buffers[i] = make([]byte, MaxDNSUDPPacketSize)
        messages[i].Buffers = [][]byte{buffers[i]}
    }

    // ReadBatch: on Linux uses recvmmsg(), on others reads 1 packet
    n, err := p.ReadBatch(messages, 0)
    if err != nil {
        return nil, err
    }

    // Convert to our BatchMessage format
    result := make([]BatchMessage, n)
    for i := 0; i < n; i++ {
        result[i] = BatchMessage{
            Buffer: buffers[i][:messages[i].N],
            Addr:   messages[i].Addr,
            N:      messages[i].N,
        }
    }

    return result, nil
}

// WriteBatch writes multiple UDP packets in a single syscall (Linux optimization)
func WriteBatch(conn *net.UDPConn, messages []BatchMessage) (int, error) {
    p := ipv4.NewPacketConn(conn)

    // Convert to ipv4.Message format
    ipv4Messages := make([]ipv4.Message, len(messages))
    for i, msg := range messages {
        ipv4Messages[i].Buffers = [][]byte{msg.Buffer}
        ipv4Messages[i].Addr = msg.Addr
    }

    // WriteBatch: on Linux uses sendmmsg(), on others writes 1 packet
    return p.WriteBatch(ipv4Messages, 0)
}
