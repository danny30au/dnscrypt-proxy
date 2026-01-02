package main

import (
    "bufio"
    "bytes"
    crypto_rand "crypto/rand"
    "crypto/sha512"
    "errors"
    "io"
    "sync"

    "github.com/jedisct1/dlog"
    "github.com/jedisct1/xsecretbox"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/secretbox"
)

const (
    NonceSize        = xsecretbox.NonceSize
    HalfNonceSize    = xsecretbox.NonceSize / 2
    TagSize          = xsecretbox.TagSize
    PublicKeySize    = 32
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
    // Size covers MaxDNSUDPPacketSize to ensure we can always compare.
    zeroPage [4096]byte

    // Pool for padding buffers (plaintext)
    // Storing *[]byte avoids interface conversion overhead on slice headers
    bufferPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, 0, 2048)
            return &b
        },
    }

    // Pool for buffered random readers
    randReaderPool = sync.Pool{
        New: func() interface{} {
            // OPTIMIZATION: 4KB buffer matches typical OS page size, reducing syscalls
            return bufio.NewReaderSize(crypto_rand.Reader, 4096)
        },
    }
)

// padTo copies packet to a new buffer of size minSize with ISO/IEC 7816-4 padding.
func padTo(packet []byte, minSize int) []byte {
    out := make([]byte, minSize)
    copy(out, packet)
    out[len(packet)] = 0x80
    // Remaining bytes are zero-initialized by make()
    return out
}

func unpad(packet []byte) ([]byte, error) {
    // Optimization: Assembly-optimized search
    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    // Optimization: Verify trailing zeros using SIMD-optimized memcmp (bytes.Equal)
    // instead of a slow loop.
    tailLen := len(packet) - idx - 1
    if tailLen > 0 {
        if tailLen > len(zeroPage) {
            // Fallback for theoretically huge packets (unlikely in DNS)
            for i := idx + 1; i < len(packet); i++ {
                if packet[i] != 0 {
                    return nil, ErrInvalidPadBytes
                }
            }
        } else if !bytes.Equal(packet[idx+1:], zeroPage[:tailLen]) {
            return nil, ErrInvalidPadBytes
        }
    }
    return packet[:idx], nil
}

// readRandom reads n bytes from a pooled buffered reader
func readRandom(p []byte) error {
    reader := randReaderPool.Get().(*bufio.Reader)
    _, err := io.ReadFull(reader, p)
    randReaderPool.Put(reader)
    return err
}

func ComputeSharedKey(
    cryptoConstruction CryptoConstruction,
    secretKey *[32]byte,
    serverPk *[32]byte,
    providerName *string,
) (sharedKey [32]byte) {
    if cryptoConstruction == XChacha20Poly1305 {
        var err error
        sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
        if err != nil {
            logMsg := "Weak XChaCha20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
        }
    } else {
        box.Precompute(&sharedKey, serverPk, secretKey)

        // Manual constant-time check for zero key
        var c byte
        for _, b := range sharedKey {
            c |= b
        }

        if c == 0 {
            logMsg := "Weak XSalsa20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            // Fallback to random to prevent catastrophe (though caller likely panics/exits)
            if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
                dlog.Fatal(err)
            }
        }
    }
    return sharedKey
}

// Encrypt encrypts a packet into dst.
// IMPROVEMENT: Returns values (arrays) instead of pointers to avoid heap escapes.
// IMPROVEMENT: Accepts dst to allow buffer reuse.
func (proxy *Proxy) Encrypt(
    dst []byte,
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey [32]byte, encrypted []byte, clientNonce [HalfNonceSize]byte, err error) {
    // 1. Zero-alloc, Batched Randomness
    var nonce [NonceSize]byte
    if err := readRandom(nonce[:HalfNonceSize]); err != nil {
        return sharedKey, nil, clientNonce, err
    }

    copy(clientNonce[:], nonce[:HalfNonceSize])
    var publicKey *[32]byte // Pointer to stack or struct field, no escape if handled carefully

    if proxy.ephemeralKeys {
        var buf [HalfNonceSize + 32]byte
        copy(buf[:], nonce[:HalfNonceSize])
        copy(buf[HalfNonceSize:], proxy.proxySecretKey[:])
        ephSk := sha512.Sum512_256(buf[:])
        var xPublicKey [32]byte
        curve25519.ScalarBaseMult(&xPublicKey, &ephSk)
        publicKey = &xPublicKey
        // Value return prevents escape
        sharedKey = ComputeSharedKey(serverInfo.CryptoConstruction, &ephSk, &serverInfo.ServerPk, nil)
    } else {
        sharedKey = serverInfo.SharedKey
        publicKey = &proxy.proxyPublicKey
    }

    minQuestionSize := QueryOverhead + len(packet)
    if proto == "udp" {
        minQuestionSize = max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
    } else {
        var xpad [1]byte
        if err := readRandom(xpad[:]); err != nil {
            return sharedKey, nil, clientNonce, err
        }
        minQuestionSize += int(xpad[0])
    }

    // Upgrade: Use Go 1.21 max/min builtins
    paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
    if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
        paddedLength = MaxDNSUDPSafePacketSize
    } else if serverInfo.Relay != nil && proto == "tcp" {
        paddedLength = MaxDNSPacketSize
    }

    if QueryOverhead+len(packet)+1 > paddedLength {
        return sharedKey, nil, clientNonce, ErrQuestionTooLarge
    }

    // Prepare headers in dst
    totalSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + (paddedLength - QueryOverhead) + TagSize
    
    // Ensure capacity
    if cap(dst) < len(dst)+totalSize {
        // Grow dst efficiently if needed (or let append handle it, but pre-grow is better)
        newDst := make([]byte, len(dst), len(dst)+totalSize)
        copy(newDst, dst)
        dst = newDst
    }

    // IMPROVEMENT: Use copy instead of append for headers to avoid intermediate slice overhead
    startLen := len(dst)
    // Extend length to accommodate headers
    headerLen := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize
    dst = dst[:startLen+headerLen]
    
    n := copy(dst[startLen:], serverInfo.MagicQuery[:])
    n += copy(dst[startLen+n:], publicKey[:])
    copy(dst[startLen+n:], nonce[:HalfNonceSize])

    plaintextLen := paddedLength - QueryOverhead
    ptr := bufferPool.Get().(*[]byte)
    paddedBuf := *ptr

    // Ensure capacity without discarding pooled memory if possible
    var tailNeedsClearing bool
    if cap(paddedBuf) < plaintextLen {
        paddedBuf = make([]byte, plaintextLen)
        // IMPROVEMENT: New buffer is already zeroed
        tailNeedsClearing = false
    } else {
        paddedBuf = paddedBuf[:plaintextLen]
        tailNeedsClearing = true
    }

    copy(paddedBuf, packet)
    paddedBuf[len(packet)] = 0x80

    // Upgrade: Use clear() for efficient intrinsic zeroing (Go 1.21+)
    // IMPROVEMENT: Only clear if the buffer was dirty (reused)
    if tailNeedsClearing {
        tail := paddedBuf[len(packet)+1:]
        clear(tail)
    }

    if serverInfo.CryptoConstruction == XChacha20Poly1305 {
        encrypted = xsecretbox.Seal(dst, nonce[:], paddedBuf, sharedKey[:])
    } else {
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], nonce[:])
        encrypted = secretbox.Seal(dst, paddedBuf, &xsalsaNonce, &sharedKey)
    }

    // Update the pool pointer to the potentially larger buffer
    *ptr = paddedBuf
    // IMPROVEMENT: Pool Hygiene - Don't recycle massive buffers
    if cap(paddedBuf) <= MaxDNSPacketSize {
        bufferPool.Put(ptr)
    }

    return sharedKey, encrypted, clientNonce, nil
}

// Decrypt decrypts a packet into dst.
// IMPROVEMENT: Accepts dst buffer to avoid allocating a return slice.
func (proxy *Proxy) Decrypt(
    dst []byte,
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encrypted []byte,
    nonce []byte,
) ([]byte, error) {
    serverMagicLen := len(ServerMagic)
    responseHeaderLen := serverMagicLen + NonceSize

    // Pre-check constraints
    if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return nil, ErrInvalidMsgSize
    }

    // BCE Hint: Proves to compiler that encrypted is large enough for all header reads
    _ = encrypted[responseHeaderLen+TagSize-1]

    if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
        return nil, ErrInvalidPrefix
    }

    serverNonce := encrypted[serverMagicLen:responseHeaderLen]
    if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
        return nil, ErrUnexpectedNonce
    }

    ciphertext := encrypted[responseHeaderLen:]
    
    // We append the decrypted content to dst
    var err error
    var packet []byte
    
    if serverInfo.CryptoConstruction == XChacha20Poly1305 {
        packet, err = xsecretbox.Open(dst, serverNonce, ciphertext, sharedKey[:])
    } else {
        var xsalsaServerNonce [24]byte
        copy(xsalsaServerNonce[:], serverNonce)
        var ok bool
        packet, ok = secretbox.Open(dst, ciphertext, &xsalsaServerNonce, sharedKey)
        if !ok {
            err = ErrIncorrectTag
        }
    }

    if err != nil {
        return nil, err
    }

    // unpad modifies the slice length in place (slicing down), no allocation
    packet, err = unpad(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        return nil, ErrInvalidPadding
    }

    return packet, nil
}
