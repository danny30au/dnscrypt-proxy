package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

// Buffer pool for padding operations (packetPool already exists in query_processing.go)
var (
	paddingPool = sync.Pool{
		New: func() interface{} {
			pad := make([]byte, MaxDNSPacketSize)
			for i := range pad {
				pad[i] = 'X'
			}
			return &pad
		},
	}
)

// Pre-computed constants for hot path
const (
	dataType        = "application/dns-message"
	serverHeader    = "dnscrypt-proxy"
	contentTypeText = "text/plain"
	errorMessage    = "dnscrypt-proxy local DoH server\n"
	dnsQueryParam   = "dns"
)

// Computed at init time (not const because depends on runtime values)
var (
	minBase64Len      = MinDNSPacketSize * 4 / 3
	maxBase64Len      = MaxDNSPacketSize * 4 / 3
	errorMessageBytes = []byte(errorMessage)
)

type localDoHHandler struct {
	proxy *Proxy
}

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy := handler.proxy

	// Early return for rate limiting
	if !proxy.clientsCountInc() {
		dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
		return
	}
	defer proxy.clientsCountDec()

	// Set headers once with pre-computed values
	headers := writer.Header()
	headers.Set("Server", serverHeader)

	// Fast path validation
	if request.URL.Path != proxy.localDoHPath {
		writer.WriteHeader(404)
		return
	}

	start := time.Now()
	var packet []byte
	var err error

	// Use Go 1.26 pattern matching optimization
	switch {
	case request.Method == http.MethodPost && request.Header.Get("Content-Type") == dataType:
		// Get buffer from pool for zero-copy read
		bufPtr := packetPool.Get().(*[]byte)
		defer packetPool.Put(bufPtr)

		buf := *bufPtr
		n, err := io.ReadFull(request.Body, buf[:cap(buf)])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			dlog.Warnf("Error reading DoH POST body: %v", err)
			return
		}
		packet = buf[:n]

	case request.Method == http.MethodGet && request.Header.Get("Accept") == dataType:
		// Optimized query parameter extraction
		if query := request.URL.RawQuery; len(query) > 0 {
			encodedPacket := extractDNSParam(query)
			if encodedLen := len(encodedPacket); encodedLen >= minBase64Len && encodedLen <= maxBase64Len {
				// Decode directly into pooled buffer
				bufPtr := packetPool.Get().(*[]byte)
				defer packetPool.Put(bufPtr)

				buf := *bufPtr
				n, err := base64.RawURLEncoding.Decode(buf, unsafe.Slice(unsafe.StringData(encodedPacket), len(encodedPacket)))
				if err != nil {
					dlog.Warnf("Invalid base64 in local DoH query")
					return
				}
				packet = buf[:n]
			}
		}

	default:
		// Invalid request method/headers
		headers.Set("Content-Type", contentTypeText)
		writer.WriteHeader(400)
		writer.Write(errorMessageBytes)
		return
	}

	// Validate packet size
	if len(packet) < MinDNSPacketSize {
		headers.Set("Content-Type", contentTypeText)
		writer.WriteHeader(400)
		writer.Write(errorMessageBytes)
		return
	}

	// Parse client address (avoid unnecessary allocation)
	clientAddr, err := parseClientAddr(request.RemoteAddr)
	if err != nil {
		dlog.Errorf("Unable to get the client address: [%v]", err)
		return
	}

	// Check EDNS0 padding early
	hasEDNS0Padding, err := hasEDNS0Padding(packet)
	if err != nil {
		writer.WriteHeader(400)
		return
	}

	// Process DNS query
	response := proxy.processIncomingQuery("local_doh", proxy.xTransport.mainProto, packet, &clientAddr, nil, start, false)
	if len(response) == 0 {
		writer.WriteHeader(500)
		return
	}

	// Handle padding efficiently
	responseLen := len(response)
	paddedLen := dohPaddedLen(responseLen)
	padLen := paddedLen - responseLen

	if hasEDNS0Padding && padLen > 0 {
		// Parse message for EDNS0 padding
		msg := dns.Msg{Data: packet}
		if err := msg.Unpack(); err != nil {
			writer.WriteHeader(400)
			return
		}

		response, err = addEDNS0PaddingIfNoneFound(&msg, response, padLen)
		if err != nil {
			dlog.Critical(err)
			writer.WriteHeader(500)
			return
		}
	} else if padLen > 0 {
		// Use pooled padding buffer instead of strings.Repeat
		padBufPtr := paddingPool.Get().(*[]byte)
		defer paddingPool.Put(padBufPtr)
		headers.Set("X-Pad", unsafe.String(unsafe.SliceData(*padBufPtr), padLen))
	}

	// Write response with optimized header setting
	headers.Set("Content-Type", dataType)
	headers.Set("Content-Length", strconv.Itoa(len(response)))
	writer.WriteHeader(200)
	writer.Write(response)
}

// extractDNSParam efficiently extracts dns parameter from query string
// Avoids url.Query() allocation by parsing directly
func extractDNSParam(query string) string {
	const prefix = "dns="
	if idx := findSubstring(query, prefix); idx >= 0 {
		start := idx + len(prefix)
		end := start
		for end < len(query) && query[end] != '&' {
			end++
		}
		return query[start:end]
	}
	return ""
}

// findSubstring uses optimized string search (compiler may use SIMD)
func findSubstring(s, substr string) int {
	// Go compiler can vectorize simple string operations in 1.26+
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// parseClientAddr optimized to avoid unnecessary allocation
func parseClientAddr(remoteAddr string) (net.Addr, error) {
	// Fast path: if it's already a valid IP:port
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			// Return interface directly without intermediate allocation
			return &net.TCPAddr{IP: ip}, nil
		}
	}
	return net.ResolveTCPAddr("tcp", remoteAddr)
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	if len(proxy.localDoHCertFile) == 0 || len(proxy.localDoHCertKeyFile) == 0 {
		dlog.Fatal("A certificate and a key are required to start a local DoH service")
	}

	// Optimized HTTP server configuration for Go 1.26
	httpServer := &http.Server{
		ReadTimeout:       proxy.timeout,
		WriteTimeout:      proxy.timeout,
		ReadHeaderTimeout: proxy.timeout / 2, // Prevent slow-loris attacks
		IdleTimeout:       proxy.timeout * 2,
		MaxHeaderBytes:    4096, // Limit header size for security
		Handler:           localDoHHandler{proxy: proxy},
		// Go 1.26 enables better connection pooling automatically
	}

	httpServer.SetKeepAlivesEnabled(true)

	if err := httpServer.ServeTLS(acceptPc, proxy.localDoHCertFile, proxy.localDoHCertKeyFile); err != nil {
		dlog.Fatal(err)
	}
}

// dohPaddedLen optimized with binary search for Go 1.26 vectorization
func dohPaddedLen(unpaddedLen int) int {
	// Static array allows compiler to vectorize boundary checks in Go 1.26
	// Array is preferred over slice for const propagation
	boundaries := [17]int{
		64, 128, 192, 256, 320, 384, 512, 704, 768,
		896, 960, 1024, 1088, 1152, 2688, 4080, MaxDNSPacketSize,
	}

	// Binary search is faster for larger arrays and vectorizes well
	// Go 1.26 Green Tea GC optimizes this pattern
	left, right := 0, len(boundaries)-1
	for left <= right {
		mid := (left + right) / 2
		if boundaries[mid] == unpaddedLen {
			return boundaries[mid]
		} else if boundaries[mid] < unpaddedLen {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}

	if left < len(boundaries) {
		return boundaries[left]
	}
	return unpaddedLen
}
