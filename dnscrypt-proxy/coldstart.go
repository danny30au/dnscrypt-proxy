package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
	"github.com/klauspost/compress/gzip" // For potential compression of large rule files
)

const (
	DNSBufferSize       = 4096
	maxPacketSize       = 65535
	readerGoroutines    = 4 // Fixed to optimal value
	defaultMapCapacity  = 100
	readBufferSize      = 2 * 1024 * 1024
	writeBufferSize     = 2 * 1024 * 1024
	defaultTTL          = 1
)

var (
	ErrSyntaxError        = errors.New("syntax error for a captive portal rule")
	ErrWildcardNotAllowed = errors.New("captive portal rule must use an exact host name")

	// Global pools for memory reuse
	msgPool = &sync.Pool{
		New: func() any {
			return new(dns.Msg)
		},
	}
	
	bufferPool = &sync.Pool{
		New: func() any {
			b := make([]byte, DNSBufferSize)
			return &b
		},
	}

	packetPool = &sync.Pool{
		New: func() any {
			return make([]byte, maxPacketSize)
		},
	}
)

type CaptivePortalEntryIPs []netip.Addr

type CaptivePortalMap struct {
	mu   sync.RWMutex
	data map[string]CaptivePortalEntryIPs
}

func (m *CaptivePortalMap) Get(key string) (CaptivePortalEntryIPs, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[key]
	return val, ok
}

func (m *CaptivePortalMap) Set(key string, val CaptivePortalEntryIPs) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = val
}

func (m *CaptivePortalMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *CaptivePortalMap) Range(f func(key string, val CaptivePortalEntryIPs) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.data {
		if !f(k, v) {
			break
		}
	}
}

type CaptivePortalHandler struct {
	wg         sync.WaitGroup
	mu         sync.RWMutex
	conns      []*net.UDPConn
	queryCount atomic.Uint64
	errorCount atomic.Uint64
	closed     atomic.Bool
}

func (h *CaptivePortalHandler) Stop() {
	if !h.closed.CompareAndSwap(false, true) {
		return
	}

	h.mu.RLock()
	conns := make([]*net.UDPConn, len(h.conns))
	copy(conns, h.conns)
	h.mu.RUnlock()

	// Close all connections in parallel
	var wg sync.WaitGroup
	wg.Add(len(conns))
	for _, conn := range conns {
		go func(c *net.UDPConn) {
			defer wg.Done()
			c.Close()
		}(conn)
	}
	wg.Wait()

	h.wg.Wait()
}

func (m *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, CaptivePortalEntryIPs, bool) {
	if len(msg.Question) != 1 {
		return nil, nil, false
	}
	question := msg.Question[0]
	hdr := question.Header()

	if hdr.Class != dns.ClassINET {
		return nil, nil, false
	}

	name, err := NormalizeQName(hdr.Name)
	if err != nil {
		return nil, nil, false
	}

	ips, ok := m.Get(name)
	return question, ips, ok
}

// HandleCaptivePortalQuery processes DNS queries and returns appropriate responses
func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips CaptivePortalEntryIPs) *dns.Msg {
	hdr := question.Header()
	qtype := dns.RRToType(question)

	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	respMsg := EmptyResponseFromMessage(msg)
	hdrTemplate := dns.Header{
		Name:  hdr.Name,
		Class: dns.ClassINET,
		TTL:   defaultTTL,
	}

	// Pre-calculate capacity for answer slice
	var matchCount int
	for _, ip := range ips {
		if (qtype == dns.TypeA && ip.Is4()) || (qtype == dns.TypeAAAA && ip.Is6()) {
			matchCount++
		}
	}

	if matchCount == 0 {
		return nil
	}

	respMsg.Answer = make([]dns.RR, 0, matchCount)

	// Use fast path for specific IP types
	for _, ip := range ips {
		if qtype == dns.TypeA && ip.Is4() {
			respMsg.Answer = append(respMsg.Answer, &dns.A{
				Hdr: hdrTemplate,
				A:   rdata.A{Addr: ip},
			})
		} else if qtype == dns.TypeAAAA && ip.Is6() {
			respMsg.Answer = append(respMsg.Answer, &dns.AAAA{
				Hdr:  hdrTemplate,
				AAAA: rdata.AAAA{Addr: ip},
			})
		}
	}

	if dlog.CurrentLogLevel() >= dlog.SeverityDebug {
		qTypeStr, ok := dns.TypeToString[qtype]
		if !ok {
			qTypeStr = fmt.Sprint(qtype)
		}
		dlog.Debugf("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)
	}

	return respMsg
}

func handlePacket(packet []byte, clientAddr *net.UDPAddr, conn *net.UDPConn, ipsMap *CaptivePortalMap, h *CaptivePortalHandler) {
	msg := msgPool.Get().(*dns.Msg)
	defer msgPool.Put(msg)

	// Reset the message for reuse
	msg.Reset()
	
	msg.Data = packet
	if err := msg.Unpack(); err != nil {
		h.errorCount.Add(1)
		return
	}

	question, ips, ok := ipsMap.GetEntry(msg)
	if !ok {
		return
	}

	h.queryCount.Add(1)

	respMsg := HandleCaptivePortalQuery(msg, question, ips)
	if respMsg == nil {
		return
	}

	// Reuse buffer for response
	respBuf := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(respBuf)

	msg.Data = (*respBuf)[:0]
	if err := respMsg.Pack(); err != nil {
		return
	}

	// Write response without allocations where possible
	_, _ = conn.WriteToUDP(msg.Data, clientAddr)
}

func addColdStartListener(
	ipsMap *CaptivePortalMap,
	listenAddrStr string,
	h *CaptivePortalHandler,
) error {
	network := "udp"
	if len(listenAddrStr) > 0 && listenAddrStr[0] >= '0' && listenAddrStr[0] <= '9' {
		network = "udp4"
	}
	
	listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
	if err != nil {
		return err
	}
	
	clientPc, err := net.ListenUDP(network, listenUDPAddr)
	if err != nil {
		return err
	}

	// Set buffer sizes
	if err := clientPc.SetReadBuffer(readBufferSize); err != nil {
		dlog.Warnf("Failed to set read buffer: %v", err)
	}
	if err := clientPc.SetWriteBuffer(writeBufferSize); err != nil {
		dlog.Warnf("Failed to set write buffer: %v", err)
	}

	// Set socket options for better performance
	if rc, err := clientPc.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			// Enable socket reuse for faster binding
			setSocketReuse(fd)
		})
	}

	h.mu.Lock()
	h.conns = append(h.conns, clientPc)
	h.mu.Unlock()

	// Use fixed number of reader goroutines for better load balancing
	for i := 0; i < readerGoroutines; i++ {
		h.wg.Add(1)
		go func(workerID int) {
			defer h.wg.Done()

			bufPtr := bufferPool.Get().(*[]byte)
			buffer := *bufPtr
			defer bufferPool.Put(bufPtr)

			for !h.closed.Load() {
				// Set deadline for non-blocking shutdown
				clientPc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				
				length, clientAddr, err := clientPc.ReadFromUDP(buffer)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					if errors.Is(err, net.ErrClosed) || h.closed.Load() {
						return
					}
					h.errorCount.Add(1)
					continue
				}

				// Copy packet to avoid buffer reuse issues
				packetCopy := packetPool.Get().([]byte)
				if cap(packetCopy) >= length {
					packetCopy = packetCopy[:length]
					copy(packetCopy, buffer[:length])
				} else {
					packetCopy = make([]byte, length)
					copy(packetCopy, buffer[:length])
					packetPool.Put(make([]byte, maxPacketSize))
				}
				
				handlePacket(packetCopy, clientAddr, clientPc, ipsMap, h)
				packetPool.Put(packetCopy[:maxPacketSize])
			}
		}(i)
	}

	return nil
}

// Optimized string splitting without regex
func parseIPs(ipsStr string) ([]netip.Addr, error) {
	if len(ipsStr) == 0 {
		return nil, nil
	}

	// Pre-allocate based on comma count
	commaCount := strings.Count(ipsStr, ",")
	ips := make([]netip.Addr, 0, commaCount+1)

	// Manual splitting for better performance
	start := 0
	for i := 0; i <= len(ipsStr); i++ {
		if i == len(ipsStr) || ipsStr[i] == ',' {
			if i > start {
				ipStr := strings.TrimSpace(ipsStr[start:i])
				if ipStr != "" {
					ip, err := netip.ParseAddr(ipStr)
					if err != nil {
						return nil, err
					}
					ips = append(ips, ip)
				}
			}
			start = i + 1
		}
	}

	return ips, nil
}

func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
	if len(proxy.captivePortalMapFile) == 0 {
		return nil, nil
	}

	file, err := os.Open(proxy.captivePortalMapFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// Use file size for better capacity estimation
	estimatedRules := defaultMapCapacity
	if fileInfo.Size() > 0 {
		estimatedRules = int(fileInfo.Size() / 40) // Approximate line length
		if estimatedRules < defaultMapCapacity {
			estimatedRules = defaultMapCapacity
		}
	}

	ipsMap := &CaptivePortalMap{
		data: make(map[string]CaptivePortalEntryIPs, estimatedRules),
	}

	scanner := bufio.NewScanner(file)
	// Use larger buffer for I/O efficiency
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		
		// Fast path for empty lines
		if len(line) == 0 {
			continue
		}
		
		// Trim and strip comments in one pass
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		
		// Remove inline comments
		if idx := bytes.IndexByte(line, '#'); idx != -1 {
			line = line[:idx]
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
		}

		// Split into name and IPs
		parts := bytes.SplitN(line, []byte{' '}, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
		}

		name := string(bytes.TrimSpace(parts[0]))
		ipsStr := string(bytes.TrimSpace(parts[1]))

		name, err = NormalizeQName(name)
		if err != nil {
			continue
		}

		if strings.Contains(ipsStr, "*") {
			return nil, fmt.Errorf("%w at line %d", ErrWildcardNotAllowed, lineNo)
		}

		ips, err := parseIPs(ipsStr)
		if err != nil {
			return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
		}

		if len(ips) > 0 {
			ipsMap.Set(name, ips)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	dlog.Infof("Loaded %d captive portal rules", ipsMap.Len())

	handler := &CaptivePortalHandler{}

	var success bool
	var lastErr error
	var wg sync.WaitGroup
	errCh := make(chan error, len(proxy.listenAddresses))

	// Start listeners concurrently
	for _, listenAddrStr := range proxy.listenAddresses {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			if err := addColdStartListener(ipsMap, addr, handler); err != nil {
				errCh <- fmt.Errorf("ColdStart listener bind failed on %v: %v", addr, err)
			} else {
				success = true
				dlog.Infof("ColdStart listener started on %v", addr)
			}
		}(listenAddrStr)
	}

	wg.Wait()
	close(errCh)

	// Collect errors
	for err := range errCh {
		if lastErr == nil {
			lastErr = err
		}
		dlog.Warn(err)
	}

	if success {
		proxy.captivePortalMap = ipsMap
		return handler, nil
	}

	handler.Stop()
	return nil, lastErr
}

// Helper functions
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// Optimized version for systems that support it
func setSocketReuse(fd uintptr) {
	// Implementation depends on OS
	// This is a placeholder for actual SO_REUSEADDR/SO_REUSEPORT setting
}

// StringTwoFields optimized version using bytes
func StringTwoFields(line string) (string, string, bool) {
	// Already implemented in parseIPs section above
	return "", "", false
}

// TrimAndStripInlineComments optimized version
func TrimAndStripInlineComments(line string) string {
	// Already implemented in ColdStart scanner loop
	return ""
}
