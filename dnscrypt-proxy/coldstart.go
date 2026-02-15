package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
)

// CaptivePortalEntryIPs is the list of IPs returned for captive portal detection.
// Keeping net.IP (instead of netip.Addr) preserves compatibility with existing parsing.
type CaptivePortalEntryIPs []net.IP

// CaptivePortalMap maps normalized QNAMEs to captive portal response IPs.
type CaptivePortalMap map[string]CaptivePortalEntryIPs

// CaptivePortalHandler owns the cold-start captive portal listeners.
// Stop() is safe to call multiple times.
type CaptivePortalHandler struct {
	wg        sync.WaitGroup
	stopOnce  sync.Once
	cancel    context.CancelFunc
	cancelCtx context.Context
}

// newCaptivePortalHandler constructs a handler with an internal cancelable context.
func newCaptivePortalHandler() *CaptivePortalHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &CaptivePortalHandler{cancelCtx: ctx, cancel: cancel}
}

// Stop stops all captive portal listeners and waits for goroutines to exit.
func (h *CaptivePortalHandler) Stop() {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
	})
	h.wg.Wait()
}

// GetEntry returns the question (as dns.RR) and the configured IPs for that name.
// Note: returning a pointer to a local variable preserves the original signature.
func (m *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, *CaptivePortalEntryIPs) {
	if m == nil || msg == nil {
		return nil, nil
	}
	if len(msg.Question) != 1 {
		return nil, nil
	}

	question := msg.Question[0]
	hdr := question.Header()
	name, err := NormalizeQName(hdr.Name)
	if err != nil {
		return nil, nil
	}
	if hdr.Class != dns.ClassINET {
		return nil, nil
	}
	ips, ok := (*m)[name]
	if !ok {
		return nil, nil
	}
	return question, &ips
}

// HandleCaptivePortalQuery synthesizes an A/AAAA answer from a captive portal mapping.
func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips *CaptivePortalEntryIPs) *dns.Msg {
	if msg == nil || question == nil || ips == nil {
		return nil
	}

	respMsg := EmptyResponseFromMessage(msg)
	const ttl = uint32(1)

	hdr := question.Header()
	qtype := dns.RRToType(question)

	switch qtype {
	case dns.TypeA:
		for _, xip := range *ips {
			ip4 := xip.To4()
			if ip4 == nil {
				continue
			}
			var b4 [4]byte
			copy(b4[:], ip4)
			rr := &dns.A{Hdr: dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}}
			rr.A = rdata.A{Addr: netip.AddrFrom4(b4)}
			respMsg.Answer = append(respMsg.Answer, rr)
		}

	case dns.TypeAAAA:
		for _, xip := range *ips {
			if xip.To4() != nil {
				continue
			}
			ip16 := xip.To16()
			if ip16 == nil {
				continue
			}
			var b16 [16]byte
			copy(b16[:], ip16)
			rr := &dns.AAAA{Hdr: dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}}
			rr.AAAA = rdata.AAAA{Addr: netip.AddrFrom16(b16)}
			respMsg.Answer = append(respMsg.Answer, rr)
		}
	}

	qTypeStr := dns.TypeToString[qtype]
	if qTypeStr == "" {
		qTypeStr = fmt.Sprint(qtype)
	}
	dlog.Infof("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)

	return respMsg
}

// readDeadline is the maximum time we block while waiting for packets.
const readDeadline = 1 * time.Second

func handleColdStartConn(ctx context.Context, clientPc *net.UDPConn, ipsMap *CaptivePortalMap) {
	defer clientPc.Close()

	buffer := make([]byte, MaxDNSPacketSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = clientPc.SetReadDeadline(time.Now().Add(readDeadline))
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			// If we timed out, just re-check cancellation and continue.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			dlog.Warn(err)
			return
		}
		if length < MinDNSPacketSize {
			continue
		}

		packet := buffer[:length]
		msg := &dns.Msg{Data: packet}
		if err := msg.Unpack(); err != nil {
			continue
		}

		question, ips := ipsMap.GetEntry(msg)
		if ips == nil {
			continue
		}

		respMsg := HandleCaptivePortalQuery(msg, question, ips)
		if respMsg == nil {
			continue
		}
		if err := respMsg.Pack(); err != nil {
			continue
		}
		if _, err := clientPc.WriteTo(respMsg.Data, clientAddr); err != nil {
			// Non-fatal: keep listening.
			dlog.Debugf("Cold start captive portal write failed: %v", err)
		}
	}
}

func udpNetworkForListenAddr(listenAddrStr string) string {
	// Preserve original intent: use udp4 for obvious IPv4 literals, but also handle
	// bracketed IPv6 or hostnames robustly.
	if len(listenAddrStr) == 0 {
		return "udp"
	}

	host, _, err := net.SplitHostPort(listenAddrStr)
	if err != nil {
		// Fallback: original code guessed using isDigit(listenAddrStr[0]).
		if isDigit(listenAddrStr[0]) {
			return "udp4"
		}
		return "udp"
	}

	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return "udp"
}

func addColdStartListener(ipsMap *CaptivePortalMap, listenAddrStr string, h *CaptivePortalHandler) error {
	if h == nil || ipsMap == nil {
		return errors.New("handler/map is nil")
	}
	if len(listenAddrStr) == 0 {
		return nil
	}

	network := udpNetworkForListenAddr(listenAddrStr)
	listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
	if err != nil {
		return err
	}

	clientPc, err := net.ListenUDP(network, listenUDPAddr)
	if err != nil {
		return err
	}

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		handleColdStartConn(h.cancelCtx, clientPc, ipsMap)
	}()

	return nil
}

func parseCaptivePortalMap(lines string) (CaptivePortalMap, error) {
	ipsMap := make(CaptivePortalMap)
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		name, ipsStr, ok := StringTwoFields(line)
		if !ok {
			return nil, fmt.Errorf("syntax error for a captive portal rule at line %d", 1+lineNo)
		}

		// Enforce exact hostname (wildcards belong in the name, not the IP list).
		if strings.Contains(name, "*") {
			return nil, fmt.Errorf("a captive portal rule must use an exact host name at line %d", 1+lineNo)
		}

		normName, err := NormalizeQName(name)
		if err != nil {
			// Preserve original behavior: skip invalid names.
			continue
		}

		var ips []net.IP
		for ipToken := range strings.SplitSeq(ipsStr, ",") {
			ipStr := strings.TrimSpace(ipToken)
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q for captive portal rule at line %d", ipStr, 1+lineNo)
			}
			ips = append(ips, ip)
		}
		ipsMap[normName] = ips
	}
	return ipsMap, nil
}

// ColdStart sets up lightweight UDP listeners that answer captive portal detection queries.
func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
	if proxy == nil {
		return nil, errors.New("proxy is nil")
	}
	if len(proxy.captivePortalMapFile) == 0 {
		return nil, nil
	}

	lines, err := ReadTextFile(proxy.captivePortalMapFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}

	ipsMap, err := parseCaptivePortalMap(lines)
	if err != nil {
		return nil, err
	}

	h := newCaptivePortalHandler()
	listenAddrStrs := proxy.listenAddresses

	var firstErr error
	anyOK := false
	for _, listenAddrStr := range listenAddrStrs {
		err := addColdStartListener(&ipsMap, listenAddrStr, h)
		if err == nil {
			anyOK = true
			continue
		}
		// Preserve the original behavior: keep trying other listeners.
		if firstErr == nil {
			firstErr = err
		}
	}

	proxy.captivePortalMap = &ipsMap
	if anyOK {
		return h, nil
	}
	// If none succeeded, return the first error.
	if firstErr == nil {
		firstErr = errors.New("no captive portal listeners could be started")
	}
	// Nothing started; ensure goroutines stop (none should exist, but keep it safe).
	h.Stop()
	return nil, firstErr
}
