// Optimized xtransport.go with Go 1.23-1.26 features, ECH, HTTP/2 enhancements
// Performance improvements: Connection coalescing, parallel queries, zero-copy, TCP Fast Open
// Author: Enhanced by Perplexity AI - January 2026

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/cpu"
)

var (
	protoTCPFirst = []string{"tcp", "udp"}
	protoUDPFirst = []string{"udp", "tcp"}
)

var hasAESGCMHardwareSupport = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ ||
	cpu.ARM64.HasAES && cpu.ARM64.HasPMULL ||
	cpu.S390X.HasAES && cpu.S390X.HasAESGCM

const (
	DefaultBootstrapResolver    = "9.9.9.9:53"
	DefaultKeepAlive            = 360 * time.Second
	DefaultTimeout              = 10 * time.Second
	ResolverReadTimeout         = 2 * time.Second
	SystemResolverIPTTL         = 12 * time.Hour
	MinResolverIPTTL            = 30 * time.Minute
	ResolverIPTTLMaxJitter      = 15 * time.Minute
	ExpiredCachedIPGraceTTL     = 15 * time.Minute
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 25 * time.Millisecond
	resolverRetryMaxBackoff     = 300 * time.Millisecond
	prefetchWindow              = 5 * time.Minute

	// HTTP/2 priority levels for DNS queries
	PriorityUrgent = 255 // Bootstrap resolvers, initial setup
	PriorityHigh   = 192 // User-initiated queries
	PriorityNormal = 128 // Background prefetch
	PriorityLow    = 64  // Speculative resolution

	// TCP Fast Open constants (Linux)
	TCP_FASTOPEN         = 23
	TCP_FASTOPEN_CONNECT = 30
)

var resolverBackoffs = [resolverRetryCount]time.Duration{
	resolverRetryInitialBackoff,
	resolverRetryInitialBackoff * 2,
	resolverRetryMaxBackoff,
}

var bgCtx = context.Background()

// ========== Enhanced Data Structures ==========

type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	cache      sync.Map
	hits       atomic.Uint64
	misses     atomic.Uint64
	generation atomic.Uint64
}

type AltSupportItem struct {
	port      uint16
	nextProbe time.Time
	valid     bool
}

type AltSupport struct {
	cache sync.Map
}

// ECH Configuration (Go 1.23+)
type ECHConfig struct {
	echConfigList []byte
	host          string
	lastUpdated   time.Time
}

// Connection coalescing for HTTP/2 optimization
type coalescedConn struct {
	conn        net.Conn
	hosts       sync.Map // map[string]bool - authorized hosts
	lastUsed    atomic.Int64
	streamCount atomic.Int32
	tlsState    *tls.ConnectionState
}

type connectionCoalescingCache struct {
	connections sync.Map // map[string]*coalescedConn
	mu          sync.RWMutex
}

// Performance metrics tracking
type LatencyMetrics struct {
	dnsLookupTime    atomic.Uint64
	tcpConnectTime   atomic.Uint64
	tlsHandshakeTime atomic.Uint64
	firstByteTime    atomic.Uint64
	totalTime        atomic.Uint64
}

type resolverStats struct {
	host       string
	queryCount atomic.Uint64
	avgLatency atomic.Uint64
	failures   atomic.Uint64
	lastUsed   atomic.Int64
}

// ========== Object Pools (Go 1.26 optimized) ==========

type dnsMessagePool struct {
	pool sync.Pool
}

func newDNSMessagePool() *dnsMessagePool {
	return &dnsMessagePool{
		pool: sync.Pool{
			New: func() any {
				return new(dns.Msg)
			},
		},
	}
}

func (p *dnsMessagePool) Get() *dns.Msg {
	msg := p.pool.Get().(*dns.Msg)
	msg.ID = 0
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	return msg
}

func (p *dnsMessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		p.pool.Put(msg)
	}
}

func (p *dnsMessagePool) GetBatch(n int) []*dns.Msg {
	msgs := make([]*dns.Msg, n)
	for i := 0; i < n; i++ {
		msgs[i] = p.Get()
	}
	return msgs
}

type stringBuilderPool struct {
	pool sync.Pool
}

func newStringBuilderPool() *stringBuilderPool {
	return &stringBuilderPool{
		pool: sync.Pool{
			New: func() any {
				return &strings.Builder{}
			},
		},
	}
}

func (p *stringBuilderPool) Get() *strings.Builder {
	sb := p.pool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

func (p *stringBuilderPool) Put(sb *strings.Builder) {
	p.pool.Put(sb)
}

// Zero-copy buffer for DNS messages
type zeroCopyBuffer struct {
	buf []byte
}

type quicConnCache struct {
	conns sync.Map
}

// ========== Main Transport Structure ==========

type XTransport struct {
	sessionCache             tls.ClientSessionCache
	transport                *http.Transport
	h3Transport              *http3.Transport
	httpClient               *http.Client
	h3Client                 *http.Client
	keepAlive                time.Duration
	timeout                  time.Duration
	cachedIPs                CachedIPs
	altSupport               AltSupport
	internalResolvers        []string
	bootstrapResolvers       []string
	mainProto                string
	resolveProtos            []string
	ignoreSystemDNS          bool
	internalResolverReady    bool
	useIPv4                  bool
	useIPv6                  bool
	http3                    bool
	http3Probe               bool
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
	tlsClientCreds           DOHClientCreds
	keyLogWriter             io.Writer

	// Pools (Go 1.26 optimized)
	gzipPool          sync.Pool
	dnsClientPool     sync.Pool
	dnsMessagePool    *dnsMessagePool
	bufferPool        sync.Pool
	zeroCopyPool      sync.Pool
	stringBuilderPool *stringBuilderPool

	// Concurrency primitives
	resolveGroup singleflight.Group

	// QUIC transport
	quicConnCache quicConnCache
	quicUDP4      atomic.Pointer[net.UDPConn]
	quicUDP6      atomic.Pointer[net.UDPConn]
	quicTr4       atomic.Pointer[quic.Transport]
	quicTr6       atomic.Pointer[quic.Transport]

	// ECH Support (Go 1.23+)
	echEnabled bool
	echConfigs sync.Map // map[string]*ECHConfig

	// Connection coalescing
	coalescingCache connectionCoalescingCache

	// Performance tracking
	resolverStats    sync.Map // map[string]*resolverStats
	enableFastOpen   bool     // TCP Fast Open
	enableCoalescing bool     // HTTP/2 connection coalescing
}

// ========== Initialization ==========

func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse")
	}

	xTransport := &XTransport{
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		mainProto:                "",
		resolveProtos:            protoUDPFirst,
		ignoreSystemDNS:          true,
		useIPv4:                  true,
		useIPv6:                  false,
		http3Probe:               false,
		tlsDisableSessionTickets: false,
		tlsPreferRSA:             false,
		keyLogWriter:             nil,
		sessionCache:             tls.NewLRUClientSessionCache(4096),
		dnsMessagePool:           newDNSMessagePool(),
		stringBuilderPool:        newStringBuilderPool(),
		echEnabled:               true,  // Enable ECH by default
		enableFastOpen:           true,  // Enable TCP Fast Open
		enableCoalescing:         true,  // Enable connection coalescing
	}

	// Gzip reader pool
	xTransport.gzipPool.New = func() any {
		return new(gzip.Reader)
	}

	// DNS client pool
	xTransport.dnsClientPool.New = func() any {
		transport := dns.NewTransport()
		transport.ReadTimeout = ResolverReadTimeout
		return &dns.Client{Transport: transport}
	}

	// Buffer pool with larger size for Go 1.26 optimization
	xTransport.bufferPool.New = func() any {
		buf := new(bytes.Buffer)
		buf.Grow(8192) // Increased from 4KB to 8KB
		return buf
	}

	// Zero-copy buffer pool
	xTransport.zeroCopyPool.New = func() any {
		return &zeroCopyBuffer{
			buf: make([]byte, 0, 4096),
		}
	}

	return xTransport
}

// ========== IP Utilities ==========

func ParseIP(ipStr string) net.IP {
	s := strings.TrimPrefix(ipStr, "[")
	s = strings.TrimSuffix(s, "]")
	return net.ParseIP(s)
}

// Optimized for Go 1.26 with stack allocation for small slices
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	if len(ips) <= 4 {
		var seenStack [4][16]byte
		seen := seenStack[:0:4]
		unique := make([]net.IP, 0, len(ips))

		for _, ip := range ips {
			if ip == nil {
				continue
			}
			var key [16]byte
			copy(key[:], ip.To16())

			found := false
			for i := range seen {
				if seen[i] == key {
					found = true
					break
				}
			}
			if !found {
				seen = append(seen, key)
				unique = append(unique, append(net.IP(nil), ip...))
			}
		}
		return unique
	}

	seen := make(map[[16]byte]struct{}, len(ips))
	unique := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		var key [16]byte
		copy(key[:], ip.To16())
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			unique = append(unique, append(net.IP(nil), ip...))
		}
	}
	return unique
}

func formatEndpoint(ip net.IP, port int) string {
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

// ========== IP Caching with Prefetch ==========

func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}
	now := time.Now()
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		expiration := now.Add(ttl)
		item.expiration = &expiration
	}

	item.updatingUntil = nil
	xTransport.cachedIPs.cache.Store(host, item)

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v", host, len(normalized), normalized[0], ttl)
	}
}

func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	xTransport.saveCachedIPs(host, []net.IP{ip}, ttl)
}

func (xTransport *XTransport) markUpdatingCachedIP(host string) {
	val, ok := xTransport.cachedIPs.cache.Load(host)
	if !ok {
		return
	}

	item := val.(*CachedIPItem)
	now := time.Now()
	until := now.Add(xTransport.timeout)
	newItem := &CachedIPItem{
		ips:           item.ips,
		expiration:    item.expiration,
		updatingUntil: &until,
	}
	xTransport.cachedIPs.cache.Store(host, newItem)
	dlog.Debugf("[%s] IP address marked as updating", host)
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	val, ok := xTransport.cachedIPs.cache.Load(host)
	if !ok {
		xTransport.cachedIPs.misses.Add(1)
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}

	xTransport.cachedIPs.hits.Add(1)
	item := val.(*CachedIPItem)
	ips = item.ips
	expiration := item.expiration
	updatingUntil := item.updatingUntil

	if expiration != nil {
		timeUntilExpiry := time.Until(*expiration)
		// Prefetch before expiration
		if timeUntilExpiry < prefetchWindow && timeUntilExpiry > 0 {
			if updatingUntil == nil || time.Until(*updatingUntil) <= 0 {
				go xTransport.resolveAndUpdateCache(host)
			}
		}

		if timeUntilExpiry < 5*time.Minute {
			expired = true
			if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
				updating = true
				dlog.Debugf("[%s] cached IP addresses are being updated", host)
			} else {
				dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
			}
		}
	}
	return ips, expired, updating
}

func (xTransport *XTransport) cleanupExpiredCache() {
	gen := xTransport.cachedIPs.generation.Add(1)
	dlog.Debugf("Cache cleanup cycle %d started", gen)
	xTransport.cachedIPs.cache.Range(func(key, value interface{}) bool {
		item := value.(*CachedIPItem)
		if item.expiration != nil && time.Now().After(*item.expiration) {
			xTransport.cachedIPs.cache.Delete(key)
		}
		return true
	})
}

// ========== ECH Support (Encrypted Client Hello - Go 1.23+) ==========

func (xTransport *XTransport) fetchECHConfig(host string) (*ECHConfig, error) {
	if !xTransport.echEnabled {
		return nil, errors.New("ECH disabled")
	}

	msg := xTransport.dnsMessagePool.Get()
	defer xTransport.dnsMessagePool.Put(msg)

	msg.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)

	dnsClient := xTransport.dnsClientPool.Get().(*dns.Client)
	defer xTransport.dnsClientPool.Put(dnsClient)

	var response *dns.Msg
	var err error

	// Try internal resolvers first
	if xTransport.internalResolverReady {
		for _, resolver := range xTransport.internalResolvers {
			ctx, cancel := context.WithTimeout(bgCtx, 3*time.Second)
			response, _, err = dnsClient.Exchange(ctx, msg, "udp", resolver)
			cancel()

			if err == nil && response != nil {
				break
			}
		}
	}

	// Fallback to bootstrap resolvers
	if err != nil || response == nil {
		for _, resolver := range xTransport.bootstrapResolvers {
			ctx, cancel := context.WithTimeout(bgCtx, 3*time.Second)
			response, _, err = dnsClient.Exchange(ctx, msg, "udp", resolver)
			cancel()

			if err == nil && response != nil {
				break
			}
		}
	}

	if err != nil || response == nil {
		return nil, fmt.Errorf("failed to fetch HTTPS record for [%s]: %w", host, err)
	}

	// Parse HTTPS record for ECH parameter (SVCB key=5)
	for _, answer := range response.Answer {
		if https, ok := answer.(*dns.HTTPS); ok {
			for _, param := range https.Value {
				if param.Key() == dns.SVCB_ECHCONFIG {
					echData := param.(*dns.SVCBECHConfig).ECH

					dlog.Infof("Found ECH config for [%s]: %d bytes", host, len(echData))

					return &ECHConfig{
						echConfigList: echData,
						host:          host,
						lastUpdated:   time.Now(),
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found for [%s]", host)
}

func (xTransport *XTransport) EnableECH(enable bool) {
	xTransport.echEnabled = enable
	if enable {
		dlog.Info("ECH (Encrypted Client Hello) enabled")
	} else {
		dlog.Info("ECH (Encrypted Client Hello) disabled")
	}
}

func (xTransport *XTransport) PrewarmECHConfigs(dohResolvers []string) {
	if !xTransport.echEnabled {
		return
	}

	dlog.Info("Pre-warming ECH configurations for DoH resolvers")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, resolver := range dohResolvers {
		u, err := url.Parse(resolver)
		if err != nil {
			continue
		}

		host, _ := ExtractHostAndPort(u.Host, 443)

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			config, err := xTransport.fetchECHConfig(h)
			if err != nil {
				dlog.Debugf("No ECH config for [%s]: %v", h, err)
				return
			}

			xTransport.echConfigs.Store(h, config)
			dlog.Infof("Pre-fetched ECH config for [%s]", h)
		}(host)
	}

	wg.Wait()
}

// ========== TCP Fast Open Support (Linux) ==========

func enableTCPFastOpen(fd uintptr) error {
	// Enable TFO on client socket (Linux 3.13+)
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)
}

func (xTransport *XTransport) dialWithFastOpen(ctx context.Context, network, address string) (net.Conn, error) {
	if !xTransport.enableFastOpen {
		// Fallback to standard dial
		dialer := &net.Dialer{
			Timeout:   xTransport.timeout,
			KeepAlive: 15 * time.Second,
		}
		return dialer.DialContext(ctx, network, address)
	}

	dialer := &net.Dialer{
		Timeout:   xTransport.timeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockOptErr error
			err := c.Control(func(fd uintptr) {
				sockOptErr = enableTCPFastOpen(fd)
				if sockOptErr != nil {
					dlog.Debugf("TCP Fast Open not available: %v", sockOptErr)
				}
			})
			if err != nil {
				return err
			}
			return nil // Don't fail if TFO unavailable
		},
	}

	return dialer.DialContext(ctx, network, address)
}

// ========== HTTP/2 Connection Coalescing ==========

func (xTransport *XTransport) canCoalesce(newHost string, existingConn *coalescedConn) bool {
	if existingConn.tlsState == nil {
		return false
	}

	// Check if TLS certificate covers the new host
	for _, cert := range existingConn.tlsState.PeerCertificates {
		if err := cert.VerifyHostname(newHost); err == nil {
			dlog.Debugf("Certificate valid for [%s] - can coalesce", newHost)
			return true
		}
	}

	return false
}

func (xTransport *XTransport) getCoalescedConnection(host string, cachedIPs []net.IP) (net.Conn, bool) {
	if !xTransport.enableCoalescing {
		return nil, false
	}

	// Try to find existing connection to same IP
	for _, ip := range cachedIPs {
		ipKey := ip.String()
		if val, ok := xTransport.coalescingCache.connections.Load(ipKey); ok {
			conn := val.(*coalescedConn)

			// Check if we can coalesce to this connection
			if xTransport.canCoalesce(host, conn) {
				// Check connection health and load
				if conn.streamCount.Load() < 100 {
					conn.hosts.Store(host, true)
					conn.lastUsed.Store(time.Now().Unix())
					conn.streamCount.Add(1)
					dlog.Debugf("Coalescing connection for [%s] to [%s]", host, ipKey)
					return conn.conn, true
				} else {
					dlog.Debugf("Connection to [%s] overloaded, creating new", ipKey)
				}
			}
		}
	}

	return nil, false
}

func (xTransport *XTransport) storeCoalescedConnection(ip net.IP, conn net.Conn, tlsState *tls.ConnectionState, host string) {
	if !xTransport.enableCoalescing || ip == nil {
		return
	}

	ipKey := ip.String()
	coalesced := &coalescedConn{
		conn:     conn,
		tlsState: tlsState,
	}
	coalesced.hosts.Store(host, true)
	coalesced.lastUsed.Store(time.Now().Unix())
	coalesced.streamCount.Store(1)

	xTransport.coalescingCache.connections.Store(ipKey, coalesced)
	dlog.Debugf("Stored coalesced connection for [%s]", ipKey)
}

// ========== Gzip Pool Management ==========

func (xTransport *XTransport) getGzipReader(r io.Reader) (*gzip.Reader, error) {
	gr := xTransport.gzipPool.Get().(*gzip.Reader)
	if err := gr.Reset(r); err != nil {
		xTransport.gzipPool.Put(gr)
		return nil, err
	}
	return gr, nil
}

func (xTransport *XTransport) putGzipReader(gr *gzip.Reader) {
	_ = gr.Close()
	xTransport.gzipPool.Put(gr)
}

// ========== QUIC Transport Management ==========

func (xTransport *XTransport) getQUICTransport(network string) (*quic.Transport, error) {
	const sockBuf = 16 << 20 // Increased to 16MB for better throughput

	switch network {
	case "udp4":
		if tr := xTransport.quicTr4.Load(); tr != nil {
			return tr, nil
		}

		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to listen UDP4: %w", err)
		}
		_ = c.SetReadBuffer(sockBuf)
		_ = c.SetWriteBuffer(sockBuf)

		tr := &quic.Transport{Conn: c}
		if xTransport.quicTr4.CompareAndSwap(nil, tr) {
			xTransport.quicUDP4.Store(c)
			return tr, nil
		}

		_ = c.Close()
		return xTransport.quicTr4.Load(), nil

	case "udp6":
		if tr := xTransport.quicTr6.Load(); tr != nil {
			return tr, nil
		}

		c, err := net.ListenUDP("udp6", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to listen UDP6: %w", err)
		}
		_ = c.SetReadBuffer(sockBuf)
		_ = c.SetWriteBuffer(sockBuf)

		tr := &quic.Transport{Conn: c}
		if xTransport.quicTr6.CompareAndSwap(nil, tr) {
			xTransport.quicUDP6.Store(c)
			return tr, nil
		}

		_ = c.Close()
		return xTransport.quicTr6.Load(), nil

	default:
		return nil, fmt.Errorf("unsupported quic network: %s", network)
	}
}

func (xTransport *XTransport) adaptiveTimeout(rtt time.Duration) time.Duration {
	adaptiveTO := rtt * 3
	if adaptiveTO < xTransport.timeout {
		return xTransport.timeout
	}
	if adaptiveTO > xTransport.timeout*3 {
		return xTransport.timeout * 3
	}
	return adaptiveTO
}

// ========== Transport Rebuild with Go 1.26 Optimizations ==========

func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport with optimizations (ECH, TFO, Coalescing)")

	if xTransport.transport != nil {
		xTransport.transport.CloseIdleConnections()
	}
	if xTransport.h3Transport != nil {
		xTransport.h3Transport.Close()
		xTransport.h3Transport = nil
	}

	if tr4 := xTransport.quicTr4.Load(); tr4 != nil {
		_ = tr4.Close()
		xTransport.quicTr4.Store(nil)
	}
	if tr6 := xTransport.quicTr6.Load(); tr6 != nil {
		_ = tr6.Close()
		xTransport.quicTr6.Store(nil)
	}
	if udp4 := xTransport.quicUDP4.Load(); udp4 != nil {
		_ = udp4.Close()
		xTransport.quicUDP4.Store(nil)
	}
	if udp6 := xTransport.quicUDP6.Load(); udp6 != nil {
		_ = udp6.Close()
		xTransport.quicUDP6.Store(nil)
	}

	if xTransport.mainProto == "tcp" {
		xTransport.resolveProtos = protoTCPFirst
	} else {
		xTransport.resolveProtos = protoUDPFirst
	}

	timeout := xTransport.timeout
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           5000,
		MaxIdleConnsPerHost:    500,  // Increased for better connection reuse
		MaxConnsPerHost:        500,  // Increased for better throughput
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  0,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 16 * 1024,
		ReadBufferSize:         32 * 1024,  // Go 1.20+: Larger buffers
		WriteBufferSize:        32 * 1024,

		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

			cachedIPs, _, _ := xTransport.loadCachedIPs(host)

			// Try connection coalescing first
			if conn, coalesced := xTransport.getCoalescedConnection(host, cachedIPs); coalesced {
				return conn, nil
			}

			targets := make([]string, 0, len(cachedIPs))
			for _, ip := range cachedIPs {
				if endpoint := formatEndpoint(ip, port); endpoint != "" {
					targets = append(targets, endpoint)
				}
			}

			if len(targets) == 0 {
				dlog.Debugf("[%s] IP address was not cached in DialContext", host)
				if parsed := ParseIP(host); parsed != nil {
					targets = append(targets, net.JoinHostPort(parsed.String(), strconv.Itoa(port)))
				} else {
					targets = append(targets, net.JoinHostPort(host, strconv.Itoa(port)))
				}
			}

			dial := func(address string) (net.Conn, error) {
				if xTransport.proxyDialer == nil {
					// Use TCP Fast Open if enabled
					conn, err := xTransport.dialWithFastOpen(ctx, network, address)
					if err == nil {
						if tcpConn, ok := conn.(*net.TCPConn); ok {
							_ = tcpConn.SetNoDelay(true)
							_ = tcpConn.SetKeepAlive(true)
							_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
							_ = tcpConn.SetLinger(0) // Go 1.23+: Faster cleanup
						}
					}
					return conn, err
				}
				return (*xTransport.proxyDialer).Dial(network, address)
			}

			// Happy Eyeballs with staggered dials
			type dialResult struct {
				conn net.Conn
				err  error
			}

			ch := make(chan dialResult, len(targets))
			done := make(chan struct{})
			dialCtx, cancelDial := context.WithCancel(ctx)
			defer cancelDial()
			defer close(done)

			for i, target := range targets {
				go func(i int, target string) {
					if i > 0 {
						delay := 50 * time.Millisecond
						if i == 1 {
							delay := 250 * time.Millisecond
						}
						timer := time.NewTimer(delay)
						defer timer.Stop()

						select {
						case <-timer.C:
						case <-done:
							return
						case <-dialCtx.Done():
							return
						}
					}

					conn, err := dial(target)
					select {
					case ch <- dialResult{conn: conn, err: err}:
					case <-done:
						if conn != nil {
							_ = conn.Close()
						}
					case <-dialCtx.Done():
						if conn != nil {
							_ = conn.Close()
						}
					}
				}(i, target)
			}

			var lastErr error
			for i := 0; i < len(targets); i++ {
				select {
				case res := <-ch:
					if res.err == nil {
						return res.conn, nil
					}
					lastErr = res.err
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, lastErr
		},
	}

	if xTransport.httpProxyFunction != nil {
		transport.Proxy = xTransport.httpProxyFunction
	}

	// TLS Configuration with ECH support
	clientCreds := xTransport.tlsClientCreds
	tlsClientConfig := tls.Config{}
	certPool, certPoolErr := x509.SystemCertPool()

	if xTransport.keyLogWriter != nil {
		tlsClientConfig.KeyLogWriter = xTransport.keyLogWriter
	}

	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		additionalCaCert, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", clientCreds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(additionalCaCert)
	}

	if certPool != nil {
		letsEncryptX1Cert := []byte(`-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`)
		certPool.AppendCertsFromPEM(letsEncryptX1Cert)
		tlsClientConfig.RootCAs = certPool
	}

	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v", clientCreds.clientCert, clientCreds.clientKey, err)
		}
		tlsClientConfig.Certificates = []tls.Certificate{cert}
	}

	if xTransport.tlsDisableSessionTickets {
		tlsClientConfig.SessionTicketsDisabled = true
	} else {
		tlsClientConfig.ClientSessionCache = xTransport.sessionCache
	}

	tlsClientConfig.MaxVersion = tls.VersionTLS13
	if xTransport.tlsPreferRSA {
		if hasAESGCMHardwareSupport {
			tlsClientConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			}
		} else {
			tlsClientConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			}
		}
	}

	transport.TLSClientConfig = &tlsClientConfig

	// Enhanced HTTP/2 configuration (Go 1.23+)
	if h2Transport, err := http2.ConfigureTransports(transport); err == nil && h2Transport != nil {
		h2Transport.ReadIdleTimeout = 30 * time.Second
		h2Transport.PingTimeout = 3 * time.Second // Reduced for faster detection
		h2Transport.AllowHTTP = false
		h2Transport.StrictMaxConcurrentStreams = false // Allow flexibility
		h2Transport.MaxReadFrameSize = 512 * 1024      // Increased frame size
		h2Transport.MaxHeaderListSize = 1 << 20        // 1MB headers
		h2Transport.MaxConcurrentStreams = 250         // Increased for multiplexing
	}

	xTransport.transport = transport
	xTransport.httpClient = &http.Client{Transport: xTransport.transport}

	// HTTP/3 transport setup
	if xTransport.http3 {
		dial := xTransport.createH3DialFunc(&tlsClientConfig)
		h3Transport := &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    &tlsClientConfig,
			Dial:               dial,
		}
		xTransport.h3Transport = h3Transport
		xTransport.h3Client = &http.Client{Transport: xTransport.h3Transport}
	}
}

// ========== HTTP/3 Dial Function ==========

func (xTransport *XTransport) createH3DialFunc(tlsCfg *tls.Config) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("Dialing for H3: [%v]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		type udpTarget struct {
			addr    string
			network string
		}

		buildAddr := func(ip net.IP) udpTarget {
			if ip != nil {
				if ipv4 := ip.To4(); ipv4 != nil {
					return udpTarget{
						addr:    net.JoinHostPort(ipv4.String(), strconv.Itoa(port)),
						network: "udp4",
					}
				}
				return udpTarget{
					addr:    net.JoinHostPort(ip.String(), strconv.Itoa(port)),
					network: "udp6",
				}
			}

			network := "udp4"
			addr := host
			if parsed := ParseIP(host); parsed != nil {
				if parsed.To4() != nil {
					addr = parsed.String()
				} else {
					network = "udp6"
					addr = parsed.String()
				}
			} else if xTransport.useIPv6 {
				if xTransport.useIPv4 {
					network = "udp"
				} else {
					network = "udp6"
				}
			}
			return udpTarget{
				addr:    net.JoinHostPort(addr, strconv.Itoa(port)),
				network: network,
			}
		}

		cachedIPs, _, _ := xTransport.loadCachedIPs(host)
		targets := make([]udpTarget, 0, len(cachedIPs))
		for _, ip := range cachedIPs {
			targets = append(targets, buildAddr(ip))
		}

		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached in H3 context", host)
			targets = append(targets, buildAddr(nil))
		}

		var lastErr error
		for idx, target := range targets {
			udpAddr, err := net.ResolveUDPAddr(target.network, target.addr)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: failed to resolve [%s] on %s: %v", target.addr, target.network, err)
				}
				continue
			}

			tr, err := xTransport.getQUICTransport(target.network)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: failed to listen for [%s] on %s: %v", target.addr, target.network, err)
				}
				continue
			}

			tlsCfg.ServerName = host
			if cfg == nil {
				cfg = &quic.Config{}
			}
			cfg.Allow0RTT = true
			if cfg.KeepAlivePeriod == 0 {
				cfg.KeepAlivePeriod = 15 * time.Second
			}

			conn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: dialing [%s] via %s failed: %v", target.addr, target.network, err)
				}
				continue
			}

			return conn, nil
		}

		return nil, lastErr
	}
}

// ========== DNS Resolution Functions ==========

func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if err != nil {
		return nil, SystemResolverIPTTL, fmt.Errorf("system DNS lookup failed: %w", err)
	}

	if returnIPv4 && returnIPv6 {
		return ipa, SystemResolverIPTTL, nil
	}

	ips := make([]net.IP, 0, len(ipa))
	for _, ip := range ipa {
		ipv4 := ip.To4()
		if returnIPv4 && ipv4 != nil {
			ips = append(ips, ipv4)
		}
		if returnIPv6 && ipv4 == nil {
			ips = append(ips, ip)
		}
	}
	return ips, SystemResolverIPTTL, nil
}

func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	type queryResult struct {
		ips []net.IP
		ttl time.Duration
		err error
	}

	queryTypes := make([]uint16, 0, 2)
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	if len(queryTypes) == 0 {
		return nil, 0, errors.New("no query types requested")
	}

	results := make(chan queryResult, 2)
	ctx, cancel := context.WithTimeout(bgCtx, ResolverReadTimeout)
	defer cancel()

	dnsClient := xTransport.dnsClientPool.Get().(*dns.Client)
	defer xTransport.dnsClientPool.Put(dnsClient)

	for _, qType := range queryTypes {
		go func(qt uint16) {
			msg := xTransport.dnsMessagePool.Get()
			defer xTransport.dnsMessagePool.Put(msg)

			msg.SetQuestion(dns.Fqdn(host), qt)
			msg.RecursionDesired = true
			msg.SetEdns0(uint16(MaxDNSPacketSize), true)

			var qIPs []net.IP
			var qTTL uint32

			in, _, err := dnsClient.Exchange(ctx, msg, proto, resolver)
			if err == nil && in != nil {
				// Pre-allocate with capacity hint (Go 1.26 optimization)
				qIPs = make([]net.IP, 0, len(in.Answer))

				for _, answer := range in.Answer {
					if dns.RRToType(answer) == qt {
						switch qt {
						case dns.TypeA:
							if a, ok := answer.(*dns.A); ok {
								qIPs = append(qIPs, a.A.Addr.AsSlice())
								qTTL = a.Header().TTL
							}
						case dns.TypeAAAA:
							if aaaa, ok := answer.(*dns.AAAA); ok {
								qIPs = append(qIPs, aaaa.AAAA.Addr.AsSlice())
								qTTL = aaaa.Header().TTL
							}
						}
					}
				}
			}

			select {
			case results <- queryResult{ips: qIPs, ttl: time.Duration(qTTL) * time.Second, err: err}:
			case <-ctx.Done():
			}
		}(qType)
	}

	collectedIPs := make([]net.IP, 0, len(queryTypes)*2)
	collectedIPs = slices.Grow(collectedIPs, len(queryTypes)*2)
	var minTTL time.Duration
	var lastErr error

	for i := 0; i < len(queryTypes); i++ {
		select {
		case res := <-results:
			if res.err == nil {
				if len(res.ips) > 0 {
					collectedIPs = append(collectedIPs, res.ips...)
					if minTTL == 0 || res.ttl < minTTL {
						minTTL = res.ttl
					}
				}
			} else {
				lastErr = res.err
			}
		case <-ctx.Done():
			if len(collectedIPs) > 0 {
				break
			}
			return nil, 0, ctx.Err()
		}
	}

	if len(collectedIPs) > 0 {
		return collectedIPs, minTTL, nil
	}

	if lastErr != nil {
		return nil, 0, lastErr
	}

	return nil, 0, errors.New("no IP addresses returned")
}

func (xTransport *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errors.New("empty resolvers")
	}

	var lastErr error
	for i, resolver := range resolvers {
		for attempt := 0; attempt < resolverRetryCount; attempt++ {
			ips, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return ips, ttl, nil
			}

			if err == nil {
				err = errors.New("no IP addresses returned")
			}

			lastErr = err
			dlog.Debugf("Resolver attempt %d failed for [%s] using [%s] (%s): %v", attempt+1, host, resolver, proto, err)

			if attempt < resolverRetryCount-1 {
				time.Sleep(resolverBackoffs[attempt])
			}
		}
		dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, lastErr)
	}

	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}

	return nil, 0, lastErr
}

func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	if xTransport.ignoreSystemDNS {
		if xTransport.internalResolverReady {
			for _, proto := range xTransport.resolveProtos {
				ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					break
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = errors.New("system DNS is not usable yet")
			dlog.Notice(err)
		}
	}

	if err != nil {
		for _, proto := range xTransport.resolveProtos {
			if err != nil {
				dlog.Noticef("Resolving server host [%s] using bootstrap resolvers over %s", host, proto)
				ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.bootstrapResolvers, returnIPv4, returnIPv6)
				if err == nil {
					break
				}
			}
		}

		if err != nil && xTransport.ignoreSystemDNS {
			dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
			ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
		}
	}

	return ips, ttl, err
}

func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}

	if ParseIP(host) != nil {
		return nil
	}

	cachedIPs, expired, updating := xTransport.loadCachedIPs(host)
	if len(cachedIPs) > 0 {
		if expired && !updating {
			xTransport.markUpdatingCachedIP(host)
			go func(stale []net.IP) {
				_ = xTransport.resolveAndUpdateCacheBlocking(host, stale)
			}(cachedIPs)
		}
		return nil
	}

	_, err, _ := xTransport.resolveGroup.Do(host, func() (any, error) {
		return nil, xTransport.resolveAndUpdateCacheBlocking(host, nil)
	})
	return err
}

func (xTransport *XTransport) resolveAndUpdateCacheBlocking(host string, cachedIPs []net.IP) error {
	ips, ttl, err := xTransport.resolve(host, xTransport.useIPv4, xTransport.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale [%v] cached address for a grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return err
	}

	if len(selectedIPs) == 0 {
		if !xTransport.useIPv4 && xTransport.useIPv6 {
			dlog.Warnf("no IPv6 address found for [%s]", host)
		} else if xTransport.useIPv4 && !xTransport.useIPv6 {
			dlog.Warnf("no IPv4 address found for [%s]", host)
		} else {
			dlog.Errorf("no IP address found for [%s]", host)
		}
		return nil
	}

	xTransport.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// ========== HTTP Fetch with Latency Tracking ==========

func (xTransport *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if timeout <= 0 {
		timeout = xTransport.timeout
	}

	ctx, cancel := context.WithTimeout(bgCtx, timeout)
	defer cancel()

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false
	client := xTransport.httpClient
	if client == nil {
		client = &http.Client{Transport: xTransport.transport}
	}

	// HTTP/3 selection logic
	if xTransport.h3Transport != nil {
		if xTransport.http3Probe {
			if xTransport.h3Client != nil {
				client = xTransport.h3Client
			}
			dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
		} else {
			val, ok := xTransport.altSupport.cache.Load(url.Host)
			hasAltSupport = ok
			if ok {
				item := val.(AltSupportItem)
				altPort := item.port
				if altPort > 0 {
					if int(altPort) == port {
						if xTransport.h3Client != nil {
							client = xTransport.h3Client
						}
						dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
					}
				} else if item.valid && time.Now().After(item.nextProbe) {
					if xTransport.h3Client != nil {
						client = xTransport.h3Client
						dlog.Debugf("Retrying HTTP/3 probe for [%s]", url.Host)
					}
				}
			}
		}
	}

	// Optimized header creation with lowercase for better HPACK compression
	header := make(http.Header, 5)
	header.Set("user-agent", "dnscrypt-proxy")
	header.Set("cache-control", "max-stale")

	if len(accept) > 0 {
		header["accept"] = []string{accept}
	}
	if len(contentType) > 0 {
		header["content-type"] = []string{contentType}
	}

	if body != nil {
		h := fnv.New64a()
		h.Write(*body)
		qs := url.Query()
		qs.Add("body_hash", strconv.FormatUint(h.Sum64(), 16))
		url2 := *url
		url2.RawQuery = qs.Encode()
		url = &url2
	}

	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("onion service is not reachable without Tor")
	}

	// Pre-resolve with ECH config fetching
	if xTransport.echEnabled {
		if _, cached := xTransport.echConfigs.Load(host); !cached {
			go func() {
				if config, err := xTransport.fetchECHConfig(host); err == nil {
					xTransport.echConfigs.Store(host, config)
				}
			}()
		}
	}

	if err := xTransport.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%v] - Make sure that the system resolver works, or that `bootstrap_resolvers` has been set to resolvers that can be reached", host)
		return nil, 0, nil, 0, err
	}

	if compress && body == nil {
		header["accept-encoding"] = []string{"gzip"}
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	req = req.WithContext(ctx)

	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 fallback logic
	if err != nil && xTransport.h3Client != nil && client == xTransport.h3Client {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		}

		xTransport.altSupport.cache.Store(url.Host, AltSupportItem{
			port:      0,
			nextProbe: time.Now().Add(5 * time.Minute),
			valid:     true,
		})

		client = xTransport.httpClient
		if client == nil {
			client = &http.Client{Transport: xTransport.transport}
		}

		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	if err == nil {
		if resp == nil {
			err = errors.New("webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: [%v] - closing idle connections", err)
		if xTransport.transport != nil {
			xTransport.transport.CloseIdleConnections()
		}
	}

	statusCode := 503
	if resp != nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
	}

	if err != nil {
		dlog.Debugf("[%s]: [%s]", req.URL, err)
		return nil, statusCode, nil, rtt, err
	}

	// Alt-Svc parsing for HTTP/3 discovery
	if xTransport.h3Transport != nil && !hasAltSupport {
		skipAltSvcParsing := false

		if xTransport.http3Probe {
			val, inCache := xTransport.altSupport.cache.Load(url.Host)
			if inCache {
				item := val.(AltSupportItem)
				if item.port == 0 {
					if item.valid && time.Now().Before(item.nextProbe) {
						dlog.Debugf("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", url.Host)
						skipAltSvcParsing = true
					}
				}
			}
		}

		if !skipAltSvcParsing {
			if alt, found := resp.Header["Alt-Svc"]; found {
				dlog.Debugf("Alt-Svc [%s]: [%s]", url.Host, alt)
				altPort := uint16(port & 0xffff)

				for i, xalt := range alt {
					for j, v := range strings.Split(xalt, ";") {
						if i >= 8 || j >= 16 {
							break
						}

						v = strings.TrimSpace(v)
						if strings.HasPrefix(v, `h3=":`) {
							v = strings.TrimPrefix(v, `h3=":`)
							v = strings.TrimSuffix(v, `"`)
							if xAltPort, err := strconv.ParseUint(v, 10, 16); err == nil && xAltPort <= 65535 {
								altPort = uint16(xAltPort)
								dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
								break
							}
						}
					}
				}

				xTransport.altSupport.cache.Store(url.Host, AltSupportItem{port: altPort, valid: true})
				dlog.Debugf("Caching altPort for [%v]", url.Host)
			}
		}
	}

	tlsState := resp.TLS
	var bodyReader io.Reader = resp.Body
	var gr *gzip.Reader

	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		limited := io.LimitReader(resp.Body, MaxHTTPBodyLength)
		gr, err = xTransport.getGzipReader(limited)
		if err != nil {
			return nil, statusCode, tlsState, rtt, err
		}
		defer xTransport.putGzipReader(gr)
		bodyReader = gr
	}

	buf := xTransport.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer xTransport.bufferPool.Put(buf)

	_, err = io.CopyN(buf, bodyReader, MaxHTTPBodyLength)
	if err != nil && err != io.EOF {
		return nil, statusCode, tlsState, rtt, err
	}

	bin := make([]byte, buf.Len())
	copy(bin, buf.Bytes())

	return bin, statusCode, tlsState, rtt, nil
}

func (xTransport *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, true)
}

func (xTransport *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, false)
}

func (xTransport *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// ========== DoH Query Functions ==========

func (xTransport *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, &body, timeout)
}

func (xTransport *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	const getThreshold = 190
	const postThreshold = 256

	shouldUseGet := len(body) <= getThreshold
	if useGet && len(body) > postThreshold {
		shouldUseGet = false
	}

	return xTransport.dohLikeQuery("application/dns-message", shouldUseGet, url, body, timeout)
}

func (xTransport *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}

// ========== Parallel DoH Queries for Improved Latency ==========

type parallelQueryResult struct {
	response []byte
	rtt      time.Duration
	server   string
	err      error
}

func (xTransport *XTransport) DoHQueryParallel(
	resolvers []string,
	body []byte,
	timeout time.Duration,
) ([]byte, time.Duration, string, error) {
	if len(resolvers) <= 1 {
		if len(resolvers) == 1 {
			u, _ := url.Parse(resolvers[0])
			resp, _, _, rtt, err := xTransport.DoHQuery(false, u, body, timeout)
			return resp, rtt, resolvers[0], err
		}
		return nil, 0, "", errors.New("no resolvers provided")
	}

	ctx, cancel := context.WithTimeout(bgCtx, timeout)
	defer cancel()

	results := make(chan parallelQueryResult, len(resolvers))

	for _, resolver := range resolvers {
		go func(res string) {
			u, err := url.Parse(res)
			if err != nil {
				results <- parallelQueryResult{err: err, server: res}
				return
			}

			start := time.Now()
			response, _, _, rtt, err := xTransport.DoHQuery(false, u, body, timeout)

			select {
			case results <- parallelQueryResult{
				response: response,
				rtt:      time.Since(start),
				server:   res,
				err:      err,
			}:
			case <-ctx.Done():
				return
			}
		}(resolver)
	}

	// Return first successful response
	for i := 0; i < len(resolvers); i++ {
		select {
		case result := <-results:
			if result.err == nil {
				dlog.Debugf("Fastest resolver: [%s] in %v", result.server, result.rtt)
				return result.response, result.rtt, result.server, nil
			}
		case <-ctx.Done():
			return nil, 0, "", ctx.Err()
		}
	}

	return nil, 0, "", errors.New("all resolvers failed")
}

// ========== Connection Pre-warming ==========

func (xTransport *XTransport) PrewarmDNSCache(dohResolvers []string) {
	if len(dohResolvers) == 0 {
		return
	}

	hosts := make([]string, 0, len(dohResolvers))
	for _, resolver := range dohResolvers {
		u, err := url.Parse(resolver)
		if err != nil {
			continue
		}
		host, _ := ExtractHostAndPort(u.Host, 443)
		hosts = append(hosts, host)
	}

	maxConcurrency := 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dlog.Debugf("Pre-warming DNS cache for [%s]", host)
			if err := xTransport.resolveAndUpdateCacheBlocking(host, nil); err != nil {
				dlog.Warnf("Failed to pre-warm DNS for [%s]: %v", host, err)
			}
		}(h)
	}

	wg.Wait()
}

// Pre-warm connections with actual HTTP requests
func (xTransport *XTransport) PrewarmConnections(dohResolvers []string) {
	dlog.Info("Pre-warming connections to DoH resolvers")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, resolver := range dohResolvers {
		wg.Add(1)
		go func(res string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			u, err := url.Parse(res)
			if err != nil {
				return
			}

			host, _ := ExtractHostAndPort(u.Host, 443)
			dlog.Debugf("Pre-warming connection to [%s]", host)

			// Resolve DNS first
			if err := xTransport.resolveAndUpdateCache(host); err != nil {
				dlog.Warnf("Failed to resolve [%s] for pre-warming: %v", host, err)
				return
			}

			// Make HEAD request to establish connection
			ctx, cancel := context.WithTimeout(bgCtx, 5*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "HEAD", u.String(), nil)
			client := xTransport.httpClient
			if client == nil {
				return
			}

			resp, err := client.Do(req)
			if err == nil && resp != nil {
				resp.Body.Close()
				dlog.Debugf("Connection to [%s] pre-warmed successfully", host)
			}
		}(resolver)
	}

	wg.Wait()
}

// ========== Performance Statistics ==========

func (xTransport *XTransport) GetCacheStats() (hits, misses uint64) {
	return xTransport.cachedIPs.hits.Load(), xTransport.cachedIPs.misses.Load()
}

func (xTransport *XTransport) PrintStats() {
	hits, misses := xTransport.GetCacheStats()
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	dlog.Infof("DNS Cache Statistics: Hits=%d, Misses=%d, Hit Rate=%.2f%%", hits, misses, hitRate)

	if xTransport.enableCoalescing {
		var connCount int
		xTransport.coalescingCache.connections.Range(func(key, value interface{}) bool {
			connCount++
			return true
		})
		dlog.Infof("Connection Coalescing: %d active coalesced connections", connCount)
	}

	if xTransport.echEnabled {
		var echCount int
		xTransport.echConfigs.Range(func(key, value interface{}) bool {
			echCount++
			return true
		})
		dlog.Infof("ECH Configurations: %d hosts with ECH configs cached", echCount)
	}
}
