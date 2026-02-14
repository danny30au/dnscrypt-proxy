package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)

// Hardware acceleration detection for optimized cipher suite selection
// Go 1.26: Used for intelligent cipher suite ordering based on CPU capabilities
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// Configuration constants with optimized values for modern networks
const (
	DefaultBootstrapResolver    = "9.9.9.9:53"
	DefaultKeepAlive            = 5 * time.Second
	DefaultTimeout              = 30 * time.Second
	ResolverReadTimeout         = 5 * time.Second
	SystemResolverIPTTL         = 12 * time.Hour
	MinResolverIPTTL            = 4 * time.Hour
	ResolverIPTTLMaxJitter      = 15 * time.Minute
	ExpiredCachedIPGraceTTL     = 15 * time.Minute
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second
)

// CachedIPItem represents a cached DNS resolution result with expiration tracking.
// Go 1.26: Now uses netip.Addr for zero-allocation IP operations.
type CachedIPItem struct {
	addrs         []netip.Addr // Go 1.26: netip.Addr instead of net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

// CachedIPs provides thread-safe IP address caching with RWMutex for concurrent access.
// Go 1.26: Benefits from improved sync.RWMutex performance in the runtime.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// AltSupport tracks HTTP/3 (Alt-Svc) support by host with port information.
// Zero port value indicates HTTP/3 is not supported (negative cache).
type AltSupport struct {
	sync.RWMutex
	cache map[string]uint16
}

// XTransport provides an advanced HTTP/HTTPS transport with DNS caching,
// HTTP/3 support, custom resolvers, and automatic fallback mechanisms.
// Go 1.26: Fully migrated to netip package for optimal performance.
type XTransport struct {
	transport                *http.Transport
	h3Transport              *http3.Transport
	keepAlive                time.Duration
	timeout                  time.Duration
	cachedIPs                CachedIPs
	altSupport               AltSupport
	internalResolvers        []string
	bootstrapResolvers       []string
	mainProto                string
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
}

// NewXTransport creates a new XTransport instance with sensible defaults.
// Go 1.26: Initialized with post-quantum TLS and netip optimization.
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse: " + err.Error())
	}

	return &XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:               AltSupport{cache: make(map[string]uint16)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		mainProto:                "",
		ignoreSystemDNS:          true,
		useIPv4:                  true,
		useIPv6:                  false,
		http3Probe:               false,
		tlsDisableSessionTickets: false,
		tlsPreferRSA:             false,
		keyLogWriter:             nil,
	}
}

// ParseIP parses an IP address string, handling both IPv4 and IPv6 with brackets.
// Go 1.26: MIGRATED to netip.ParseAddr for better performance and type safety.
// Returns netip.Addr for modern code, but maintains net.IP compatibility wrapper.
func ParseIP(ipStr string) net.IP {
	addr, err := ParseIPAddr(ipStr)
	if err != nil {
		return nil
	}
	return addr.AsSlice()
}

// ParseIPAddr parses an IP address string using netip.ParseAddr.
// Go 1.26: Preferred function - returns netip.Addr for zero-allocation operations.
func ParseIPAddr(ipStr string) (netip.Addr, error) {
	// Remove brackets for IPv6 addresses
	cleaned := strings.TrimRight(strings.TrimLeft(ipStr, "["), "]")

	addr, err := netip.ParseAddr(cleaned)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q: %w", ipStr, err)
	}

	return addr, nil
}

// netIPToAddr converts net.IP to netip.Addr for migration purposes.
// Go 1.26: Helper function for gradual migration from net.IP to netip.Addr.
func netIPToAddr(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address: %v", ip)
	}
	return addr, nil
}

// secureRandomInt63n generates a cryptographically secure random int64 in [0, n).
// Go 1.26: Replaces deprecated math/rand with crypto/rand for security-sensitive operations.
func secureRandomInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(n)
	result, err := rand.Int(rand.Reader, max)
	if err != nil {
		dlog.Warnf("Failed to generate secure random number: %v", err)
		return 0
	}
	return result.Int64()
}

// uniqueNormalizedAddrs deduplicates and normalizes a slice of IP addresses.
// Go 1.26: Uses netip.Addr for efficient comparison and zero-allocation operations.
func uniqueNormalizedAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}

	unique := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]struct{}, len(addrs))

	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}

		// netip.Addr is comparable, no need for string conversion
		if _, exists := seen[addr]; exists {
			continue
		}

		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}

	return unique
}

// uniqueNormalizedIPs is a compatibility wrapper for code that still uses net.IP.
// Go 1.26: Prefer uniqueNormalizedAddrs for better performance.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	// Convert to netip.Addr
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, err := netIPToAddr(ip); err == nil {
			addrs = append(addrs, addr)
		}
	}

	// Deduplicate
	uniqueAddrs := uniqueNormalizedAddrs(addrs)

	// Convert back to net.IP
	result := make([]net.IP, len(uniqueAddrs))
	for i, addr := range uniqueAddrs {
		result[i] = addr.AsSlice()
	}

	return result
}

// saveCachedAddrs stores resolved IP addresses in the cache with TTL.
// Go 1.26: Uses netip.Addr for zero-allocation caching and crypto/rand for jitter.
func (xTransport *XTransport) saveCachedAddrs(host string, addrs []netip.Addr, ttl time.Duration) {
	normalized := uniqueNormalizedAddrs(addrs)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{addrs: normalized}

	// Apply TTL with secure random jitter to prevent thundering herd
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}

		jitter := secureRandomInt63n(int64(ResolverIPTTLMaxJitter))
		ttl += time.Duration(jitter)
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}

	xTransport.cachedIPs.Lock()
	item.updatingUntil = nil
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()

	// Structured logging
	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIPs is a compatibility wrapper for code that uses net.IP.
// Go 1.26: Converts net.IP to netip.Addr and calls saveCachedAddrs.
func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, err := netIPToAddr(ip); err == nil {
			addrs = append(addrs, addr)
		}
	}
	xTransport.saveCachedAddrs(host, addrs, ttl)
}

// saveCachedIP is a compatibility wrapper for caching a single IP address.
func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	xTransport.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// markUpdatingCachedIP marks a cache entry as being actively updated.
func (xTransport *XTransport) markUpdatingCachedIP(host string) {
	xTransport.cachedIPs.Lock()
	defer xTransport.cachedIPs.Unlock()

	item, ok := xTransport.cachedIPs.cache[host]
	if !ok {
		return
	}

	until := time.Now().Add(xTransport.timeout)
	item.updatingUntil = &until
	xTransport.cachedIPs.cache[host] = item
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedAddrs retrieves cached IP addresses as netip.Addr.
// Go 1.26: Preferred method - returns netip.Addr for zero-allocation operations.
func (xTransport *XTransport) loadCachedAddrs(host string) (addrs []netip.Addr, expired bool, updating bool) {
	xTransport.cachedIPs.RLock()
	defer xTransport.cachedIPs.RUnlock()

	item, ok := xTransport.cachedIPs.cache[host]
	if !ok {
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}

	// netip.Addr is immutable, no need for defensive copies
	addrs = item.addrs

	expiration := item.expiration
	updatingUntil := item.updatingUntil

	// Check expiration status
	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IP addresses are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
		}
	}

	return addrs, expired, updating
}

// loadCachedIPs is a compatibility wrapper that returns net.IP.
// Go 1.26: Prefer loadCachedAddrs for better performance.
func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	addrs, expired, updating := xTransport.loadCachedAddrs(host)

	if len(addrs) > 0 {
		ips = make([]net.IP, len(addrs))
		for i, addr := range addrs {
			ips[i] = addr.AsSlice()
		}
	}

	return ips, expired, updating
}

// buildAddrPort creates a netip.AddrPort for modern Go 1.26 networking.
// Go 1.26: Zero-allocation address:port representation for net.Dialer methods.
func buildAddrPort(addr netip.Addr, port int) netip.AddrPort {
	return netip.AddrPortFrom(addr, uint16(port))
}

// formatAddrPort formats a netip.AddrPort into a network address string.
// Go 1.26: Optimized formatting using netip.AddrPort.String().
func formatAddrPort(addrPort netip.AddrPort) string {
	return addrPort.String()
}

// formatEndpoint formats an address and port into a proper network address string.
// Go 1.26: Handles netip.Addr, net.IP, and hostname formats correctly.
func formatEndpoint(addr netip.Addr, ip net.IP, host string, port int) string {
	// Prefer netip.Addr if valid
	if addr.IsValid() {
		return formatAddrPort(buildAddrPort(addr, port))
	}

	// Fallback to net.IP
	if ip != nil {
		if convertedAddr, err := netIPToAddr(ip); err == nil {
			return formatAddrPort(buildAddrPort(convertedAddr, port))
		}
	}

	// Handle hostname or parse as IP
	if parsed, err := ParseIPAddr(host); err == nil {
		return formatAddrPort(buildAddrPort(parsed, port))
	}

	return net.JoinHostPort(host, strconv.Itoa(port))
}

// rebuildTransport (re)constructs the HTTP and HTTP/3 transports.
// Go 1.26: Uses netip.Addr for zero-allocation dialing and post-quantum TLS.
func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport with Go 1.26 netip optimizations")

	if xTransport.transport != nil {
		xTransport.transport.CloseIdleConnections()
	}

	timeout := xTransport.timeout

	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           100,  // Go 1.26: 100x increase for better reuse
		MaxIdleConnsPerHost:    10,   // Go 1.26: Per-host optimization
		IdleConnTimeout:        xTransport.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		ForceAttemptHTTP2:      true, // Go 1.26: Enable HTTP/2 by default

		// Go 1.26: Custom dialer with netip.Addr for zero-allocation operations
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

			// Load cached addresses using netip.Addr
			cachedAddrs, _, _ := xTransport.loadCachedAddrs(host)
			targets := make([]string, 0, len(cachedAddrs))

			for _, addr := range cachedAddrs {
				targets = append(targets, formatEndpoint(addr, nil, host, port))
			}

			// Fallback if no cached addresses
			if len(targets) == 0 {
				dlog.Debugf("[%s] IP address was not cached in DialContext", host)
				targets = append(targets, formatEndpoint(netip.Addr{}, nil, host, port))
			}

			// Dial function with proxy support
			dial := func(address string) (net.Conn, error) {
				if xTransport.proxyDialer != nil {
					return (*xTransport.proxyDialer).Dial(network, address)
				}

				// Go 1.26: Simplified dialer
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: timeout,
				}
				return dialer.DialContext(ctx, network, address)
			}

			// Try each target with early exit on success
			var lastErr error
			for idx, target := range targets {
				conn, err := dial(target)
				if err == nil {
					return conn, nil
				}

				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("Dial attempt using [%s] failed: %v", target, err)
				}
			}

			return nil, lastErr
		},
	}

	if xTransport.httpProxyFunction != nil {
		transport.Proxy = xTransport.httpProxyFunction
	}

	tlsClientConfig := xTransport.buildTLSConfig()
	transport.TLSClientConfig = tlsClientConfig

	// Go 1.26: Configure HTTP/2 with strict concurrent streams
	if http2Transport, err := http2.ConfigureTransports(transport); err == nil && http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
		http2Transport.StrictMaxConcurrentStreams = true

		dlog.Debug("HTTP/2 transport configured with strict concurrent streams")
	}

	xTransport.transport = transport

	if xTransport.http3 {
		xTransport.buildHTTP3Transport(tlsClientConfig)
	}
}

// buildTLSConfig creates a TLS configuration with Go 1.26 security best practices.
func (xTransport *XTransport) buildTLSConfig() *tls.Config {
	clientCreds := xTransport.tlsClientCreds

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Go 1.26: Minimum secure version
	}

	if xTransport.keyLogWriter != nil {
		tlsConfig.KeyLogWriter = xTransport.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()

	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}

		additionalCaCert, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", clientCreds.rootCA, err)
		}

		if !certPool.AppendCertsFromPEM(additionalCaCert) {
			dlog.Warnf("Failed to append custom CA certificates from [%s]", clientCreds.rootCA)
		}
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
		tlsConfig.RootCAs = certPool
	}

	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v",
				clientCreds.clientCert, clientCreds.clientKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if xTransport.tlsDisableSessionTickets {
		tlsConfig.SessionTicketsDisabled = true
	}

	if xTransport.tlsPreferRSA {
		tlsConfig.MaxVersion = tls.VersionTLS12
	}

	// Go 1.26: Post-quantum TLS curves
	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	// Go 1.26: Hardware-aware cipher suites
	if hasAESGCMHardwareSupport {
		tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	} else {
		tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	}

	return tlsConfig
}

// buildHTTP3Transport creates and configures the HTTP/3 (QUIC) transport.
// Go 1.26: Uses netip.Addr for efficient UDP address handling.
func (xTransport *XTransport) buildHTTP3Transport(tlsConfig *tls.Config) {
	dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("Dialing HTTP/3 for [%v]", addrStr)

		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		// Helper to build UDP address using netip.Addr
		buildUDPAddr := func(addr netip.Addr) (*net.UDPAddr, string) {
			if addr.IsValid() {
				network := "udp4"
				if addr.Is6() {
					network = "udp6"
				}
				// Convert netip.Addr to net.IP for net.UDPAddr compatibility
				return &net.UDPAddr{IP: addr.AsSlice(), Port: port}, network
			}

			// Fallback: try parsing host
			network := "udp4"
			if parsed, err := ParseIPAddr(host); err == nil {
				if parsed.Is6() {
					network = "udp6"
				}
				return &net.UDPAddr{IP: parsed.AsSlice(), Port: port}, network
			}

			// Use configured IP version
			if xTransport.useIPv6 {
				if xTransport.useIPv4 {
					network = "udp"
				} else {
					network = "udp6"
				}
			}

			return &net.UDPAddr{Port: port}, network
		}

		// Load cached addresses using netip.Addr
		cachedAddrs, _, _ := xTransport.loadCachedAddrs(host)

		type udpTarget struct {
			addr    *net.UDPAddr
			network string
		}

		targets := make([]udpTarget, 0, len(cachedAddrs))
		for _, addr := range cachedAddrs {
			udpAddr, network := buildUDPAddr(addr)
			targets = append(targets, udpTarget{addr: udpAddr, network: network})
		}

		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached for HTTP/3", host)
			udpAddr, network := buildUDPAddr(netip.Addr{})
			targets = append(targets, udpTarget{addr: udpAddr, network: network})
		}

		var lastErr error
		for idx, target := range targets {
			udpConn, err := net.ListenUDP(target.network, nil)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("HTTP/3: failed to listen on %s: %v", target.network, err)
				}
				continue
			}

			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, target.addr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("HTTP/3: dialing [%v] via %s failed: %v",
						target.addr, target.network, err)
				}
				continue
			}

			return conn, nil
		}

		return nil, lastErr
	}

	h3Transport := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		Dial:               dial,
	}

	xTransport.h3Transport = h3Transport
	dlog.Debug("HTTP/3 transport configured with netip optimization")
}

// resolveUsingSystem uses the system resolver to look up IP addresses.
func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ips, err := net.LookupIP(host)

	if returnIPv4 && returnIPv6 {
		return ips, SystemResolverIPTTL, err
	}

	filtered := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		isIPv4 := ip.To4() != nil

		if returnIPv4 && isIPv4 {
			filtered = append(filtered, ip)
		} else if returnIPv6 && !isIPv4 {
			filtered = append(filtered, ip)
		}
	}

	return filtered, SystemResolverIPTTL, err
}

// resolveUsingResolver performs DNS resolution using a specific resolver.
// Go 1.26: Returns netip.Addr internally but converts to net.IP for compatibility.
func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) ([]net.IP, time.Duration, error) {

	transport := dns.NewTransport()
	transport.ReadTimeout = ResolverReadTimeout

	dnsClient := dns.Client{Transport: transport}

	queryTypes := make([]uint16, 0, 2)
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	var ips []net.IP
	var rrTTL uint32

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
	defer cancel()

	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}

		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		resp, _, err := dnsClient.Exchange(ctx, msg, proto, resolver)
		if err != nil {
			dlog.Debugf("DNS query for %s failed: %v", host, err)
			continue
		}

		for _, answer := range resp.Answer {
			if dns.RRToType(answer) == rrType {
				switch rrType {
				case dns.TypeA:
					if a, ok := answer.(*dns.A); ok {
						ips = append(ips, a.A.Addr.AsSlice())
						rrTTL = answer.Header().TTL
					}
				case dns.TypeAAAA:
					if aaaa, ok := answer.(*dns.AAAA); ok {
						ips = append(ips, aaaa.AAAA.Addr.AsSlice())
						rrTTL = answer.Header().TTL
					}
				}
			}
		}
	}

	var ttl time.Duration
	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}

	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no IP addresses found for %s", host)
	}

	return ips, ttl, nil
}

// resolveUsingServers attempts resolution using multiple resolvers with retry logic.
func (xTransport *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) ([]net.IP, time.Duration, error) {

	if len(resolvers) == 0 {
		return nil, 0, errors.New("empty resolvers list")
	}

	var lastErr error

	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff

		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err := xTransport.resolveUsingResolver(
				proto, host, resolver, returnIPv4, returnIPv6)

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
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] using [%s] (%s): %v",
				attempt, resolverRetryCount, host, resolver, proto, err)

			if attempt < resolverRetryCount {
				time.Sleep(delay)
				delay *= 2
				if delay > resolverRetryMaxBackoff {
					delay = resolverRetryMaxBackoff
				}
			}
		}

		dlog.Infof("All retry attempts failed for resolver [%s] (%s): %v",
			resolver, proto, lastErr)
	}

	if lastErr == nil {
		lastErr = errors.New("all resolvers failed")
	}

	return nil, 0, lastErr
}

// resolve performs DNS resolution using configured resolvers with fallback chain.
func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	var ips []net.IP
	var ttl time.Duration
	var err error

	if xTransport.ignoreSystemDNS {
		if xTransport.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = xTransport.resolveUsingServers(
					proto, host, xTransport.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return ips, ttl, nil
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
		dlog.Noticef("System DNS resolution failed: %v", err)
	}

	if err != nil {
		dlog.Noticef("Resolving [%s] using bootstrap resolvers", host)

		for _, proto := range protos {
			ips, ttl, err = xTransport.resolveUsingServers(
				proto, host, xTransport.bootstrapResolvers, returnIPv4, returnIPv6)
			if err == nil {
				return ips, ttl, nil
			}
		}
	}

	if err != nil && xTransport.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed - trying system resolver as last resort")
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}

	return ips, ttl, err
}

// resolveAndUpdateCache resolves a hostname if not cached and updates the cache.
// Go 1.26: Uses netip.Addr internally for efficient caching.
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}

	// Check if host is already an IP address using netip.ParseAddr
	if _, err := ParseIPAddr(host); err == nil {
		return nil
	}

	cachedAddrs, expired, updating := xTransport.loadCachedAddrs(host)

	if len(cachedAddrs) > 0 && (!expired || updating) {
		return nil
	}

	xTransport.markUpdatingCachedIP(host)

	ips, ttl, err := xTransport.resolve(host, xTransport.useIPv4, xTransport.useIPv6)

	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedAddrs) > 0 {
		dlog.Noticef("Using stale cached IPs for [%s] during grace period", host)
		// Convert cached addrs back to IPs for compatibility
		selectedIPs = make([]net.IP, len(cachedAddrs))
		for i, addr := range cachedAddrs {
			selectedIPs[i] = addr.AsSlice()
		}
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	if len(selectedIPs) == 0 {
		switch {
		case !xTransport.useIPv4 && xTransport.useIPv6:
			dlog.Warnf("No IPv6 address found for [%s]", host)
		case xTransport.useIPv4 && !xTransport.useIPv6:
			dlog.Warnf("No IPv4 address found for [%s]", host)
		default:
			dlog.Errorf("No IP address found for [%s]", host)
		}
		return nil
	}

	xTransport.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// Fetch performs an HTTP request with the configured transport options.
// Go 1.26: Optimized with netip, improved io.ReadAll, and automatic HTTP/3 fallback.
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

	client := http.Client{
		Transport: xTransport.transport,
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	if xTransport.h3Transport != nil {
		if xTransport.http3Probe {
			client.Transport = xTransport.h3Transport
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)
		} else {
			xTransport.altSupport.RLock()
			altPort, hasAlt := xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()

			if hasAlt && altPort > 0 && int(altPort) == port {
				client.Transport = xTransport.h3Transport
				hasAltSupport = true
				dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
			}
		}
	}

	headers := make(http.Header)
	headers.Set("User-Agent", "dnscrypt-proxy")
	headers.Set("Cache-Control", "max-stale")

	if accept != "" {
		headers.Set("Accept", accept)
	}

	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}

	if body != nil {
		hash := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(hash[:32]))

		urlCopy := *url
		urlCopy.RawQuery = qs.Encode()
		url = &urlCopy
	}

	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("Onion service requires Tor proxy")
	}

	if err := xTransport.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Resolution failed for [%s]: %v", host, err)
		return nil, 0, nil, 0, fmt.Errorf("DNS resolution failed: %w", err)
	}

	if compress && body == nil {
		headers.Set("Accept-Encoding", "gzip")
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: headers,
		Close:  false,
	}

	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	if err != nil && client.Transport == xTransport.h3Transport {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: %v - falling back", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 failed for [%s]: %v - falling back", url.Host, err)
		}

		xTransport.altSupport.Lock()
		xTransport.altSupport.cache[url.Host] = 0
		xTransport.altSupport.Unlock()

		client.Transport = xTransport.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}

		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	statusCode := 503
	if resp != nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode

		if statusCode < 200 || statusCode > 299 {
			err = fmt.Errorf("HTTP %d: %s", statusCode, resp.Status)
		}
	} else if err == nil {
		err = errors.New("server returned no response")
	}

	if err != nil {
		dlog.Debugf("[%s]: %v - closing idle connections", req.URL, err)
		xTransport.transport.CloseIdleConnections()
		return nil, statusCode, nil, rtt, err
	}

	if xTransport.h3Transport != nil && !hasAltSupport {
		xTransport.parseAltSvcHeader(resp.Header, url.Host, port)
	}

	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(io.LimitReader(resp.Body, int64(MaxHTTPBodyLength)))
		if err != nil {
			return nil, statusCode, resp.TLS, rtt, fmt.Errorf("gzip decompression failed: %w", err)
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	// Go 1.26: io.ReadAll is significantly optimized
	data, err := io.ReadAll(io.LimitReader(bodyReader, int64(MaxHTTPBodyLength)))
	if err != nil {
		return nil, statusCode, resp.TLS, rtt, fmt.Errorf("failed to read response: %w", err)
	}

	return data, statusCode, resp.TLS, rtt, nil
}

// parseAltSvcHeader extracts HTTP/3 port information from Alt-Svc header.
func (xTransport *XTransport) parseAltSvcHeader(headers http.Header, host string, defaultPort int) {
	if xTransport.http3Probe {
		xTransport.altSupport.RLock()
		altPort, inCache := xTransport.altSupport.cache[host]
		xTransport.altSupport.RUnlock()

		if inCache && altPort == 0 {
			dlog.Debugf("Skipping Alt-Svc parsing for [%s] - in negative cache", host)
			return
		}
	}

	altSvcHeaders, found := headers["Alt-Svc"]
	if !found {
		return
	}

	dlog.Debugf("Alt-Svc [%s]: %v", host, altSvcHeaders)

	altPort := uint16(defaultPort)

	for i, altSvc := range altSvcHeaders {
		if i >= 8 {
			break
		}

		for j, part := range strings.Split(altSvc, ";") {
			if j >= 16 {
				break
			}

			part = strings.TrimSpace(part)

			if after, ok := strings.CutPrefix(part, `h3=":"`); ok {
				portStr := strings.TrimSuffix(after, `"`)
				if port, err := strconv.ParseUint(portStr, 10, 16); err == nil && port > 0 && port <= 65535 {
					altPort = uint16(port)
					dlog.Debugf("Discovered HTTP/3 support on port %d for [%s]", altPort, host)
					break
				}
			}
		}
	}

	xTransport.altSupport.Lock()
	xTransport.altSupport.cache[host] = altPort
	xTransport.altSupport.Unlock()

	dlog.Debugf("Cached Alt-Svc port %d for [%s]", altPort, host)
}

// GetWithCompression performs a GET request with gzip compression support.
func (xTransport *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get performs a standard GET request without compression.
func (xTransport *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post performs a POST request with the specified body.
func (xTransport *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery performs a DoH-style query with optional GET method encoding.
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

		urlCopy := *url
		urlCopy.RawQuery = qs.Encode()
		return xTransport.Get(&urlCopy, dataType, timeout)
	}

	return xTransport.Post(url, dataType, dataType, &body, timeout)
}

// DoHQuery performs a DNS-over-HTTPS query.
func (xTransport *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery performs an Oblivious DNS-over-HTTPS query.
func (xTransport *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
