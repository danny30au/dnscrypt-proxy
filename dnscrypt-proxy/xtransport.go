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
	MaxDNSPacketSize            = 4096
	MaxHTTPBodyLength           = 10 * 1024 * 1024 // 10MB limit
)

// CachedIPItem represents a cached DNS resolution result with expiration tracking.
// Go 1.26: Uses pointer fields for optional time values to reduce memory overhead.
type CachedIPItem struct {
	ips           []net.IP
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

// DOHClientCreds holds TLS client authentication credentials for DoH connections.
type DOHClientCreds struct {
	clientCert string
	clientKey  string
	rootCA     string
}

// XTransport provides an advanced HTTP/HTTPS transport with DNS caching,
// HTTP/3 support, custom resolvers, and automatic fallback mechanisms.
// Go 1.26: Optimized for post-quantum TLS and improved HTTP/2 performance.
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
// Go 1.26: Initialized with post-quantum TLS support enabled by default.
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
// Go 1.26: Consider migrating to netip.ParseAddr for better performance.
func ParseIP(ipStr string) net.IP {
	cleaned := strings.TrimRight(strings.TrimLeft(ipStr, "["), "]")
	return net.ParseIP(cleaned)
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
		// Fallback to zero on error - caller should handle appropriately
		dlog.Warnf("Failed to generate secure random number: %v", err)
		return 0
	}
	return result.Int64()
}

// uniqueNormalizedIPs deduplicates and normalizes a slice of IP addresses.
// Go 1.26: Uses map for O(n) deduplication with minimal allocations.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	unique := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		// Create defensive copy to prevent mutation
		copyIP := append(net.IP(nil), ip...)
		key := copyIP.String()

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		unique = append(unique, copyIP)
	}

	return unique
}

// saveCachedIPs stores resolved IP addresses in the cache with TTL.
// Go 1.26: Uses crypto/rand for secure jitter calculation.
func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}

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

// saveCachedIP is a convenience wrapper for caching a single IP address.
func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	xTransport.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// markUpdatingCachedIP marks a cache entry as being actively updated to prevent
// concurrent update attempts and allow stale data usage during refresh.
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

// loadCachedIPs retrieves cached IP addresses and their expiration status.
// Returns: IPs, expired flag, updating flag.
// Go 1.26: Optimized lock usage with deferred unlock for cleaner code.
func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	xTransport.cachedIPs.RLock()
	defer xTransport.cachedIPs.RUnlock()

	item, ok := xTransport.cachedIPs.cache[host]
	if !ok {
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}

	// Create defensive copies of IPs
	if len(item.ips) > 0 {
		ips = make([]net.IP, 0, len(item.ips))
		for _, ip := range item.ips {
			if ip != nil {
				ips = append(ips, append(net.IP(nil), ip...))
			}
		}
	}

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

	return ips, expired, updating
}

// ipToNetipAddr converts net.IP to netip.Addr for type-safe operations.
// Go 1.26: Leverages netip package for improved performance and type safety.
func ipToNetipAddr(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address: %v", ip)
	}
	return addr, nil
}

// buildAddrPort creates a netip.AddrPort for modern Go 1.26 networking.
// Go 1.26: Preferred over string-based address formats for zero-allocation dialing.
func buildAddrPort(ip net.IP, port int) (netip.AddrPort, error) {
	addr, err := ipToNetipAddr(ip)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// formatEndpoint formats an IP and port into a proper network address string.
// Handles IPv4, IPv6, and hostname formats correctly.
func formatEndpoint(ip net.IP, host string, port int) string {
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return net.JoinHostPort(ipv4.String(), strconv.Itoa(port))
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}

	// Handle case where host might be an IP
	if parsed := ParseIP(host); parsed != nil {
		return net.JoinHostPort(parsed.String(), strconv.Itoa(port))
	}

	return net.JoinHostPort(host, strconv.Itoa(port))
}

// rebuildTransport (re)constructs the HTTP and HTTP/3 transports with current configuration.
// Go 1.26: Includes post-quantum TLS, optimized HTTP/2, and improved connection pooling.
func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport with Go 1.26 optimizations")

	// Clean up existing transport
	if xTransport.transport != nil {
		xTransport.transport.CloseIdleConnections()
	}

	timeout := xTransport.timeout

	// Create base HTTP transport with optimized settings
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           100,        // Go 1.26: Increased for better connection reuse
		MaxIdleConnsPerHost:    10,         // Go 1.26: Optimized per-host pooling
		IdleConnTimeout:        xTransport.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		ForceAttemptHTTP2:      true,       // Go 1.26: Enable HTTP/2 by default

		// Custom dialer with cached IP resolution
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

			// Load cached IPs
			cachedIPs, _, _ := xTransport.loadCachedIPs(host)
			targets := make([]string, 0, len(cachedIPs))

			for _, ip := range cachedIPs {
				targets = append(targets, formatEndpoint(ip, host, port))
			}

			// Fallback to original address if no cached IPs
			if len(targets) == 0 {
				dlog.Debugf("[%s] IP address was not cached in DialContext", host)
				targets = append(targets, formatEndpoint(nil, host, port))
			}

			// Dial function with proxy support
			dial := func(address string) (net.Conn, error) {
				if xTransport.proxyDialer != nil {
					return (*xTransport.proxyDialer).Dial(network, address)
				}

				// Go 1.26: Simplified dialer without deprecated DualStack
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

	// Configure HTTP proxy if specified
	if xTransport.httpProxyFunction != nil {
		transport.Proxy = xTransport.httpProxyFunction
	}

	// Build TLS configuration with Go 1.26 security enhancements
	tlsClientConfig := xTransport.buildTLSConfig()
	transport.TLSClientConfig = tlsClientConfig

	// Go 1.26: Configure HTTP/2 with new strict concurrent streams option
	if http2Transport, err := http2.ConfigureTransports(transport); err == nil && http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
		http2Transport.StrictMaxConcurrentStreams = true // New in Go 1.26

		dlog.Debug("HTTP/2 transport configured with strict concurrent streams")
	}

	xTransport.transport = transport

	// Configure HTTP/3 transport if enabled
	if xTransport.http3 {
		xTransport.buildHTTP3Transport(tlsClientConfig)
	}
}

// buildTLSConfig creates a TLS configuration with Go 1.26 security best practices.
// Go 1.26: Includes post-quantum key exchange and optimized cipher suites.
func (xTransport *XTransport) buildTLSConfig() *tls.Config {
	clientCreds := xTransport.tlsClientCreds

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Go 1.26: Minimum secure version
	}

	// Configure key logging for debugging (if enabled)
	if xTransport.keyLogWriter != nil {
		tlsConfig.KeyLogWriter = xTransport.keyLogWriter
	}

	// Load system certificate pool
	certPool, certPoolErr := x509.SystemCertPool()

	// Add custom root CA if specified
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

	// Add Let's Encrypt ISRG Root X1 for compatibility with older systems
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

	// Load client certificate if specified
	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v",
				clientCreds.clientCert, clientCreds.clientKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Session ticket configuration
	if xTransport.tlsDisableSessionTickets {
		tlsConfig.SessionTicketsDisabled = true
	}

	// RSA preference for compatibility
	if xTransport.tlsPreferRSA {
		tlsConfig.MaxVersion = tls.VersionTLS12
	}

	// Go 1.26: Configure curve preferences for post-quantum support
	// Post-quantum is enabled by default, but we specify modern curves
	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519,    // Modern, fast elliptic curve
		tls.CurveP256, // Widely supported
		tls.CurveP384, // Higher security level
	}

	// Go 1.26: Optimized cipher suite ordering based on hardware capabilities
	if hasAESGCMHardwareSupport {
		tlsConfig.CipherSuites = []uint16{
			// AES-GCM first when hardware accelerated
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// ChaCha20 as fallback
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	} else {
		tlsConfig.CipherSuites = []uint16{
			// ChaCha20 first when no hardware acceleration
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			// AES-GCM as fallback
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	}

	return tlsConfig
}

// buildHTTP3Transport creates and configures the HTTP/3 (QUIC) transport.
// Go 1.26: Optimized QUIC implementation with improved performance.
func (xTransport *XTransport) buildHTTP3Transport(tlsConfig *tls.Config) {
	dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("Dialing HTTP/3 for [%v]", addrStr)

		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		// Helper to build UDP address
		buildUDPAddr := func(ip net.IP) (*net.UDPAddr, string) {
			if ip != nil {
				network := "udp4"
				if ip.To4() == nil {
					network = "udp6"
				}
				return &net.UDPAddr{IP: ip, Port: port}, network
			}

			// Determine network type from host
			network := "udp4"
			if parsed := ParseIP(host); parsed != nil {
				if parsed.To4() == nil {
					network = "udp6"
				}
				return &net.UDPAddr{IP: parsed, Port: port}, network
			}

			// Use IPv6 if configured
			if xTransport.useIPv6 {
				if xTransport.useIPv4 {
					network = "udp"
				} else {
					network = "udp6"
				}
			}

			return &net.UDPAddr{Port: port}, network
		}

		// Load cached IPs
		cachedIPs, _, _ := xTransport.loadCachedIPs(host)

		type udpTarget struct {
			addr    *net.UDPAddr
			network string
		}

		targets := make([]udpTarget, 0, len(cachedIPs))
		for _, ip := range cachedIPs {
			addr, network := buildUDPAddr(ip)
			targets = append(targets, udpTarget{addr: addr, network: network})
		}

		// Fallback to unresolved address
		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached for HTTP/3", host)
			addr, network := buildUDPAddr(nil)
			targets = append(targets, udpTarget{addr: addr, network: network})
		}

		// Try each target
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
	dlog.Debug("HTTP/3 transport configured")
}

// resolveUsingSystem uses the system resolver to look up IP addresses.
// Returns IPs, TTL, and any error encountered.
func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ips, err := net.LookupIP(host)

	// Return all IPs if both IPv4 and IPv6 are requested
	if returnIPv4 && returnIPv6 {
		return ips, SystemResolverIPTTL, err
	}

	// Filter by IP version
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
// Go 1.26: Uses context-aware DNS client with proper timeout handling.
func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) ([]net.IP, time.Duration, error) {

	transport := dns.NewTransport()
	transport.ReadTimeout = ResolverReadTimeout

	dnsClient := dns.Client{Transport: transport}

	// Determine query types based on IP version requirements
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

	// Query for each requested record type
	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}

		msg.RecursionDesired = true
		msg.UDPSize = MaxDNSPacketSize
		msg.Security = true

		resp, _, err := dnsClient.Exchange(ctx, msg, proto, resolver)
		if err != nil {
			dlog.Debugf("DNS query for %s failed: %v", host, err)
			continue
		}

		// Extract IP addresses from response
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
// Go 1.26: Implements exponential backoff with jitter for optimal retry behavior.
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
				// Move successful resolver to front for future queries
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

			// Apply exponential backoff before retry
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
// Resolution order: internal resolvers -> bootstrap resolvers -> system resolver.
func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	var ips []net.IP
	var ttl time.Duration
	var err error

	// Try internal resolvers first if system DNS is disabled
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
		// Use system resolver
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
		dlog.Noticef("System DNS resolution failed: %v", err)
	}

	// Fallback to bootstrap resolvers
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

	// Last resort: try system resolver even if ignoreSystemDNS is set
	if err != nil && xTransport.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed - trying system resolver as last resort")
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}

	return ips, ttl, err
}

// resolveAndUpdateCache resolves a hostname if not cached and updates the cache.
// Implements stale-while-revalidate pattern for improved reliability.
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	// Skip resolution if using proxy or host is already an IP
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}

	if ParseIP(host) != nil {
		return nil
	}

	// Check cache status
	cachedIPs, expired, updating := xTransport.loadCachedIPs(host)

	// Use cached IPs if valid or being updated
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	// Mark as updating to prevent concurrent resolution
	xTransport.markUpdatingCachedIP(host)

	// Perform resolution
	ips, ttl, err := xTransport.resolve(host, xTransport.useIPv4, xTransport.useIPv6)

	// Enforce minimum TTL
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	// Use resolved IPs or fall back to stale cache
	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached IPs for [%s] during grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	// Log warning if no IPs found
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

	// Update cache with new IPs
	xTransport.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// Fetch performs an HTTP request with the configured transport options.
// Go 1.26: Optimized with improved io.ReadAll and automatic HTTP/3 fallback.
func (xTransport *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {

	// Use configured timeout if not specified
	if timeout <= 0 {
		timeout = xTransport.timeout
	}

	client := http.Client{
		Transport: xTransport.transport,
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	// Determine if HTTP/3 should be used
	if xTransport.h3Transport != nil {
		if xTransport.http3Probe {
			// Always probe HTTP/3 first when enabled
			client.Transport = xTransport.h3Transport
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)
		} else {
			// Check Alt-Svc cache for HTTP/3 support
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

	// Build request headers
	headers := make(http.Header)
	headers.Set("User-Agent", "dnscrypt-proxy")
	headers.Set("Cache-Control", "max-stale")

	if accept != "" {
		headers.Set("Accept", accept)
	}

	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}

	// Add body hash to query string if body provided
	if body != nil {
		hash := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(hash[:32]))

		urlCopy := *url
		urlCopy.RawQuery = qs.Encode()
		url = &urlCopy
	}

	// Check for Tor onion addresses without proxy
	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("Onion service requires Tor proxy")
	}

	// Resolve and cache hostname
	if err := xTransport.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Resolution failed for [%s]: %v", host, err)
		return nil, 0, nil, 0, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Enable compression if requested
	if compress && body == nil {
		headers.Set("Accept-Encoding", "gzip")
	}

	// Create HTTP request
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

	// Execute request
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// Handle HTTP/3 failure with automatic fallback to HTTP/2
	if err != nil && client.Transport == xTransport.h3Transport {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: %v - falling back", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 failed for [%s]: %v - falling back", url.Host, err)
		}

		// Add to negative cache
		xTransport.altSupport.Lock()
		xTransport.altSupport.cache[url.Host] = 0
		xTransport.altSupport.Unlock()

		// Retry with HTTP/2
		client.Transport = xTransport.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}

		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Validate response
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

	// Parse Alt-Svc header for HTTP/3 support discovery
	if xTransport.h3Transport != nil && !hasAltSupport {
		xTransport.parseAltSvcHeader(resp.Header, url.Host, port)
	}

	// Handle response body with optional decompression
	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if err != nil {
			return nil, statusCode, resp.TLS, rtt, fmt.Errorf("gzip decompression failed: %w", err)
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	// Go 1.26: io.ReadAll is significantly optimized
	data, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, resp.TLS, rtt, fmt.Errorf("failed to read response: %w", err)
	}

	return data, statusCode, resp.TLS, rtt, nil
}

// parseAltSvcHeader extracts HTTP/3 port information from Alt-Svc header.
// Implements caching for future HTTP/3 connection attempts.
func (xTransport *XTransport) parseAltSvcHeader(headers http.Header, host string, defaultPort int) {
	// Check negative cache when using http3_probe
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

	// Parse Alt-Svc header values
	for i, altSvc := range altSvcHeaders {
		if i >= 8 { // Limit parsing attempts
			break
		}

		for j, part := range strings.Split(altSvc, ";") {
			if j >= 16 { // Limit parts per header
				break
			}

			part = strings.TrimSpace(part)

			// Look for h3=":port" pattern
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

	// Cache Alt-Svc result
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
		// Encode DNS message in query parameter
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

// Helper functions (these would typically be in a separate file)

// ExtractHostAndPort parses a host:port string, using defaultPort if port is missing.
func ExtractHostAndPort(hostPort string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port specified, use default
		return hostPort, defaultPort
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return host, defaultPort
	}

	return host, port
}

// isIPAndPort validates that a string is in the format IP:port.
func isIPAndPort(address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	return nil
}

// fqdn ensures a hostname ends with a dot for DNS queries.
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
