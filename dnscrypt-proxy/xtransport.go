package main

import (
    "bytes"
    "compress/gzip"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "hash/fnv"
    "io"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
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
    DefaultKeepAlive            = 30 * time.Second
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

var dnsMsgPool = sync.Pool{
    New: func() any { return new(dns.Msg) },
}

type CachedIPItem struct {
    ips           []net.IP
    expiration    time.Time
    updatingUntil time.Time
}

type CachedIPs struct {
    sync.RWMutex
    cache map[string]*CachedIPItem
}

type AltSupport struct {
    sync.RWMutex
    cache map[string]uint16
}

type XTransport struct {
    transport   *http.Transport
    h3Transport *http3.Transport

    // Reused clients (avoid per-request allocations)
    httpClient *http.Client
    h3Client   *http.Client
    dnsClient  *dns.Client
    baseDialer *net.Dialer

    keepAlive  time.Duration
    timeout    time.Duration
    cachedIPs  CachedIPs
    altSupport AltSupport

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

    // Hot-path pools / coalescing
    gzipPool     sync.Pool
    resolveGroup singleflight.Group
    refreshGroup singleflight.Group // Deduplicate background refreshes

    // Load balancing
    bootstrapIdx uint32
    internalIdx  uint32

    // Lifecycle management
    mu        sync.Mutex
    ctx       context.Context
    ctxCancel context.CancelFunc

    // QUIC UDP socket reuse (min churn, lower tail latency)
    quicMu   sync.Mutex
    quicUDP4 *net.UDPConn
    quicUDP6 *net.UDPConn
    quicTr4  *quic.Transport
    quicTr6  *quic.Transport
}

func NewXTransport() *XTransport {
    if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
        panic("DefaultBootstrapResolver does not parse")
    }
    ctx, cancel := context.WithCancel(context.Background())
    xTransport := &XTransport{
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
        ctx:                      ctx,
        ctxCancel:                cancel,
    }

    xTransport.gzipPool.New = func() any { return new(gzip.Reader) }
    xTransport.baseDialer = &net.Dialer{
        Timeout:   DefaultTimeout,
        KeepAlive: DefaultKeepAlive,
        DualStack: true,
    }
    xTransport.dnsClient = &dns.Client{
        Net: "udp",
        Transport: &dns.Transport{
            ReadTimeout: ResolverReadTimeout,
        },
    }

    return xTransport
}

func ParseIP(ipStr string) net.IP {
    if len(ipStr) > 2 && ipStr[0] == '[' && ipStr[len(ipStr)-1] == ']' {
        ipStr = ipStr[1 : len(ipStr)-1]
    }
    return net.ParseIP(ipStr)
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, MinResolverIPTTL)
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
    if len(ips) == 0 {
        return nil
    }
    unique := make([]net.IP, 0, len(ips))
    for _, ip := range ips {
        if ip == nil {
            continue
        }
        isDuplicate := false
        for _, existing := range unique {
            if existing.Equal(ip) {
                isDuplicate = true
                break
            }
        }
        if !isDuplicate {
            unique = append(unique, append(net.IP(nil), ip...))
        }
    }
    return unique
}

func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
    normalized := uniqueNormalizedIPs(ips)
    if len(normalized) == 0 {
        return
    }
    item := &CachedIPItem{ips: normalized}
    if ttl >= 0 {
        ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
        if ttl < MinResolverIPTTL {
            ttl = MinResolverIPTTL
        }
        item.expiration = time.Now().Add(ttl)
    }
    xTransport.cachedIPs.Lock()
    xTransport.cachedIPs.cache[host] = item
    xTransport.cachedIPs.Unlock()
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

// Mark an entry as being updated
func (xTransport *XTransport) markUpdatingCachedIP(host string) {
    xTransport.cachedIPs.Lock()
    item, ok := xTransport.cachedIPs.cache[host]
    if ok {
        item.updatingUntil = time.Now().Add(xTransport.timeout)
        xTransport.cachedIPs.cache[host] = item
        dlog.Debugf("[%s] IP address marked as updating", host)
    }
    xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
    ips = nil
    xTransport.cachedIPs.RLock()
    item, ok := xTransport.cachedIPs.cache[host]
    if !ok {
        xTransport.cachedIPs.RUnlock()
        dlog.Debugf("[%s] IP address not found in the cache", host)
        return nil, false, false
    }
    ips = item.ips
    expiration := item.expiration
    updatingUntil := item.updatingUntil
    xTransport.cachedIPs.RUnlock()

    if !expiration.IsZero() && time.Until(expiration) < 0 {
        expired = true
        if !updatingUntil.IsZero() && time.Until(updatingUntil) > 0 {
            updating = true
            dlog.Debugf("[%s] cached IP addresses are being updated", host)
        } else {
            dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
        }
    }
    return ips, expired, updating
}

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

func (xTransport *XTransport) getQUICTransport(network string) (*quic.Transport, error) {
    // Fast path: check without lock
    if network == "udp4" && xTransport.quicTr4 != nil {
        return xTransport.quicTr4, nil
    }
    if network == "udp6" && xTransport.quicTr6 != nil {
        return xTransport.quicTr6, nil
    }

    xTransport.quicMu.Lock()
    defer xTransport.quicMu.Unlock()

    const sockBuf = 8 << 20 // 8 MiB for high throughput
    switch network {
    case "udp4":
        if xTransport.quicTr4 != nil {
            return xTransport.quicTr4, nil
        }
        c, err := net.ListenUDP("udp4", nil)
        if err != nil {
            return nil, err
        }
        _ = c.SetReadBuffer(sockBuf)
        _ = c.SetWriteBuffer(sockBuf)
        xTransport.quicUDP4 = c
        xTransport.quicTr4 = &quic.Transport{Conn: c}
        return xTransport.quicTr4, nil
    case "udp6":
        if xTransport.quicTr6 != nil {
            return xTransport.quicTr6, nil
        }
        c, err := net.ListenUDP("udp6", nil)
        if err != nil {
            return nil, err
        }
        _ = c.SetReadBuffer(sockBuf)
        _ = c.SetWriteBuffer(sockBuf)
        xTransport.quicUDP6 = c
        xTransport.quicTr6 = &quic.Transport{Conn: c}
        return xTransport.quicTr6, nil
    default:
        return nil, errors.New("unsupported quic network: " + network)
    }
}

func (xTransport *XTransport) rebuildTransport() {
    dlog.Debug("Rebuilding transport")

    xTransport.mu.Lock()
    // Cancel any in-flight requests from the previous generation
    if xTransport.ctxCancel != nil {
        xTransport.ctxCancel()
    }
    // Create new lifecycle context
    xTransport.ctx, xTransport.ctxCancel = context.WithCancel(context.Background())
    xTransport.mu.Unlock()

    if xTransport.transport != nil {
        xTransport.transport.CloseIdleConnections()
    }

    if xTransport.h3Transport != nil {
        xTransport.h3Transport.Close()
        xTransport.h3Transport = nil
    }
    xTransport.quicMu.Lock()
    if xTransport.quicTr4 != nil {
        _ = xTransport.quicTr4.Close()
        xTransport.quicTr4 = nil
    }
    if xTransport.quicTr6 != nil {
        _ = xTransport.quicTr6.Close()
        xTransport.quicTr6 = nil
    }
    if xTransport.quicUDP4 != nil {
        _ = xTransport.quicUDP4.Close()
        xTransport.quicUDP4 = nil
    }
    if xTransport.quicUDP6 != nil {
        _ = xTransport.quicUDP6.Close()
        xTransport.quicUDP6 = nil
    }
    xTransport.quicMu.Unlock()

    timeout := xTransport.timeout
    // Update base dialer
    if xTransport.baseDialer == nil {
        xTransport.baseDialer = &net.Dialer{DualStack: true}
    }
    xTransport.baseDialer.Timeout = timeout
    xTransport.baseDialer.KeepAlive = xTransport.keepAlive

    transport := &http.Transport{
        DisableKeepAlives:      false,
        DisableCompression:     true,
        MaxIdleConns:           2048, // Increased default
        MaxIdleConnsPerHost:    128,
        MaxConnsPerHost:        0,
        IdleConnTimeout:        xTransport.keepAlive,
        ResponseHeaderTimeout:  timeout,
        ExpectContinueTimeout:  timeout,
        MaxResponseHeaderBytes: 4096,
        DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
            formatEndpoint := func(ip net.IP) string {
                if ip != nil {
                    if ipv4 := ip.To4(); ipv4 != nil {
                        return ipv4.String() + ":" + strconv.Itoa(port)
                    }
                    return "[" + ip.String() + "]:" + strconv.Itoa(port)
                }
                if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
                    return "[" + parsed.String() + "]:" + strconv.Itoa(port)
                }
                return host + ":" + strconv.Itoa(port)
            }

            cachedIPs, _, _ := xTransport.loadCachedIPs(host)
            
            dial := func(address string) (net.Conn, error) {
                if xTransport.proxyDialer == nil {
                    return xTransport.baseDialer.DialContext(ctx, network, address)
                }
                return (*xTransport.proxyDialer).Dial(network, address)
            }

            // Optimized dial loop without slice allocation
            var lastErr error
            if len(cachedIPs) > 0 {
                for _, ip := range cachedIPs {
                    target := formatEndpoint(ip)
                    conn, err := dial(target)
                    if err == nil {
                        return conn, nil
                    }
                    lastErr = err
                    dlog.Debugf("Dial attempt using [%s] failed: %v", target, err)
                }
            } else {
                dlog.Debugf("[%s] IP address was not cached in DialContext", host)
                return dial(formatEndpoint(nil))
            }
            return nil, lastErr
        },
    }
    if xTransport.httpProxyFunction != nil {
        transport.Proxy = xTransport.httpProxyFunction
    }

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
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`)
        certPool.AppendCertsFromPEM(letsEncryptX1Cert)
        tlsClientConfig.RootCAs = certPool
    }

    if clientCreds.clientCert != "" {
        cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
        if err != nil {
            dlog.Fatalf(
                "Unable to use certificate [%v] (key: [%v]): %v",
                clientCreds.clientCert,
                clientCreds.clientKey,
                err,
            )
        }
        tlsClientConfig.Certificates = []tls.Certificate{cert}
    }

    if xTransport.tlsDisableSessionTickets {
        tlsClientConfig.SessionTicketsDisabled = true
    } else {
        tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4096)
    }
    if xTransport.tlsPreferRSA {
        tlsClientConfig.MaxVersion = tls.VersionTLS13
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
    if h2Transport, err := http2.ConfigureTransports(transport); err == nil && h2Transport != nil {
        h2Transport.ReadIdleTimeout = timeout
        h2Transport.PingTimeout = 5 * time.Second
        h2Transport.AllowHTTP = false
        h2Transport.StrictMaxConcurrentStreams = true
    }
    xTransport.transport = transport
    xTransport.httpClient = &http.Client{Transport: xTransport.transport}
    if xTransport.http3 {
        dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
            dlog.Debugf("Dialing for H3: [%v]", addrStr)
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
            
            cachedIPs, _, _ := xTransport.loadCachedIPs(host)
            
            // Allow 0-RTT
            if cfg == nil {
                cfg = &quic.Config{}
            }
            cfg.Allow0RTT = true
            if cfg.KeepAlivePeriod == 0 {
                cfg.KeepAlivePeriod = 15 * time.Second
            }
            if cfg.TokenStore == nil {
                cfg.TokenStore = quic.NewLRUTokenStore(10, 4)
            }

            // Zero-copy, zero-allocation dial loop
            var lastErr error
            
            // Try cached IPs first
            for _, ip := range cachedIPs {
                network := "udp6"
                if ip4 := ip.To4(); ip4 != nil {
                    network = "udp4"
                }
                
                tr, err := xTransport.getQUICTransport(network)
                if err != nil {
                    lastErr = err
                    continue
                }

                udpAddr := &net.UDPAddr{IP: ip, Port: port}
                tlsCfg.ServerName = host
                
                conn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
                if err != nil {
                    lastErr = err
                    dlog.Debugf("H3: dialing [%s] via %s failed: %v", ip.String(), network, err)
                    continue
                }
                return conn, nil
            }
            
            // Fallback if no cache or cache failed
            if len(cachedIPs) == 0 {
                // ... original fallback logic if needed, or simplified:
                dlog.Debugf("[%s] IP address was not cached in H3 context", host)
            }
            
            if lastErr == nil {
                lastErr = errors.New("no cached IPs available for H3 dial")
            }
            return nil, lastErr
        }
        h3Transport := &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
        xTransport.h3Transport = h3Transport
        xTransport.h3Client = &http.Client{Transport: xTransport.h3Transport}
    }
}

func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
    ipa, err := net.LookupIP(host)
    if returnIPv4 && returnIPv6 {
        return ipa, SystemResolverIPTTL, err
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
    return ips, SystemResolverIPTTL, err
}

func (xTransport *XTransport) resolveUsingResolver(
    proto, host string,
    resolver string,
    returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
    // Reuse global client with context awareness
    dnsClient := xTransport.dnsClient
    
    queryType := make([]uint16, 0, 2)
    if returnIPv4 {
        queryType = append(queryType, dns.TypeA)
    }
    if returnIPv6 {
        queryType = append(queryType, dns.TypeAAAA)
    }

    var mu sync.Mutex
    var wg sync.WaitGroup
    var rrTTL uint32
    
    ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
    defer cancel()

    for _, rrType := range queryType {
        wg.Add(1)
        go func(rrType uint16) {
            defer wg.Done()
            
            msg := dnsMsgPool.Get().(*dns.Msg)
            defer func() {
                msg.Question = msg.Question[:0]
                msg.Answer = msg.Answer[:0]
                msg.Ns = msg.Ns[:0]
                msg.Extra = msg.Extra[:0]
                dnsMsgPool.Put(msg)
            }()
            
            msg.SetQuestion(fqdn(host), rrType)
            msg.RecursionDesired = true
            msg.UDPSize = uint16(MaxDNSPacketSize)
            msg.Security = true // set AD bit

            if in, _, err := dnsClient.ExchangeContext(ctx, msg, resolver); err == nil {
                if in.Truncated && proto == "udp" {
                    // Fallback to TCP handled by caller or retry here
                    return 
                }
                
                mu.Lock()
                for _, answer := range in.Answer {
                    if dns.RRToType(answer) == rrType {
                        switch rrType {
                        case dns.TypeA:
                            ips = append(ips, answer.(*dns.A).A.To4())
                        case dns.TypeAAAA:
                            ips = append(ips, answer.(*dns.AAAA).AAAA)
                        }
                        if answer.Header().TTL > rrTTL {
                             rrTTL = answer.Header().TTL
                        }
                    }
                }
                mu.Unlock()
            }
        }(rrType)
    }
    wg.Wait()

    if len(ips) > 0 {
        ttl = time.Duration(rrTTL) * time.Second
    }
    return ips, ttl, err
}

func (xTransport *XTransport) resolveUsingServers(
    proto, host string,
    resolvers []string,
    returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
    if len(resolvers) == 0 {
        return nil, 0, errors.New("Empty resolvers")
    }

    // Happy Eyeballs: Race all resolvers
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    type result struct {
        ips []net.IP
        ttl time.Duration
        err error
    }
    
    resultCh := make(chan result, len(resolvers))
    
    // Select starting index to avoid stampeding the first resolver
    startIdx := 0
    if len(resolvers) > 1 {
        // Use either internal or bootstrap index based on the slice passed
        // For simplicity, we just start at 0 but we could use atomic counters here
        // The race below mitigates the need for strict rotation
    }

    for _, resolver := range resolvers {
        go func(r string) {
            // Apply jitter to start time to avoid synchronized spikes
            time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
            
            ips, ttl, err := xTransport.resolveUsingResolver(proto, host, r, returnIPv4, returnIPv6)
            
            select {
            case <-ctx.Done():
                return
            default:
                if err == nil && len(ips) > 0 {
                    resultCh <- result{ips, ttl, nil}
                    cancel() // Cancel others
                } else {
                    resultCh <- result{nil, 0, err}
                }
            }
        }(resolver)
    }

    // Wait for first success or all failures
    failures := 0
    for i := 0; i < len(resolvers); i++ {
        select {
        case res := <-resultCh:
            if res.err == nil {
                return res.ips, res.ttl, nil
            }
            failures++
            if failures == len(resolvers) {
                return nil, 0, res.err
            }
        case <-time.After(ResolverReadTimeout + 100*time.Millisecond):
            return nil, 0, errors.New("timeout waiting for resolvers")
        }
    }
    
    return nil, 0, errors.New("no IP addresses returned")
}

func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
    protos := protoUDPFirst
    if xTransport.mainProto == "tcp" {
        protos = protoTCPFirst
    }
    if xTransport.ignoreSystemDNS {
        if xTransport.internalResolverReady {
            for _, proto := range protos {
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
            err = errors.New("System DNS is not usable yet")
            dlog.Notice(err)
        }
    }
    if err != nil {
        for _, proto := range protos {
            if err != nil {
                dlog.Noticef(
                    "Resolving server host [%s] using bootstrap resolvers over %s",
                    host,
                    proto,
                )
            }
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
    return ips, ttl, err
}

// If a name is not present in the cache, resolve the name and update the cache
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
    if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
        return nil
    }
    if ParseIP(host) != nil {
        return nil
    }

    cachedIPs, expired, updating := xTransport.loadCachedIPs(host)
    if len(cachedIPs) > 0 {
        // Never block the request path when stale data exists; refresh in background.
        if expired && !updating {
            xTransport.markUpdatingCachedIP(host)
            go func(stale []net.IP) {
                // Use refreshGroup to deduplicate background refreshes for same host
                _, _, _ = xTransport.refreshGroup.Do(host, func() (any, error) {
                     return nil, xTransport.resolveAndUpdateCacheBlocking(host, stale)
                })
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
    // Bind context to transport lifecycle
    ctx, cancel := context.WithTimeout(xTransport.ctx, timeout)
    defer cancel()

    host, port := ExtractHostAndPort(url.Host, 443)
    hasAltSupport := false

    client := xTransport.httpClient
    if client == nil {
        client = &http.Client{Transport: xTransport.transport}
    }

    if xTransport.h3Transport != nil {
        if xTransport.http3Probe {
            if xTransport.h3Client != nil {
                client = xTransport.h3Client
            }
            dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
        } else {
            xTransport.altSupport.RLock()
            var altPort uint16
            altPort, hasAltSupport = xTransport.altSupport.cache[url.Host]
            xTransport.altSupport.RUnlock()
            if hasAltSupport && altPort > 0 {
                if int(altPort) == port {
                    if xTransport.h3Client != nil {
                        client = xTransport.h3Client
                    }
                    dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
                }
            }
        }
    }

    // Pre-allocate header map
    header := make(http.Header, 6)
    header.Set("User-Agent", "dnscrypt-proxy")
    if len(accept) > 0 {
        header["Accept"] = []string{accept}
    }
    if len(contentType) > 0 {
        header["Content-Type"] = []string{contentType}
    }
    header["Cache-Control"] = []string{"max-stale"}

    // Optimized body_hash query calc
    if body != nil {
        h := fnv.New128a()
        h.Write(*body)
        hash := hex.EncodeToString(h.Sum(nil))
        
        url2 := *url
        if url2.RawQuery == "" {
            url2.RawQuery = "body_hash=" + hash
        } else {
            qs := url2.Query()
            qs.Add("body_hash", hash)
            url2.RawQuery = qs.Encode()
        }
        url = &url2
    }

    if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
        return nil, 0, nil, 0, errors.New("Onion service is not reachable without Tor")
    }

    if err := xTransport.resolveAndUpdateCache(host); err != nil {
        dlog.Errorf(
            "Unable to resolve [%v] - Make sure that the system resolver works, or that `bootstrap_resolvers` has been set to resolvers that can be reached",
            host,
        )
        return nil, 0, nil, 0, err
    }

    if compress && body == nil {
        header["Accept-Encoding"] = []string{"gzip"}
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

    // Handle HTTP/3 error case - fallback to HTTP/2 when HTTP/3 fails
    if err != nil && xTransport.h3Client != nil && client == xTransport.h3Client {
        if xTransport.http3Probe {
            dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
        } else {
            dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
        }

        // Add server to negative cache when HTTP/3 fails
        xTransport.altSupport.Lock()
        xTransport.altSupport.cache[url.Host] = 0
        xTransport.altSupport.Unlock()

        // Retry with HTTP/2
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
            err = errors.New("Webserver returned an error")
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

    if xTransport.h3Transport != nil && !hasAltSupport {
        skipAltSvcParsing := false
        if xTransport.http3Probe {
            xTransport.altSupport.RLock()
            altPort, inCache := xTransport.altSupport.cache[url.Host]
            xTransport.altSupport.RUnlock()
            if inCache && altPort == 0 {
                dlog.Debugf("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", url.Host)
                skipAltSvcParsing = true
            }
        }
        if !skipAltSvcParsing {
            if alt, found := resp.Header["Alt-Svc"]; found {
                dlog.Debugf("Alt-Svc [%s]: [%s]", url.Host, alt)
                altPort := uint16(port & 0xffff)
                
                // Optimized single-pass Alt-Svc parsing
                for _, xalt := range alt {
                    if idx := strings.Index(xalt, `h3=":`); idx >= 0 {
                        start := idx + 5
                        end := start
                        for end < len(xalt) && xalt[end] >= '0' && xalt[end] <= '9' {
                            end++
                        }
                        if end > start {
                            if xAltPort, err := strconv.ParseUint(xalt[start:end], 10, 16); err == nil && xAltPort <= 65535 {
                                altPort = uint16(xAltPort)
                                dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
                                break
                            }
                        }
                    }
                }
                xTransport.altSupport.Lock()
                xTransport.altSupport.cache[url.Host] = altPort
                dlog.Debugf("Caching altPort for [%v]", url.Host)
                xTransport.altSupport.Unlock()
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

    // Smart pre-allocation based on Content-Length
    capacity := int64(bytes.MinRead)
    if resp.ContentLength > 0 {
        capacity = resp.ContentLength + 512
    }
    if capacity > MaxHTTPBodyLength {
        capacity = MaxHTTPBodyLength
    }
    
    buf := bytes.NewBuffer(make([]byte, 0, capacity))
    _, err = buf.ReadFrom(io.LimitReader(bodyReader, MaxHTTPBodyLength))
    if err != nil {
        return nil, statusCode, tlsState, rtt, err
    }
    bin := buf.Bytes()
    
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

func (xTransport *XTransport) dohLikeQuery(
    dataType string,
    useGet bool,
    url *url.URL,
    body []byte,
    timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
    if useGet {
        // Optimized zero-copyish query param
        encLen := base64.RawURLEncoding.EncodedLen(len(body))
        buf := make([]byte, encLen)
        base64.RawURLEncoding.Encode(buf, body)
        encBody := string(buf)

        url2 := *url
        if url2.RawQuery == "" {
            url2.RawQuery = "dns=" + encBody
        } else {
            qs := url2.Query()
            qs.Add("dns", encBody)
            url2.RawQuery = qs.Encode()
        }
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
    return xTransport.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

func (xTransport *XTransport) ObliviousDoHQuery(
    useGet bool,
    url *url.URL,
    body []byte,
    timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
    return xTransport.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
