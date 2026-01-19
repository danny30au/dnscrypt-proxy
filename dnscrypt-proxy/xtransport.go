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
    DefaultBootstrapResolver   = "9.9.9.9:53"
    DefaultKeepAlive           = 360 * time.Second
    DefaultTimeout             = 10 * time.Second
    ResolverReadTimeout        = 2 * time.Second
    SystemResolverIPTTL        = 12 * time.Hour
    MinResolverIPTTL           = 30 * time.Minute
    ResolverIPTTLMaxJitter     = 15 * time.Minute
    ExpiredCachedIPGraceTTL    = 15 * time.Minute
    resolverRetryCount         = 3
    resolverRetryInitialBackoff = 50 * time.Millisecond
    resolverRetryMaxBackoff    = 300 * time.Millisecond
)

var resolverBackoffs = [resolverRetryCount]time.Duration{
    resolverRetryInitialBackoff,
    resolverRetryInitialBackoff * 2,
    resolverRetryMaxBackoff,
}

var bgCtx = context.Background()

type CachedIPItem struct {
    ips           []net.IP
    expiration    *time.Time
    updatingUntil *time.Time
}

type CachedIPs struct {
    sync.RWMutex
    cache  map[string]*CachedIPItem
    hits   atomic.Uint64
    misses atomic.Uint64
}

type AltSupportItem struct {
    port      uint16
    nextProbe time.Time
}

type AltSupport struct {
    sync.RWMutex
    cache map[string]AltSupportItem
}

type XTransport struct {
    sessionCache              tls.ClientSessionCache
    transport                 *http.Transport
    h3Transport               *http3.Transport
    httpClient                *http.Client
    h3Client                  *http.Client
    keepAlive                 time.Duration
    timeout                   time.Duration
    cachedIPs                 CachedIPs
    altSupport                AltSupport
    internalResolvers         []string
    bootstrapResolvers        []string
    mainProto                 string
    resolveProtos             []string
    ignoreSystemDNS           bool
    internalResolverReady     bool
    useIPv4                   bool
    useIPv6                   bool
    http3                     bool
    http3Probe                bool
    tlsDisableSessionTickets  bool
    tlsPreferRSA              bool
    proxyDialer               *netproxy.Dialer
    httpProxyFunction         func(*http.Request) (*url.URL, error)
    tlsClientCreds            DOHClientCreds
    keyLogWriter              io.Writer
    gzipPool                  sync.Pool
    dnsClientPool             sync.Pool
    dnsMessagePool            sync.Pool
    bufferPool                sync.Pool
    resolveGroup              singleflight.Group
    quicMu                    sync.Mutex
    quicUDP4                  *net.UDPConn
    quicUDP6                  *net.UDPConn
    quicTr4                   *quic.Transport
    quicTr6                   *quic.Transport
}

func NewXTransport() *XTransport {
    if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
        panic("DefaultBootstrapResolver does not parse")
    }

    xTransport := &XTransport{
        cachedIPs:              CachedIPs{cache: make(map[string]*CachedIPItem)},
        altSupport:             AltSupport{cache: make(map[string]AltSupportItem)},
        keepAlive:              DefaultKeepAlive,
        timeout:                DefaultTimeout,
        bootstrapResolvers:     []string{DefaultBootstrapResolver},
        mainProto:              "",
        resolveProtos:          protoUDPFirst,
        ignoreSystemDNS:        true,
        useIPv4:                true,
        useIPv6:                false,
        http3Probe:             false,
        tlsDisableSessionTickets: false,
        tlsPreferRSA:           false,
        keyLogWriter:           nil,
        sessionCache:           tls.NewLRUClientSessionCache(4096),
    }

    xTransport.gzipPool.New = func() any { return new(gzip.Reader) }
    xTransport.dnsClientPool.New = func() any {
        transport := dns.NewTransport()
        transport.ReadTimeout = ResolverReadTimeout
        return &dns.Client{Transport: transport}
    }
    xTransport.dnsMessagePool.New = func() any {
        return new(dns.Msg)
    }
    xTransport.bufferPool.New = func() any {
        return new(bytes.Buffer)
    }

    return xTransport
}

func ParseIP(ipStr string) net.IP {
    return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

func uniqueNormalizedIPs(ips []net.IP) []net.IP {
    if len(ips) == 0 {
        return nil
    }

    seen := make(map[string]struct{}, len(ips))
    unique := make([]net.IP, 0, len(ips))

    for _, ip := range ips {
        if ip == nil {
            continue
        }
        key := ip.String()
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

    var b strings.Builder
    if ipv4 := ip.To4(); ipv4 != nil {
        b.Grow(21)
        b.WriteString(ipv4.String())
        b.WriteByte(':')
        b.WriteString(strconv.Itoa(port))
    } else {
        b.Grow(50)
        b.WriteByte('[')
        b.WriteString(ip.String())
        b.WriteString("]:")
        b.WriteString(strconv.Itoa(port))
    }
    return b.String()
}

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
        ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
        expiration := now.Add(ttl)
        item.expiration = &expiration
    }

    xTransport.cachedIPs.Lock()
    item.updatingUntil = nil
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

func (xTransport *XTransport) markUpdatingCachedIP(host string) {
    xTransport.cachedIPs.Lock()
    item, ok := xTransport.cachedIPs.cache[host]
    if ok {
        now := time.Now()
        until := now.Add(xTransport.timeout)
        item.updatingUntil = &until
        xTransport.cachedIPs.cache[host] = item
    }
    xTransport.cachedIPs.Unlock()

    if ok {
        dlog.Debugf("[%s] IP address marked as updating", host)
    }
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
    ips = nil
    xTransport.cachedIPs.RLock()
    item, ok := xTransport.cachedIPs.cache[host]
    if !ok {
        xTransport.cachedIPs.RUnlock()
        xTransport.cachedIPs.misses.Add(1)
        dlog.Debugf("[%s] IP address not found in the cache", host)
        return nil, false, false
    }

    xTransport.cachedIPs.hits.Add(1)
    ips = item.ips
    expiration := item.expiration
    updatingUntil := item.updatingUntil
    xTransport.cachedIPs.RUnlock()

    if expiration != nil && time.Until(*expiration) < 5*time.Minute {
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
    xTransport.quicMu.Lock()
    defer xTransport.quicMu.Unlock()

    const sockBuf = 4 << 20

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

    if xTransport.mainProto == "tcp" {
        xTransport.resolveProtos = protoTCPFirst
    } else {
        xTransport.resolveProtos = protoUDPFirst
    }

    timeout := xTransport.timeout
    transport := &http.Transport{
        DisableKeepAlives:      false,
        DisableCompression:     true,
        MaxIdleConns:           2000,
        MaxIdleConnsPerHost:    100,
        MaxConnsPerHost:        100,
        IdleConnTimeout:        90 * time.Second,
        ExpectContinueTimeout:  0,
        ForceAttemptHTTP2:      true,
        MaxResponseHeaderBytes: 16 * 1024,
        DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

            cachedIPs, _, _ := xTransport.loadCachedIPs(host)
            targets := make([]string, 0, len(cachedIPs))
            for _, ip := range cachedIPs {
                if endpoint := formatEndpoint(ip, port); endpoint != "" {
                    targets = append(targets, endpoint)
                }
            }

            if len(targets) == 0 {
                dlog.Debugf("[%s] IP address was not cached in DialContext", host)
                if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
                    targets = append(targets, "["+parsed.String()+"]:"+strconv.Itoa(port))
                } else {
                    targets = append(targets, host+":"+strconv.Itoa(port))
                }
            }

            dial := func(address string) (net.Conn, error) {
                if xTransport.proxyDialer == nil {
                    dialer := &net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second, DualStack: true}
                    return dialer.DialContext(ctx, network, address)
                }
                return (*xTransport.proxyDialer).Dial(network, address)
            }

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
                        var delay time.Duration
                        if i == 1 {
                            delay = 250 * time.Millisecond
                        } else {
                            delay = 50 * time.Millisecond
                        }
                        timer := time.NewTimer(delay)
                        select {
                        case <-timer.C:
                        case <-done:
                            if !timer.Stop() {
                                <-timer.C
                            }
                            return
                        case <-dialCtx.Done():
                            if !timer.Stop() {
                                <-timer.C
                            }
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

    if h2Transport, err := http2.ConfigureTransports(transport); err == nil && h2Transport != nil {
        h2Transport.ReadIdleTimeout = 30 * time.Second
        h2Transport.PingTimeout = 5 * time.Second
        h2Transport.AllowHTTP = false
        h2Transport.StrictMaxConcurrentStreams = true
        h2Transport.MaxReadFrameSize = 256 * 1024
    }

    xTransport.transport = transport
    xTransport.httpClient = &http.Client{Transport: xTransport.transport}

    if xTransport.http3 {
        dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
            dlog.Debugf("Dialing for H3: [%v]", addrStr)
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

            type udpTarget struct {
                addr    string
                network string
            }

            buildAddr := func(ip net.IP) udpTarget {
                if ip != nil {
                    if ipv4 := ip.To4(); ipv4 != nil {
                        return udpTarget{addr: ipv4.String() + ":" + strconv.Itoa(port), network: "udp4"}
                    }
                    return udpTarget{addr: "[" + ip.String() + "]:" + strconv.Itoa(port), network: "udp6"}
                }

                network := "udp4"
                addr := host
                if parsed := ParseIP(host); parsed != nil {
                    if parsed.To4() != nil {
                        addr = parsed.String()
                    } else {
                        network = "udp6"
                        addr = "[" + parsed.String() + "]"
                    }
                } else if xTransport.useIPv6 {
                    if xTransport.useIPv4 {
                        network = "udp"
                    } else {
                        network = "udp6"
                    }
                }
                return udpTarget{addr: addr + ":" + strconv.Itoa(port), network: network}
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

        h3Transport := &http3.Transport{
            DisableCompression: true,
            TLSClientConfig:    &tlsClientConfig,
            Dial:               dial,
        }
        xTransport.h3Transport = h3Transport
        xTransport.h3Client = &http.Client{Transport: xTransport.h3Transport}
    }
}

func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
    ipa, err := net.LookupIP(host)
    if returnIPv4 && returnIPv6 {
        return ipa, SystemResolverIPTTL, err
    }

    ips := make([]net.IP, 0)
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

    results := make(chan queryResult, len(queryTypes))
    ctx, cancel := context.WithTimeout(bgCtx, ResolverReadTimeout)
    defer cancel()

    dnsClient := xTransport.dnsClientPool.Get().(*dns.Client)
    defer xTransport.dnsClientPool.Put(dnsClient)

    for _, qType := range queryTypes {
        go func(qt uint16) {
            msg := dns.NewMsg(fqdn(host), qt)
            if msg == nil {
                select {
                case results <- queryResult{ips: nil, ttl: 0, err: errors.New("failed to create DNS message")}:
                case <-ctx.Done():
                }
                return
            }

            msg.RecursionDesired = true
            msg.UDPSize = uint16(MaxDNSPacketSize)
            msg.Security = true

            var qIPs []net.IP
            var qTTL uint32

            in, _, err := dnsClient.Exchange(ctx, msg, proto, resolver)
            if err == nil && in != nil {
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

    var collectedIPs []net.IP
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
        return nil, 0, errors.New("Empty resolvers")
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
            err = errors.New("System DNS is not usable yet")
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

    if xTransport.h3Transport != nil {
        if xTransport.http3Probe {
            if xTransport.h3Client != nil {
                client = xTransport.h3Client
            }
            dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
        } else {
            xTransport.altSupport.RLock()
            item, ok := xTransport.altSupport.cache[url.Host]
            xTransport.altSupport.RUnlock()

            hasAltSupport = ok
            if ok {
                altPort := item.port
                if altPort > 0 {
                    if int(altPort) == port {
                        if xTransport.h3Client != nil {
                            client = xTransport.h3Client
                        }
                        dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
                    }
                } else if !item.nextProbe.IsZero() && time.Now().After(item.nextProbe) {
                    if xTransport.h3Client != nil {
                        client = xTransport.h3Client
                        dlog.Debugf("Retrying HTTP/3 probe for [%s]", url.Host)
                    }
                }
            }
        }
    }

    header := make(http.Header, 5)
    header.Set("User-Agent", "dnscrypt-proxy")
    header.Set("Cache-Control", "max-stale")

    if len(accept) > 0 {
        header["Accept"] = []string{accept}
    }
    if len(contentType) > 0 {
        header["Content-Type"] = []string{contentType}
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
        return nil, 0, nil, 0, errors.New("Onion service is not reachable without Tor")
    }

    if err := xTransport.resolveAndUpdateCache(host); err != nil {
        dlog.Errorf("Unable to resolve [%v] - Make sure that the system resolver works, or that `bootstrap_resolvers` has been set to resolvers that can be reached", host)
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

    if err != nil && xTransport.h3Client != nil && client == xTransport.h3Client {
        if xTransport.http3Probe {
            dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
        } else {
            dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
        }

        xTransport.altSupport.Lock()
        xTransport.altSupport.cache[url.Host] = AltSupportItem{port: 0, nextProbe: time.Now().Add(5 * time.Minute)}
        xTransport.altSupport.Unlock()

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
            item, inCache := xTransport.altSupport.cache[url.Host]
            xTransport.altSupport.RUnlock()

            if inCache && item.port == 0 {
                if item.nextProbe.IsZero() || time.Now().Before(item.nextProbe) {
                    dlog.Debugf("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", url.Host)
                    skipAltSvcParsing = true
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

                xTransport.altSupport.Lock()
                xTransport.altSupport.cache[url.Host] = AltSupportItem{port: altPort}
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

    bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
    if err != nil {
        return nil, statusCode, tlsState, rtt, err
    }

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
