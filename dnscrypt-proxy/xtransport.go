package main

import (
    "bytes"
    "compress/gzip"
    "context"
    "crypto/sha512"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "io"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/jedisct1/dlog"
    stamps "github.com/jedisct1/go-dnsstamps"
    "github.com/miekg/dns"
    "github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/http3"
    "golang.org/x/net/http2"
    netproxy "golang.org/x/net/proxy"
)

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

type CachedIPItem struct {
    ips           []net.IP
    expiration    *time.Time
    updatingUntil *time.Time
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
    tlsCipherSuite           []uint16
    proxyDialer              *netproxy.Dialer
    httpProxyFunction        func(*http.Request) (*url.URL, error)
    tlsClientCreds           DOHClientCreds
    keyLogWriter             io.Writer
}

func NewXTransport() *XTransport {
    if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
        panic("DefaultBootstrapResolver does not parse")
    }
    xTransport := XTransport{
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
        tlsCipherSuite:           nil,
        keyLogWriter:             nil,
    }
    return &xTransport
}

func ParseIP(ipStr string) net.IP {
    if len(ipStr) > 1 && ipStr[0] == '[' && ipStr[len(ipStr)-1] == ']' {
        return net.ParseIP(ipStr[1 : len(ipStr)-1])
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
        found := false
        for _, u := range unique {
            if u.Equal(ip) {
                found = true
                break
            }
        }
        if !found {
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
        if ttl < MinResolverIPTTL {
            ttl = MinResolverIPTTL
        }
        ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
        expiration := time.Now().Add(ttl)
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

// Mark an entry as being updated
func (xTransport *XTransport) markUpdatingCachedIP(host string) {
    xTransport.cachedIPs.Lock()
    item, ok := xTransport.cachedIPs.cache[host]
    if ok {
        now := time.Now()
        until := now.Add(xTransport.timeout)
        item.updatingUntil = &until
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
    if len(item.ips) > 0 {
        ips = make([]net.IP, 0, len(item.ips))
        for _, ip := range item.ips {
            if ip == nil {
                continue
            }
            ips = append(ips, append(net.IP(nil), ip...))
        }
    }
    expiration := item.expiration
    updatingUntil := item.updatingUntil
    xTransport.cachedIPs.RUnlock()
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

func (xTransport *XTransport) loadCachedIP(host string) (net.IP, bool, bool) {
    ips, expired, updating := xTransport.loadCachedIPs(host)
    if len(ips) > 0 {
        return ips[0], expired, updating
    }
    return nil, expired, updating
}

func (xTransport *XTransport) rebuildTransport() {
    dlog.Debug("Rebuilding transport")
    if xTransport.transport != nil {
        xTransport.transport.CloseIdleConnections()
    }
    timeout := xTransport.timeout
    transport := &http.Transport{
        DisableKeepAlives:      false,
        DisableCompression:     true,
        MaxIdleConns:           1,
        IdleConnTimeout:        xTransport.keepAlive,
        ResponseHeaderTimeout:  timeout,
        ExpectContinueTimeout:  timeout,
        MaxResponseHeaderBytes: 4096,
        DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
            formatEndpoint := func(ip net.IP) string {
                portStr := strconv.Itoa(port)
                if ip != nil {
                    return net.JoinHostPort(ip.String(), portStr)
                }
                return net.JoinHostPort(host, portStr)
            }

            cachedIPs, _, _ := xTransport.loadCachedIPs(host)
            targets := make([]string, 0, len(cachedIPs))
            for _, ip := range cachedIPs {
                targets = append(targets, formatEndpoint(ip))
            }
            if len(targets) == 0 {
                dlog.Debugf("[%s] IP address was not cached in DialContext", host)
                targets = append(targets, formatEndpoint(nil))
            }

            dial := func(address string) (net.Conn, error) {
                if xTransport.proxyDialer == nil {
                    dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}
                    return dialer.DialContext(ctx, network, address)
                }
                return (*xTransport.proxyDialer).Dial(network, address)
            }

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

    overrideCipherSuite := len(xTransport.tlsCipherSuite) > 0
    if xTransport.tlsDisableSessionTickets || overrideCipherSuite {
        tlsClientConfig.SessionTicketsDisabled = xTransport.tlsDisableSessionTickets
        if !xTransport.tlsDisableSessionTickets {
            tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
        }
        if overrideCipherSuite {
            tlsClientConfig.PreferServerCipherSuites = false
            tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
            compatibleSuitesCount := 0
            for _, suite := range tls.CipherSuites() {
                if suite.Insecure {
                    continue
                }
                for _, supportedVersion := range suite.SupportedVersions {
                    if supportedVersion == tls.VersionTLS12 {
                        for _, expectedSuiteID := range xTransport.tlsCipherSuite {
                            if expectedSuiteID == suite.ID {
                                compatibleSuitesCount += 1
                                break
                            }
                        }
                    }
                }
            }
            if compatibleSuitesCount != len(tls.CipherSuites()) {
                dlog.Notice("Explicit cipher suite configured - downgrading to TLS 1.2")
                tlsClientConfig.MaxVersion = tls.VersionTLS12
            }
        }
    }
    transport.TLSClientConfig = &tlsClientConfig
    if http2Transport, _ := http2.ConfigureTransports(transport); http2Transport != nil {
        http2Transport.ReadIdleTimeout = timeout
        http2Transport.AllowHTTP = false
    }
    xTransport.transport = transport
    if xTransport.http3 {
        dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
            dlog.Debugf("Dialing for H3: [%v]", addrStr)
            host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
            type udpTarget struct {
                addr    *net.UDPAddr
                network string
            }
            buildAddr := func(ip net.IP) udpTarget {
                if ip != nil {
                    if ipv4 := ip.To4(); ipv4 != nil {
                        return udpTarget{addr: &net.UDPAddr{IP: ipv4, Port: port}, network: "udp4"}
                    }
                    return udpTarget{addr: &net.UDPAddr{IP: ip, Port: port}, network: "udp6"}
                }
                network := "udp4"
                targetHost := host
                if parsed := ParseIP(host); parsed != nil {
                    if parsed.To4() != nil {
                        targetHost = parsed.String()
                    } else {
                        network = "udp6"
                        targetHost = parsed.String()
                    }
                } else if xTransport.useIPv6 {
                    if xTransport.useIPv4 {
                        network = "udp"
                    } else {
                        network = "udp6"
                    }
                }
                uAddr, _ := net.ResolveUDPAddr(network, net.JoinHostPort(targetHost, strconv.Itoa(port)))
                return udpTarget{addr: uAddr, network: network}
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
                if target.addr == nil {
                    continue
                }
                udpConn, err := net.ListenUDP(target.network, nil)
                if err != nil {
                    lastErr = err
                    if idx < len(targets)-1 {
                        dlog.Debugf("H3: failed to listen for [%s] on %s: %v", target.addr, target.network, err)
                    }
                    continue
                }
                tlsCfg.ServerName = host
                conn, err := quic.DialEarly(ctx, udpConn, target.addr, tlsCfg, cfg)
                if err != nil {
                    udpConn.Close()
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
        h3Transport := &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
        xTransport.h3Transport = h3Transport
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
    dnsClient := dns.Client{Net: proto, ReadTimeout: ResolverReadTimeout}
    queryType := make([]uint16, 0, 2)
    if returnIPv4 {
        queryType = append(queryType, dns.TypeA)
    }
    if returnIPv6 {
        queryType = append(queryType, dns.TypeAAAA)
    }
    var rrTTL uint32
    for _, rrType := range queryType {
        msg := dns.Msg{}
        msg.SetQuestion(dns.Fqdn(host), rrType)
        msg.SetEdns0(uint16(MaxDNSPacketSize), true)
        var in *dns.Msg
        if in, _, err = dnsClient.Exchange(&msg, resolver); err == nil {
            for _, answer := range in.Answer {
                if answer.Header().Rrtype == rrType {
                    switch rrType {
                    case dns.TypeA:
                        ips = append(ips, answer.(*dns.A).A)
                    case dns.TypeAAAA:
                        ips = append(ips, answer.(*dns.AAAA).AAAA)
                    }
                    rrTTL = answer.Header().Ttl
                }
            }
        }
    }
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
    var lastErr error
    for i, resolver := range resolvers {
        delay := resolverRetryInitialBackoff
        for attempt := 1; attempt <= resolverRetryCount; attempt++ {
            ips, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
            if err == nil && len(ips) > 0 {
                if i > 0 {
                    dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
                    resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
                }
                return ips, ttl, nil
            }
            if err == nil {
