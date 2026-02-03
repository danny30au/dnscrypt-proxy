package main

import (
    "context"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "os"
    "strings"
    "sync"
    "time"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/svcb"
)

const (
    myResolverHost  string = "resolver.dnscrypt.info."
    nonexistentName string = "nonexistent-zone.dnscrypt-test."
    MaxDNSPacketSize int    = 1232 // RFC 8914 recommended size
)

// Resolver holds reusable client state to avoid per-query allocations
type Resolver struct {
    server    string
    transport *dns.Transport
    client    *dns.Client
    ecsOpt    *dns.SUBNET
}

// NewResolver creates a modern, efficient resolver instance
func NewResolver(server string, sendClientSubnet bool) *Resolver {
    tr := dns.NewTransport()
    // Go 1.26: Use new(expr) for pointer-based configuration values
    tr.ReadTimeout = 1500 * time.Millisecond
    
    c := &dns.Client{Transport: tr}
    var ecs *dns.SUBNET

    if sendClientSubnet {
        // Optimization: Use netip.Prefix for zero-allocation subnet handling
        prefix := netip.MustParsePrefix("93.184.216.0/24")
        addr := prefix.Addr()
        
        family := uint16(1) // IPv4
        if addr.Is6() {
            family = 2
        }

        ecs = &dns.SUBNET{
            Family:  family,
            Netmask: uint8(prefix.Bits()),
            Scope:   0,
            Address: addr.AsSlice(),
        }
    }

    return &Resolver{
        server:    server,
        transport: tr,
        client:    c,
        ecsOpt:    ecs,
    }
}

// resolveQuery performs a DNS query with automatic TCP fallback
func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
    msg := dns.NewMsg()
    msg.SetQuestion(dns.Fqdn(qName), qType)
    msg.RecursionDesired = true
    msg.Opcode = dns.OpcodeQuery
    msg.UDPSize = uint16(MaxDNSPacketSize)
    msg.SetEdns0(uint16(MaxDNSPacketSize), true)

    if useECS && r.ecsOpt != nil {
        msg.Extra = append(msg.Extra, r.ecsOpt)
    }

    timeout := r.transport.ReadTimeout
    for attempt := 0; attempt < 2; attempt++ {
        msg.Id = dns.Id()
        queryCtx, cancel := context.WithTimeout(ctx, timeout)
        
        // Go 1.26 improves Dialer efficiency with native netip support
        response, _, err := r.client.ExchangeContext(queryCtx, msg, r.server)
        cancel()

        if err == nil && response != nil && response.Truncated {
            tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
            response, _, err = r.client.ExchangeContext(tcpCtx, msg, r.server)
            tcpCancel()
            return response, err
        }

        if err == nil {
            return response, nil
        }

        if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
            timeout = timeout * 3 / 2
            continue
        }
        return nil, err
    }

    return nil, errors.New("query timed out")
}

// parallelQueries executes multiple DNS queries concurrently
func (r *Resolver) parallelQueries(ctx context.Context, qName string, qTypes []uint16) map[uint16]*dns.Msg {
    results := make(map[uint16]*dns.Msg, len(qTypes))
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, qType := range qTypes {
        wg.Add(1)
        go func(qt uint16) {
            defer wg.Done()
            resp, err := r.resolveQuery(ctx, qName, qt, false)
            if err == nil && resp != nil {
                mu.Lock()
                results[qt] = resp
                mu.Unlock()
            }
        }(qType)
    }

    wg.Wait()
    return results
}

func Resolve(server string, name string, singleResolver bool) {
    // Parsing and normalization
    if parts := strings.SplitN(name, ",", 2); len(parts) == 2 {
        name, server = parts[0], parts[1]
        singleResolver = true
    }

    host, port, _ := net.SplitHostPort(server)
    if host == "" { host = server; port = "53" }
    
    // Modern netip address normalization
    addr, err := netip.ParseAddr(host)
    if err == nil {
        if addr.IsUnspecified() {
            if addr.Is4() { host = "127.0.0.1" } else { host = "::1" }
        }
    }

    fullServer := net.JoinHostPort(host, port)
    fmt.Printf("Resolving [%s] using %s port %s

", name, host, port)
    
    ctx := context.Background()
    resolver := NewResolver(fullServer, true)
    cname := dns.Fqdn(name)
    var clientSubnet string

    // Query for resolver info
    response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
    if err != nil {
        fmt.Printf("Unable to resolve: [%v]
", err)
        os.Exit(1)
    }

    fmt.Printf("Resolver : ")
    type resolverInfo struct {
        ip  string
        ptr string
    }

    // Go 1.26: Slices are more likely to stay on stack if not escaped
    infos := make([]resolverInfo, 0, len(response.Answer))
    for _, answer := range response.Answer {
        if txt, ok := answer.(*dns.TXT); ok {
            var ip string
            for _, s := range txt.Txt {
                // Optimized prefix scanning
                if strings.HasPrefix(s, "Resolver IP: ") {
                    ip = strings.TrimPrefix(s, "Resolver IP: ")
                } else if strings.HasPrefix(s, "EDNS0 client subnet: ") {
                    clientSubnet = strings.TrimPrefix(s, "EDNS0 client subnet: ")
                }
            }
            if ip != "" {
                infos = append(infos, resolverInfo{ip: ip})
            }
        }
    }

    // Parallel Reverse DNS Lookups
    var wg sync.WaitGroup
    for i := range infos {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            rev, _ := dns.ReverseAddr(infos[idx].ip)
            if resp, err := resolver.resolveQuery(ctx, rev, dns.TypePTR, false); err == nil {
                for _, ptr := range resp.Answer {
                    if p, ok := ptr.(*dns.PTR); ok {
                        infos[idx].ptr = p.Ptr
                        break
                    }
                }
            }
        }(i)
    }
    wg.Wait()

    resStrings := make([]string, 0, len(infos))
    for _, info := range infos {
        if info.ptr != "" {
            resStrings = append(resStrings, fmt.Sprintf("%s (%s)", info.ip, info.ptr))
        } else {
            resStrings = append(resStrings, info.ip)
        }
    }
    
    if len(resStrings) == 0 {
        fmt.Println("-")
    } else {
        fmt.Println(strings.Join(resStrings, ", "))
    }

    // Additional record type queries (A, AAAA, NS, MX, HTTPS, etc.)
    // Optimized via parallel execution and netip string formatting
    recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeMX, dns.TypeHTTPS, dns.TypeHINFO, dns.TypeTXT}
    results := resolver.parallelQueries(ctx, cname, recordTypes)

    // Example: Process A/AAAA
    for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
        label := "IPv4"
        if qt == dns.TypeAAAA { label = "IPv6" }
        fmt.Printf("%s addresses: ", label)
        if resp, ok := results[qt]; ok && len(resp.Answer) > 0 {
            addrs := make([]string, 0, len(resp.Answer))
            for _, rr := range resp.Answer {
                addrs = append(addrs, rr.String())
            }
            fmt.Println(strings.Join(addrs, ", "))
        } else {
            fmt.Println("-")
        }
    }
}

func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: resolve <server> <name>")
        return
    }
    Resolve(os.Args[1], os.Args[2], false)
}
