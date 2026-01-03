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
    myResolverHost   string = "resolver.dnscrypt.info."
    nonexistentName  string = "nonexistent-zone.dnscrypt-test."
    MaxDNSPacketSize        = 4096
    MaxConcurrency          = 32
)

// MsgPool reuses dns.Msg objects to reduce GC pressure
var msgPool = sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}

// Resolver holds reusable client state
type Resolver struct {
    server    string
    transport *dns.Transport
    client    *dns.Client
    ecsOpt    *dns.SUBNET
}

// NewResolver creates a reusable resolver instance
func NewResolver(server string, sendClientSubnet bool) *Resolver {
    tr := dns.NewTransport()
    tr.ReadTimeout = 1500 * time.Millisecond

    c := &dns.Client{
        Transport:      tr,
        SingleInflight: true,
    }

    var ecs *dns.SUBNET
    if sendClientSubnet {
        subnet := net.IPNet{IP: net.IPv4(93, 184, 216, 0), Mask: net.CIDRMask(24, 32)}
        bits, totalSize := subnet.Mask.Size()
        var family uint16
        if totalSize == 32 {
            family = 1
        } else if totalSize == 128 {
            family = 2
        }
        addr, _ := netip.AddrFromSlice(subnet.IP)
        ecs = &dns.SUBNET{
            Family:  family,
            Netmask: uint8(bits),
            Scope:   0,
            Address: addr,
        }
    }

    return &Resolver{
        server:    server,
        transport: tr,
        client:    c,
        ecsOpt:    ecs,
    }
}

// resolveQuery performs a DNS query with object reuse and TCP fallback
func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
    msg := msgPool.Get().(*dns.Msg)
    defer func() {
        msg.Id = 0
        msg.Response = false
        msg.Opcode = 0
        msg.Authoritative = false
        msg.Truncated = false
        msg.RecursionDesired = false
        msg.RecursionAvailable = false
        msg.Zero = false
        msg.AuthenticatedData = false
        msg.CheckingDisabled = false
        msg.Question = nil
        msg.Answer = nil
        msg.Ns = nil
        msg.Extra = nil
        msgPool.Put(msg)
    }()

    msg.SetQuestion(qName, qType)
    msg.RecursionDesired = true
    msg.Opcode = dns.OpcodeQuery
    msg.SetEdns0(uint16(MaxDNSPacketSize), true)

    if useECS && r.ecsOpt != nil {
        msg.Pseudo = append(msg.Pseudo, r.ecsOpt)
    }

    timeout := r.transport.ReadTimeout

    for attempt := 0; attempt < 2; attempt++ {
        msg.Id = dns.Id()
        
        queryCtx, cancel := context.WithTimeout(ctx, timeout)
        response, _, err := r.client.ExchangeContext(queryCtx, msg, r.server)
        cancel()

        if err == nil && response != nil && response.Truncated {
            tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
            // Force standard TCP exchange on truncation
            response, _, err = dns.ExchangeContext(tcpCtx, msg, r.server)
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
    return nil, errors.New("timeout")
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
    parts := strings.SplitN(name, ",", 2)
    if len(parts) == 2 {
        name, server = parts[0], parts[1]
        singleResolver = true
    }

    host, port := ExtractHostAndPort(server, 53)
    if host == "0.0.0.0" {
        host = "127.0.0.1"
    } else if host == "[::]" {
        host = "[::1]"
    }
    server = fmt.Sprintf("%s:%d", host, port)

    fmt.Printf("Resolving [%s] using %s port %d

", name, host, port)
    name = dns.Fqdn(name)

    ctx := context.Background()
    resolver := NewResolver(server, true)

    cname := name
    var clientSubnet string

    for once := true; once; once = false {
        response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
        if err != nil {
            fmt.Printf("Unable to resolve: [%s]
", err)
            os.Exit(1)
        }
        fmt.Printf("Resolver      : ")

        type resolverInfo struct {
            ip  string
            ptr string
        }

        infos := make([]resolverInfo, 0, len(response.Answer))

        for _, answer := range response.Answer {
            if answer.Header().Class != dns.ClassINET || answer.Header().Rrtype != dns.TypeTXT {
                continue
            }
            if txt, ok := answer.(*dns.TXT); ok {
                for _, t := range txt.Txt {
                    if strings.HasPrefix(t, "Resolver IP: ") {
                        infos = append(infos, resolverInfo{ip: strings.TrimPrefix(t, "Resolver IP: ")})
                    } else if strings.HasPrefix(t, "EDNS0 client subnet: ") {
                        clientSubnet = strings.TrimPrefix(t, "EDNS0 client subnet: ")
                    }
                }
            }
        }

        sem := make(chan struct{}, MaxConcurrency)
        var wg sync.WaitGroup
        var mu sync.Mutex

        for i := range infos {
            rev, err := reverseAddr(infos[i].ip)
            if err != nil {
                continue
            }
            
            wg.Add(1)
            sem <- struct{}{}
            
            go func(idx int, revAddr string) {
                defer wg.Done()
                defer func() { <-sem }()

                if resp, err := resolver.resolveQuery(ctx, revAddr, dns.TypePTR, false); err == nil {
                    for _, answer := range resp.Answer {
                        if ptr, ok := answer.(*dns.PTR); ok {
                            mu.Lock()
                            infos[idx].ptr = ptr.Ptr
                            mu.Unlock()
                            break
                        }
                    }
                }
            }(i, rev)
        }
        wg.Wait()

        res := make([]string, 0, len(infos))
        for _, info := range infos {
            if info.ptr != "" {
                res = append(res, info.ip+" ("+info.ptr+")")
            } else {
                res = append(res, info.ip)
            }
        }

        if len(res) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(res, ", "))
        }
    }

    if singleResolver {
        for once := true; once; once = false {
            fmt.Printf("Lying         : ")
            response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
            if err != nil {
                fmt.Printf("[%v]", err)
                break
            }
            if response.Rcode == dns.RcodeSuccess {
                fmt.Println("yes. That resolver returns wrong responses")
            } else if response.Rcode == dns.RcodeNameError {
                fmt.Println("no")
            } else {
                fmt.Printf("unknown - query returned %s
", dns.RcodeToString[response.Rcode])
            }

            if response.Rcode == dns.RcodeNameError {
                fmt.Printf("DNSSEC        : ")
                if response.AuthenticatedData {
                    fmt.Println("yes, the resolver supports DNSSEC")
                } else {
                    fmt.Println("no, the resolver doesn't support DNSSEC")
                }
            }

            fmt.Printf("ECS           : ")
            if clientSubnet != "" {
                fmt.Println("client network address is sent to authoritative servers")
            } else {
                fmt.Println("ignored or selective")
            }
        }
    }

    fmt.Println("")

    cname:
    for once := true; once; once = false {
        fmt.Printf("Canonical name: ")
        for i := 0; i < 10; i++ {
            response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
            if err != nil {
                break cname
            }
            found := false
            for _, answer := range response.Answer {
                if answer.Header().Rrtype != dns.TypeCNAME || answer.Header().Class != dns.ClassINET {
                    continue
                }
                if cn, ok := answer.(*dns.CNAME); ok {
                    cname = cn.Target
                    found = true
                    break
                }
            }
            if !found {
                break
            }
        }
        fmt.Println(cname)
    }

    fmt.Println("")

    ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

    fmt.Printf("IPv4 addresses: ")
    if resp, ok := ipQueries[dns.TypeA]; ok {
        ipv4 := make([]string, 0, len(resp.Answer))
        for _, answer := range resp.Answer {
            if answer.Header().Rrtype == dns.TypeA && answer.Header().Class == dns.ClassINET {
                if a, ok := answer.(*dns.A); ok {
                    ipv4 = append(ipv4, a.A.String())
                }
            }
        }
        if len(ipv4) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(ipv4, ", "))
        }
    } else {
        fmt.Println("-")
    }

    fmt.Printf("IPv6 addresses: ")
    if resp, ok := ipQueries[dns.TypeAAAA]; ok {
        ipv6 := make([]string, 0, len(resp.Answer))
        for _, answer := range resp.Answer {
            if answer.Header().Rrtype == dns.TypeAAAA && answer.Header().Class == dns.ClassINET {
                if aaaa, ok := answer.(*dns.AAAA); ok {
                    ipv6 = append(ipv6, aaaa.AAAA.String())
                }
            }
        }
        if len(ipv6) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(ipv6, ", "))
        }
    } else {
        fmt.Println("-")
    }

    fmt.Println("")

    recordQueries := resolver.parallelQueries(ctx, cname, []uint16{
        dns.TypeNS, dns.TypeMX, dns.TypeHTTPS, dns.TypeHINFO, dns.TypeTXT,
    })

    fmt.Printf("Name servers  : ")
    if response, ok := recordQueries[dns.TypeNS]; ok {
        nss := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeNS && answer.Header().Class == dns.ClassINET {
                if ns, ok := answer.(*dns.NS); ok {
                    nss = append(nss, ns.Ns)
                }
            }
        }
        if response.Rcode == dns.RcodeNameError {
            fmt.Println("name does not exist")
        } else if response.Rcode != dns.RcodeSuccess {
            fmt.Printf("server returned %s", dns.RcodeToString[response.Rcode])
        } else if len(nss) == 0 {
            fmt.Println("no name servers found")
        } else {
            fmt.Println(strings.Join(nss, ", "))
        }
        fmt.Printf("DNSSEC signed : ")
        if response.AuthenticatedData {
            fmt.Println("yes")
        } else {
            fmt.Println("no")
        }
    } else {
        fmt.Println("-")
        fmt.Printf("DNSSEC signed : -
")
    }

    fmt.Printf("Mail servers  : ")
    if response, ok := recordQueries[dns.TypeMX]; ok {
        mxs := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeMX && answer.Header().Class == dns.ClassINET {
                if mx, ok := answer.(*dns.MX); ok {
                    mxs = append(mxs, mx.Mx)
                }
            }
        }
        if len(mxs) == 0 {
            fmt.Println("no mail servers found")
        } else if len(mxs) > 1 {
            fmt.Printf("%d mail servers found
", len(mxs))
        } else {
            fmt.Println("1 mail server found")
        }
    } else {
        fmt.Println("-")
    }

    fmt.Println("")

    fmt.Printf("HTTPS alias   : ")
    if response, ok := recordQueries[dns.TypeHTTPS]; ok {
        aliases := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
                if https, ok := answer.(*dns.HTTPS); ok {
                    if https.Priority == 0 && len(https.Target) >= 2 {
                        aliases = append(aliases, https.Target)
                    }
                }
            }
        }
        if len(aliases) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(aliases, ", "))
        }

        fmt.Printf("HTTPS info    : ")
        info := make([]string, 0, len(response.Answer)*2)
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
                if https, ok := answer.(*dns.HTTPS); ok {
                    if https.Priority != 0 || len(https.Target) <= 1 {
                        for _, value := range https.Value {
                            info = append(info, fmt.Sprintf("[%s]=[%s]", svcb.KeyToString(svcb.PairToKey(value)), value.String()))
                        }
                    }
                }
            }
        }
        if len(info) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(info, ", "))
        }
    } else {
        fmt.Println("-")
        fmt.Printf("HTTPS info    : -
")
    }

    fmt.Println("")

    fmt.Printf("Host info     : ")
    if response, ok := recordQueries[dns.TypeHINFO]; ok {
        hinfo := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeHINFO && answer.Header().Class == dns.ClassINET {
                if hi, ok := answer.(*dns.HINFO); ok {
                    hinfo = append(hinfo, fmt.Sprintf("%s %s", hi.Cpu, hi.Os))
                }
            }
        }
        if len(hinfo) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(hinfo, ", "))
        }
    } else {
        fmt.Println("-")
    }

    fmt.Printf("TXT records   : ")
    if response, ok := recordQueries[dns.TypeTXT]; ok {
        txt := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if answer.Header().Rrtype == dns.TypeTXT && answer.Header().Class == dns.ClassINET {
                if t, ok := answer.(*dns.TXT); ok {
                    txt = append(txt, strings.Join(t.Txt, " "))
                }
            }
        }
        if len(txt) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(txt, ", "))
        }
    } else {
        fmt.Println("-")
    }

    fmt.Println("")
}

// Helper stubs
func ExtractHostAndPort(host string, defaultPort int) (string, int) {
    host, portStr, err := net.SplitHostPort(host)
    if err != nil {
        return host, defaultPort
    }
    port, _ := net.LookupPort("tcp", portStr)
    return host, port
}

func reverseAddr(ip string) (string, error) {
    addr, err := netip.ParseAddr(ip)
    if err != nil {
        return "", err
    }
    if addr.Is4() {
        bits := addr.As4()
        return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", bits[3], bits[2], bits[1], bits[0]), nil
    }
    return "", fmt.Errorf("ipv6 not implemented in stub")
}
