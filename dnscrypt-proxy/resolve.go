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
    MaxDNSPacketSize int    = 1232
)

type Resolver struct {
    server    string
    transport *dns.Transport
    client    *dns.Client
    ecsOpt    *dns.EDNS0_SUBNET
}

func NewResolver(server string, sendClientSubnet bool) *Resolver {
    tr := dns.NewTransport()
    tr.ReadTimeout = 1500 * time.Millisecond
    c := &dns.Client{Transport: tr}
    
    var ecs *dns.EDNS0_SUBNET
    if sendClientSubnet {
        prefix := netip.MustParsePrefix("93.184.216.0/24")
        addr := prefix.Addr()
        
        family := uint16(1)
        if addr.Is6() {
            family = 2
        }
        
        ecs = &dns.EDNS0_SUBNET{
            Code:          dns.EDNS0SUBNET,
            Family:        family,
            SourceNetmask: uint8(prefix.Bits()),
            SourceScope:   0,
            Address:       addr.AsSlice(),
        }
    }
    
    return &Resolver{
        server:    server,
        transport: tr,
        client:    c,
        ecsOpt:    ecs,
    }
}

func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
    msg := new(dns.Msg)
    msg.SetQuestion(dns.Fqdn(qName), qType)
    msg.RecursionDesired = true
    msg.SetEdns0(uint16(MaxDNSPacketSize), true)
    
    if useECS && r.ecsOpt != nil {
        opt := msg.IsEdns0()
        if opt != nil {
            opt.Option = append(opt.Option, r.ecsOpt)
        }
    }
    
    timeout := r.transport.ReadTimeout
    for attempt := 0; attempt < 2; attempt++ {
        msg.Id = dns.Id()
        queryCtx, cancel := context.WithTimeout(ctx, timeout)
        response, _, err := r.client.ExchangeContext(queryCtx, msg, r.server)
        cancel()
        
        if err == nil && response != nil && response.Truncated {
            r.client.Net = "tcp"
            tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
            response, _, err = r.client.ExchangeContext(tcpCtx, msg, r.server)
            r.client.Net = "udp"
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

func ExtractHostAndPort(server string, defaultPort int) (string, int) {
    host, portStr, err := net.SplitHostPort(server)
    if err != nil {
        return server, defaultPort
    }
    
    port := defaultPort
    if portStr != "" {
        fmt.Sscanf(portStr, "%d", &port)
    }
    return host, port
}

func fqdn(name string) string {
    return dns.Fqdn(name)
}

func reverseAddr(ip string) (string, error) {
    return dns.ReverseAddr(ip)
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
    fmt.Printf("Resolving [%s] using %s port %d\n\n", name, host, port)
    name = fqdn(name)
    ctx := context.Background()
    resolver := NewResolver(server, true)
    cname := name
    var clientSubnet string
    
    response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
    if err != nil {
        fmt.Printf("Unable to resolve: [%s]\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Resolver : ")
    
    type resolverInfo struct {
        ip  string
        ptr string
    }
    
    infos := make([]resolverInfo, 0, len(response.Answer))
    for _, answer := range response.Answer {
        if answer.Header().Class != dns.ClassINET {
            continue
        }
        if txt, ok := answer.(*dns.TXT); ok {
            var ip string
            for _, s := range txt.Txt {
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
    
    var wg sync.WaitGroup
    for i := range infos {
        if rev, err := reverseAddr(infos[i].ip); err == nil {
            wg.Add(1)
            go func(idx int, revAddr string) {
                defer wg.Done()
                if response, err := resolver.resolveQuery(ctx, revAddr, dns.TypePTR, false); err == nil {
                    for _, answer := range response.Answer {
                        if ptr, ok := answer.(*dns.PTR); ok && answer.Header().Class == dns.ClassINET {
                            infos[idx].ptr = ptr.Ptr
                            break
                        }
                    }
                }
            }(i, rev)
        }
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
    
    if singleResolver {
        fmt.Printf("Lying : ")
        response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
        if err != nil {
            fmt.Printf("[%v]\n", err)
        } else {
            if response.Rcode == dns.RcodeSuccess {
                fmt.Println("yes. That resolver returns wrong responses")
            } else if response.Rcode == dns.RcodeNameError {
                fmt.Println("no")
            } else {
                fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
            }
            
            if response.Rcode == dns.RcodeNameError {
                fmt.Printf("DNSSEC : ")
                if response.AuthenticatedData {
                    fmt.Println("yes, the resolver supports DNSSEC")
                } else {
                    fmt.Println("no, the resolver doesn't support DNSSEC")
                }
            }
        }
        
        fmt.Printf("ECS : ")
        if clientSubnet != "" {
            fmt.Println("client network address is sent to authoritative servers")
        } else {
            fmt.Println("ignored or selective")
        }
        fmt.Println("")
    }
    
    fmt.Printf("Canonical name: ")
    for i := 0; i < 10; i++ {
        response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
        if err != nil {
            break
        }
        
        found := false
        for _, answer := range response.Answer {
            if cn, ok := answer.(*dns.CNAME); ok && answer.Header().Class == dns.ClassINET {
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
    fmt.Println("")
    
    ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})
    
    fmt.Printf("IPv4 addresses: ")
    if resp, ok := ipQueries[dns.TypeA]; ok {
        ipv4 := make([]string, 0, len(resp.Answer))
        for _, answer := range resp.Answer {
            if a, ok := answer.(*dns.A); ok && answer.Header().Class == dns.ClassINET {
                ipv4 = append(ipv4, a.A.String())
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
            if aaaa, ok := answer.(*dns.AAAA); ok && answer.Header().Class == dns.ClassINET {
                ipv6 = append(ipv6, aaaa.AAAA.String())
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
    
    fmt.Printf("Name servers : ")
    if response, ok := recordQueries[dns.TypeNS]; ok {
        nss := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if ns, ok := answer.(*dns.NS); ok && answer.Header().Class == dns.ClassINET {
                nss = append(nss, ns.Ns)
            }
        }
        
        if response.Rcode == dns.RcodeNameError {
            fmt.Println("name does not exist")
        } else if response.Rcode != dns.RcodeSuccess {
            fmt.Printf("server returned %s\n", dns.RcodeToString[response.Rcode])
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
        fmt.Printf("DNSSEC signed : -\n")
    }
    
    fmt.Printf("Mail servers : ")
    if response, ok := recordQueries[dns.TypeMX]; ok {
        mxs := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if mx, ok := answer.(*dns.MX); ok && answer.Header().Class == dns.ClassINET {
                mxs = append(mxs, mx.Mx)
            }
        }
        
        if len(mxs) == 0 {
            fmt.Println("no mail servers found")
        } else if len(mxs) > 1 {
            fmt.Printf("%d mail servers found\n", len(mxs))
        } else {
            fmt.Println("1 mail server found")
        }
    } else {
        fmt.Println("-")
    }
    
    fmt.Println("")
    
    fmt.Printf("HTTPS alias : ")
    if response, ok := recordQueries[dns.TypeHTTPS]; ok {
        aliases := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if https, ok := answer.(*dns.HTTPS); ok && answer.Header().Class == dns.ClassINET {
                if https.Priority == 0 && len(https.Target) >= 2 {
                    aliases = append(aliases, https.Target)
                }
            }
        }
        if len(aliases) == 0 {
            fmt.Println("-")
        } else {
            fmt.Println(strings.Join(aliases, ", "))
        }
        
        fmt.Printf("HTTPS info : ")
        info := make([]string, 0, len(response.Answer)*2)
        for _, answer := range response.Answer {
            if https, ok := answer.(*dns.HTTPS); ok && answer.Header().Class == dns.ClassINET {
                if https.Priority != 0 || len(https.Target) <= 1 {
                    for _, value := range https.Value {
                        info = append(info, fmt.Sprintf("[%s]=[%s]", svcb.KeyToString(svcb.PairToKey(value)), value.String()))
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
        fmt.Printf("HTTPS info : -\n")
    }
    
    fmt.Println("")
    
    fmt.Printf("Host info : ")
    if response, ok := recordQueries[dns.TypeHINFO]; ok {
        hinfo := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if hi, ok := answer.(*dns.HINFO); ok && answer.Header().Class == dns.ClassINET {
                hinfo = append(hinfo, fmt.Sprintf("%s %s", hi.Cpu, hi.Os))
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
    
    fmt.Printf("TXT records : ")
    if response, ok := recordQueries[dns.TypeTXT]; ok {
        txt := make([]string, 0, len(response.Answer))
        for _, answer := range response.Answer {
            if t, ok := answer.(*dns.TXT); ok && answer.Header().Class == dns.ClassINET {
                txt = append(txt, strings.Join(t.Txt, " "))
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
