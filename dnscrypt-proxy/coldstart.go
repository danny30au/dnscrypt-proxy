package main

import (
    "bufio"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "os"
    "strings"
    "sync"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/rdata"
    "github.com/jedisct1/dlog"
)

// Use netip.Addr for zero-allocation IP storage
type CaptivePortalEntryIPs []netip.Addr

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
    wg    sync.WaitGroup
    mu    sync.Mutex
    conns []*net.UDPConn
}

func (h *CaptivePortalHandler) Stop() {
    h.mu.Lock()
    // Optimization: Copy connections and clear slice inside lock,
    // then close them outside the lock to minimize contention.
    conns := h.conns
    h.conns = nil
    h.mu.Unlock()

    for _, conn := range conns {
        // Closing the connection will cause ReadFrom to return an error,
        // unblocking the listener goroutines immediately.
        conn.Close()
    }
    h.wg.Wait()
}

// Fixed: Reverted to original signature to satisfy interface/external calls
func (ipsMap *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, CaptivePortalEntryIPs, bool) {
    if len(msg.Question) != 1 {
        return nil, nil, false
    }
    question := msg.Question[0]
    hdr := question.Header()
    name, err := NormalizeQName(hdr.Name)
    if err != nil {
        return nil, nil, false
    }
    ips, ok := (*ipsMap)[name]
    if !ok {
        return nil, nil, false
    }
    if hdr.Class != dns.ClassINET {
        return nil, nil, false
    }
    return question, ips, true
}

func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips CaptivePortalEntryIPs) *dns.Msg {
    respMsg := EmptyResponseFromMessage(msg)
    ttl := uint32(1)
    hdr := question.Header()
    qtype := dns.RRToType(question)

    isA := qtype == dns.TypeA
    isAAAA := qtype == dns.TypeAAAA

    if !isA && !isAAAA {
        return nil
    }

    // Optimization: Calculate required capacity first to avoid slice growth
        count := 0
        for _, ip := range ips {
            if (isA && ip.Is4()) || (isAAAA && ip.Is6()) {
                count++
            }
        }

        if count > 0 {
            respMsg.Answer = make([]dns.RR, 0, count)
            for _, ip := range ips {
                shouldInclude := (isA && ip.Is4()) || (isAAAA && ip.Is6())
                if !shouldInclude {
                    continue
                }

                var rr dns.RR
                if isA {
                    r := new(dns.A)
                    r.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
                    r.A = rdata.A{Addr: ip}
                    rr = r
                } else {
                    r := new(dns.AAAA)
                    r.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
                    r.AAAA = rdata.AAAA{Addr: ip}
                    rr = r
                }
                respMsg.Answer = append(respMsg.Answer, rr)
            }
        }

    qTypeStr, ok := dns.TypeToString[qtype]
    if !ok {
        qTypeStr = fmt.Sprint(qtype)
    }
    dlog.Debugf("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)
    return respMsg
}

func addColdStartListener(
    ipsMap *CaptivePortalMap,
    listenAddrStr string,
    h *CaptivePortalHandler,
) error {
    network := "udp"
    if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
        network = "udp4"
    }
    listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
    if err != nil {
        return err
    }
    clientPc, err := net.ListenUDP(network, listenUDPAddr)
    if err != nil {
        return err
    }

    h.mu.Lock()
    h.conns = append(h.conns, clientPc)
    h.mu.Unlock()

    h.wg.Add(1)
    go func() {
        defer h.wg.Done()

        // Allocating buffer once outside the loop reuses memory for all packets
        buffer := make([]byte, MaxDNSPacketSize)

        for {
            length, clientAddr, err := clientPc.ReadFromUDP(buffer)
            if err != nil {
                if errors.Is(err, net.ErrClosed) {
                    return
                }
                dlog.Warn(err)
                continue
            }

            packet := buffer[:length]
            msg := &dns.Msg{}
            // Optimization: Assign to Data field first, then Unpack()
            msg.Data = packet
            if err := msg.Unpack(); err != nil {
                continue
            }

            // Fixed: Use original calling convention
            question, ips, ok := ipsMap.GetEntry(msg)
            if !ok {
                continue
            }

            respMsg := HandleCaptivePortalQuery(msg, question, ips)
            if respMsg == nil {
                continue
            }

            // Optimization: Use existing Pack() API which returns error only
            // and writes to respMsg.Data
            if err := respMsg.Pack(); err == nil {
                clientPc.WriteToUDP(respMsg.Data, clientAddr)
            }
        }
    }()
    return nil
}

func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
    if len(proxy.captivePortalMapFile) == 0 {
        return nil, nil
    }

    file, err := os.Open(proxy.captivePortalMapFile)
    if err != nil {
        dlog.Warn(err)
        return nil, err
    }
    defer file.Close()

    ipsMap := make(CaptivePortalMap)
    scanner := bufio.NewScanner(file)
    scanner.Buffer(make([]byte, 64*1024), 1024*1024)
    lineNo := 0

    for scanner.Scan() {
        lineNo++
        line := scanner.Text()
        line = TrimAndStripInlineComments(line)
        if len(line) == 0 {
            continue
        }
        name, ipsStr, ok := StringTwoFields(line)
        if !ok {
            return nil, fmt.Errorf(
                "Syntax error for a captive portal rule at line %d",
                lineNo,
            )
        }
        name, err = NormalizeQName(name)
        if err != nil {
            continue
        }
        if strings.Contains(ipsStr, "*") {
            return nil, fmt.Errorf(
                "A captive portal rule must use an exact host name at line %d",
                lineNo,
            )
        }

        // Optimization: Pre-allocate slice capacity based on split count
        ipParts := strings.Split(ipsStr, ",")
        var ips = make([]netip.Addr, 0, len(ipParts))
        
        for _, ipStr := range ipParts {
            ipStr = strings.TrimSpace(ipStr)
            if ipStr == "" {
                return nil, fmt.Errorf(
                    "Syntax error for a captive portal rule at line %d",
                    lineNo,
                )
            }
            if ip, err := netip.ParseAddr(ipStr); err == nil {
                ips = append(ips, ip)
            } else {
                return nil, fmt.Errorf(
                    "Syntax error for a captive portal rule at line %d",
                    lineNo,
                )
            }
        }
        ipsMap[name] = ips
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    handler := &CaptivePortalHandler{}

    ok := false
    var lastErr error
    for _, listenAddrStr := range proxy.listenAddresses {
        if err := addColdStartListener(&ipsMap, listenAddrStr, handler); err == nil {
            ok = true
        } else {
            lastErr = err
            dlog.Warnf("ColdStart listener bind failed on %v: %v", listenAddrStr, err)
        }
    }

    if ok {
        proxy.captivePortalMap = &ipsMap
        return handler, nil
    }

    handler.Stop()
    return handler, lastErr
}
