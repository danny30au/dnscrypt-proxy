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

const DNSBufferSize = 4096

var (
    ErrSyntaxError = errors.New("syntax error for a captive portal rule")
    ErrWildcardNotAllowed = errors.New("captive portal rule must use an exact host name")
)

type CaptivePortalEntryIPs []netip.Addr

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
    wg    sync.WaitGroup
    mu    sync.Mutex
    conns []*net.UDPConn
}

func (h *CaptivePortalHandler) Stop() {
    h.mu.Lock()
    conns := h.conns
    h.conns = nil
    h.mu.Unlock()

    for _, conn := range conns {
        conn.Close()
    }
    h.wg.Wait()
}

func (ipsMap CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, CaptivePortalEntryIPs, bool) {
    if len(msg.Question) != 1 {
        return nil, nil, false
    }
    question := msg.Question[0]
    hdr := question.Header()

    if hdr.Class != dns.ClassINET {
        return nil, nil, false
    }

    name, err := NormalizeQName(hdr.Name)
    if err != nil {
        return nil, nil, false
    }

    ips, ok := ipsMap[name]
    return question, ips, ok
}

func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips CaptivePortalEntryIPs) *dns.Msg {
    respMsg := EmptyResponseFromMessage(msg)
    hdr := question.Header()
    qtype := dns.RRToType(question)

    isA := qtype == dns.TypeA
    isAAAA := qtype == dns.TypeAAAA

    if !isA && !isAAAA {
        return nil
    }

    hdrTemplate := dns.Header{
        Name:  hdr.Name,
        Class: dns.ClassINET,
        TTL:   1,
    }

    respMsg.Answer = make([]dns.RR, 0, len(ips))

    for _, ip := range ips {
        if (isA && ip.Is4()) || (isAAAA && ip.Is6()) {
            if isA {
                respMsg.Answer = append(respMsg.Answer, &dns.A{
                    Hdr: hdrTemplate,
                    A:   rdata.A{Addr: ip},
                })
            } else {
                respMsg.Answer = append(respMsg.Answer, &dns.AAAA{
                    Hdr: hdrTemplate,
                    AAAA: rdata.AAAA{Addr: ip},
                })
            }
        }
    }

    if len(respMsg.Answer) == 0 {
        return nil
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

    h.wg.Go(func() {
        buffer := make([]byte, DNSBufferSize)

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
            msg.Data = packet
            if err := msg.Unpack(); err != nil {
                continue
            }

            question, ips, ok := ipsMap.GetEntry(msg)
            if !ok {
                continue
            }

            respMsg := HandleCaptivePortalQuery(msg, question, ips)
            if respMsg == nil {
                continue
            }

            if err := respMsg.Pack(); err == nil {
                clientPc.WriteToUDP(respMsg.Data, clientAddr)
            }
        }
    })
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

    estimatedRules := 100
    ipsMap := make(CaptivePortalMap, estimatedRules)
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
            return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
        }
        name, err = NormalizeQName(name)
        if err != nil {
            continue
        }
        if strings.Contains(ipsStr, "*") {
            return nil, fmt.Errorf("%w at line %d", ErrWildcardNotAllowed, lineNo)
        }

        var ips []netip.Addr
        remaining := ipsStr
        for {
            var ipStr string
            ipStr, remaining, _ = strings.Cut(remaining, ",")
            ipStr = strings.TrimSpace(ipStr)

            if ipStr == "" && remaining == "" {
                break
            }
            if ipStr == "" {
                return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
            }

            ip, err := netip.ParseAddr(ipStr)
            if err != nil {
                return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
            }
            ips = append(ips, ip)

            if remaining == "" {
                break
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
