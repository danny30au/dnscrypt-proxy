package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "net"
    "net/netip"
    "strings"
    "sync"
    "time"
    "unicode/utf8"
    "unsafe"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/rdata"
    "github.com/jedisct1/dlog"
)

// --- Memory Pools ---

var msgPool = sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}

// GetMsg retrieves a zeroed message from the pool
func GetMsg() *dns.Msg {
    return msgPool.Get().(*dns.Msg)
}

// PutMsg resets and returns a message to the pool
func PutMsg(m *dns.Msg) {
    if m == nil {
        return
    }

    // Preserve slice capacities to reduce allocations on reuse.
    q := m.Question[:0]
    a := m.Answer[:0]
    ns := m.Ns[:0]
    ex := m.Extra[:0]
    ps := m.Pseudo[:0]
    data := m.Data[:0]

    // Reset the struct in one assignment, then restore reusable buffers.
    *m = dns.Msg{}
    m.Question = q
    m.Answer = a
    m.Ns = ns
    m.Extra = ex
    m.Pseudo = ps
    m.Data = data

    msgPool.Put(m)
}

// --- Static Data ---
var (
    blockedHinfoCPU = "This query has been locally blocked"
    blockedHinfoOS  = "by dnscrypt-proxy"
)

// --- Functions ---

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
    dstMsg := GetMsg()
    dstMsg.ID = srcMsg.ID
    dstMsg.Opcode = srcMsg.Opcode

    dstMsg.Question = append(dstMsg.Question[:0], srcMsg.Question...)

    dstMsg.Response = true
    dstMsg.RecursionAvailable = true
    dstMsg.RecursionDesired = srcMsg.RecursionDesired
    dstMsg.CheckingDisabled = false
    dstMsg.AuthenticatedData = false

    if srcMsg.UDPSize > 0 {
        dstMsg.UDPSize = srcMsg.UDPSize
    }
    return dstMsg
}

// TruncatedResponse - Optimized
func TruncatedResponse(packet []byte) ([]byte, error) {
    if len(packet) < 12 {
        return nil, errors.New("packet too short")
    }

    qdCount := binary.BigEndian.Uint16(packet[4:6])
    offset := 12
    for i := uint16(0); i < qdCount; i++ {
        for {
            if offset >= len(packet) {
                return nil, errors.New("packet malformed")
            }
            labelLen := int(packet[offset])
            if (labelLen & 0xC0) == 0xC0 {
                offset += 2
                break
            }
            offset++
            if labelLen == 0 {
                break
            }
            offset += labelLen
        }
        offset += 4
    }

    if offset > len(packet) {
        return nil, errors.New("packet malformed")
    }

    // Allocate exactly what is returned (avoids pool lifetime issues and double-copy).
    truncated := make([]byte, offset)
    copy(truncated, packet[:offset])

    // Set QR=1 and TC=1 (0x80 | 0x02) while preserving other bits.
    truncated[2] |= 0x82

    // Clear ANCOUNT/NSCOUNT/ARCOUNT.
    for i := 6; i < 12; i++ {
        truncated[i] = 0
    }

    return truncated, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
    dstMsg := EmptyResponseFromMessage(srcMsg)

    var ede *dns.EDE
    if dstMsg.UDPSize > 0 {
        ede = &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
        dstMsg.Pseudo = append(dstMsg.Pseudo, ede)
    }

    if refusedCode {
        dstMsg.Rcode = dns.RcodeRefused
    } else {
        dstMsg.Rcode = dns.RcodeSuccess
        questions := srcMsg.Question
        if len(questions) == 0 {
            return dstMsg
        }
        question := questions[0]
        qtype := dns.RRToType(question)
        qname := question.Header().Name
        sendHInfoResponse := true

        if ipv4 != nil && qtype == dns.TypeA {
            if ip4 := ipv4.To4(); ip4 != nil {
                rr := &dns.A{
                    Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    A:   rdata.A{Addr: netip.AddrFrom4([4]byte(ip4))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                if ede != nil {
                    ede.InfoCode = dns.ExtendedErrorForgedAnswer
                }
            }
        } else if ipv6 != nil && qtype == dns.TypeAAAA {
            if ip6 := ipv6.To16(); ip6 != nil {
                rr := &dns.AAAA{
                    Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    AAAA: rdata.AAAA{Addr: netip.AddrFrom16([16]byte(ip6))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                if ede != nil {
                    ede.InfoCode = dns.ExtendedErrorForgedAnswer
                }
            }
        }

        if sendHInfoResponse {
            hinfo := &dns.HINFO{
                Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                HINFO: rdata.HINFO{
                    Cpu: blockedHinfoCPU,
                    Os:  blockedHinfoOS,
                },
            }
            dstMsg.Answer = append(dstMsg.Answer, hinfo)
        } else {
            if ede != nil {
                ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
            }
        }
    }

    return dstMsg
}

func HasTCFlag(packet []byte) bool {
    return packet[2]&2 == 2
}

func TransactionID(packet []byte) uint16 {
    return binary.BigEndian.Uint16(packet[0:2])
}

func SetTransactionID(packet []byte, tid uint16) {
    binary.BigEndian.PutUint16(packet[0:2], tid)
}

func Rcode(packet []byte) uint8 {
    return packet[3] & 0xf
}

func NormalizeRawQName(name *[]byte) {
    b := *name
    for i := 0; i < len(b); i++ {
        c := b[i]
        if c >= 'A' && c <= 'Z' {
            b[i] = c + ('a' - 'A')
        }
    }
}

func NormalizeQName(str string) (string, error) {
    if len(str) == 0 || str == "." {
        return ".", nil
    }
    str = strings.TrimSuffix(str, ".")

    // Single scan: validate ASCII and detect first uppercase.
    upperAt := -1
    for i := 0; i < len(str); i++ {
        c := str[i]
        if c >= utf8.RuneSelf {
            return str, errors.New("Query name is not an ASCII string")
        }
        if upperAt < 0 && c >= 'A' && c <= 'Z' {
            upperAt = i
        }
    }
    if upperAt < 0 {
        return str, nil
    }

    b := []byte(str)
    for i := upperAt; i < len(b); i++ {
        c := b[i]
        if c >= 'A' && c <= 'Z' {
            b[i] = c + ('a' - 'A')
        }
    }

    return unsafe.String(unsafe.SliceData(b), len(b)), nil
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
    if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
        (len(msg.Answer) == 0 && len(msg.Ns) == 0) {
        return time.Duration(cacheNegMinTTL) * time.Second
    }

    ttl := maxTTL
    if msg.Rcode != dns.RcodeSuccess {
        ttl = cacheNegMaxTTL
    }

    minFrom := func(rrs []dns.RR, cur uint32) uint32 {
        for _, rr := range rrs {
            if t := rr.Header().TTL; t < cur {
                cur = t
            }
        }
        return cur
    }

    if len(msg.Answer) > 0 {
        ttl = minFrom(msg.Answer, ttl)
    } else {
        ttl = minFrom(msg.Ns, ttl)
    }

    if msg.Rcode == dns.RcodeSuccess {
        if ttl < minTTL {
            ttl = minTTL
        }
    } else {
        if ttl < cacheNegMinTTL {
            ttl = cacheNegMinTTL
        }
    }

    return time.Duration(ttl) * time.Second
}

func updateTTL(msg *dns.Msg, expiration time.Time) {
    until := time.Until(expiration)
    ttl := uint32(0)
    if until > 0 {
        ttl = uint32(until / time.Second)
        if until-time.Duration(ttl)*time.Second >= time.Second/2 {
            ttl += 1
        }
    }
    for _, rr := range msg.Answer {
        rr.Header().TTL = ttl
    }
    for _, rr := range msg.Ns {
        rr.Header().TTL = ttl
    }
    for _, rr := range msg.Extra {
        if dns.RRToType(rr) != dns.TypeOPT {
            rr.Header().TTL = ttl
        }
    }
}

func hasEDNS0Padding(packet []byte) (bool, error) {
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return false, err
    }
    // In v2, options are in Pseudo
    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return true, nil
        }
    }
    return false, nil
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
    if msg.UDPSize == 0 {
        msg.UDPSize = uint16(MaxDNSPacketSize)
    }

    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return unpaddedPacket, nil
        }
    }

    paddingRR := &dns.PADDING{Padding: strings.Repeat("X", paddingLen)}
    msg.Pseudo = append(msg.Pseudo, paddingRR)

    if err := msg.Pack(); err != nil {
        return nil, err
    }
    return msg.Data, nil
}

func removeEDNS0Options(msg *dns.Msg) bool {
    if len(msg.Pseudo) == 0 {
        return false
    }
    msg.Pseudo = nil
    return true
}

func dddToByte3(a, b, c byte) byte {
    return byte((a-'0')*100 + (b-'0')*10 + (c - '0'))
}

func PackTXTRR(s string) []byte {
    var buf bytes.Buffer
    buf.Grow(len(s))

    for i := 0; i < len(s); i++ {
        c := s[i]
        if c != '\\' {
            buf.WriteByte(c)
            continue
        }

        // Backslash: start of escape sequence.
        i++
        if i >= len(s) {
            break
        }

        // Try DDD decimal escape.
        if i+2 < len(s) {
            a, b, c3 := s[i], s[i+1], s[i+2]
            if a >= '0' && a <= '9' &&
                b >= '0' && b <= '9' &&
                c3 >= '0' && c3 <= '9' {
                buf.WriteByte(dddToByte3(a, b, c3))
                i += 2
                continue
            }
        }

        // Simple escapes.
        switch s[i] {
        case 't':
            buf.WriteByte('\t')
        case 'r':
            buf.WriteByte('
')
        case 'n':
            buf.WriteByte('
')
        default:
            buf.WriteByte(s[i])
        }
    }

    return buf.Bytes()
}

type DNSExchangeResponse struct {
    response         *dns.Msg
    rtt              time.Duration
    priority         int
    fragmentsBlocked bool
    err              error
}

func DNSExchange(
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    serverName *string,
    tryFragmentsSupport bool,
) (*dns.Msg, time.Duration, bool, error) {
    for {
        cancelChannel := make(chan struct{})
        maxTries := 3
        channel := make(chan DNSExchangeResponse, 2*maxTries)
        var err error
        options := 0

        for tries := 0; tries < maxTries; tries++ {
            if tryFragmentsSupport {
                queryCopy := query.Copy()
                queryCopy.ID += uint16(options)
                go func(query *dns.Msg, delay time.Duration) {
                    time.Sleep(delay)
                    option := DNSExchangeResponse{err: errors.New("Canceled")}
                    select {
                    case <-cancelChannel:
                    default:
                        option = _dnsExchange(proxy, proto, query, serverAddress, relay, 1500)
                    }
                    option.fragmentsBlocked = false
                    option.priority = 0
                    channel <- option
                }(queryCopy, time.Duration(200*tries)*time.Millisecond)
                options++
            }
            queryCopy := query.Copy()
            queryCopy.ID += uint16(options)
            go func(query *dns.Msg, delay time.Duration) {
                time.Sleep(delay)
                option := DNSExchangeResponse{err: errors.New("Canceled")}
                select {
                case <-cancelChannel:
                default:
                    option = _dnsExchange(proxy, proto, query, serverAddress, relay, 480)
                }
                option.fragmentsBlocked = true
                option.priority = 1
                channel <- option
            }(queryCopy, time.Duration(250*tries)*time.Millisecond)
            options++
        }
        var bestOption *DNSExchangeResponse
        for i := 0; i < options; i++ {
            if dnsExchangeResponse := <-channel; dnsExchangeResponse.err == nil {
                if bestOption == nil || dnsExchangeResponse.priority < bestOption.priority ||
                    (dnsExchangeResponse.priority == bestOption.priority && dnsExchangeResponse.rtt < bestOption.rtt) {
                    bestOption = &dnsExchangeResponse
                    if bestOption.priority == 0 {
                        close(cancelChannel)
                        break
                    }
                }
            } else {
                err = dnsExchangeResponse.err
            }
        }
        if bestOption != nil {
            if bestOption.fragmentsBlocked {
                dlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *serverName)
            } else {
                dlog.Debugf("[%v] public key retrieval succeeded", *serverName)
            }
            return bestOption.response, bestOption.rtt, bestOption.fragmentsBlocked, nil
        }

        if relay == nil || !proxy.anonDirectCertFallback {
            if err == nil {
                err = errors.New("Unable to reach the server")
            }
            return nil, 0, false, err
        }
        dlog.Infof(
            "Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
            *serverName,
            relay.RelayUDPAddr.IP,
        )
        relay = nil
    }
}

func _dnsExchange(
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    paddedLen int,
) DNSExchangeResponse {
    var packet []byte
    var rtt time.Duration
    if proto == "udp" {
        qNameLen, padding := len(query.Question[0].Header().Name), 0
        if qNameLen < paddedLen {
            padding = paddedLen - qNameLen
        }
        if padding > 0 {
            paddingRR := &dns.PADDING{Padding: strings.Repeat("X", padding)}
            query.Pseudo = append(query.Pseudo, paddingRR)
            if query.UDPSize == 0 {
                query.UDPSize = uint16(MaxDNSPacketSize)
            }
        }
        if err := query.Pack(); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery := query.Data
        udpAddr, err := net.ResolveUDPAddr("udp", serverAddress)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        upstreamAddr := udpAddr
        if relay != nil {
            proxy.prepareForRelay(udpAddr.IP, udpAddr.Port, &binQuery)
            upstreamAddr = relay.RelayUDPAddr
        }
        now := time.Now()
        pc, err := net.DialTimeout("udp", upstreamAddr.String(), proxy.timeout)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        defer pc.Close()
        if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
            return DNSExchangeResponse{err: err}
        }
        if _, err := pc.Write(binQuery); err != nil {
            return DNSExchangeResponse{err: err}
        }
        packet = make([]byte, MaxDNSPacketSize)
        length, err := pc.Read(packet)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        rtt = time.Since(now)
        packet = packet[:length]
    } else {
        if err := query.Pack(); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery := query.Data
        tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        upstreamAddr := tcpAddr
        if relay != nil {
            proxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
            upstreamAddr = relay.RelayTCPAddr
        }
        now := time.Now()
        var pc net.Conn
        proxyDialer := proxy.xTransport.proxyDialer
        if proxyDialer == nil {
            pc, err = net.DialTimeout("tcp", upstreamAddr.String(), proxy.timeout)
        } else {
            pc, err = (*proxyDialer).Dial("tcp", tcpAddr.String())
        }
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        defer pc.Close()
        if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery, err = PrefixWithSize(binQuery)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        if _, err := pc.Write(binQuery); err != nil {
            return DNSExchangeResponse{err: err}
        }
        packet, err = ReadPrefixed(&pc)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        rtt = time.Since(now)
    }
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return DNSExchangeResponse{err: err}
    }
    return DNSExchangeResponse{response: &msg, rtt: rtt, err: nil}
}
