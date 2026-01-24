package main

import (
    "context"
    "errors"
    "log/slog"
    "net"
    "net/netip"
    "slices"
    "strings"
    "sync"
    "time"
    "unicode/utf8"

    "codeberg.org/miekg/dns"
)

// Global Transport Configurations
// Kept these as they seem specific to this file's logic or are needed globalvars
// If these are also duplicated, remove them.
var msgPool = sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}

var tcpConnPool = struct {
    sync.RWMutex
    conns map[string][]*tcpConnWrapper
}{
    conns: make(map[string][]*tcpConnWrapper),
}

type tcpConnWrapper struct {
    conn     net.Conn
    lastUsed time.Time
}

func init() {
    // Only keep local initialization. 
    // If httpTransport/http2Transport are global in other files, remove this init or the vars.
    go connectionPoolCleaner()
}

func connectionPoolCleaner() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        tcpConnPool.Lock()
        now := time.Now()

        // Go 1.21+ slices.DeleteFunc: Zero-allocation filtering
        for addr, conns := range tcpConnPool.conns {
            newConns := slices.DeleteFunc(conns, func(c *tcpConnWrapper) bool {
                if now.Sub(c.lastUsed) >= 60*time.Second {
                    c.conn.Close()
                    return true // Delete
                }
                return false // Keep
            })

            if len(newConns) > 0 {
                tcpConnPool.conns[addr] = newConns
            } else {
                delete(tcpConnPool.conns, addr)
            }
        }
        tcpConnPool.Unlock()
    }
}

func getTCPConn(addr string, timeout time.Duration) (net.Conn, bool, error) {
    tcpConnPool.Lock()
    conns := tcpConnPool.conns[addr]
    if len(conns) > 0 {
        lastIdx := len(conns) - 1
        wrapper := conns[lastIdx]
        // Avoid potential memory leak in long-lived slices
        conns[lastIdx] = nil
        tcpConnPool.conns[addr] = conns[:lastIdx]
        tcpConnPool.Unlock()

        wrapper.lastUsed = time.Now()
        return wrapper.conn, true, nil
    }
    tcpConnPool.Unlock()

    // Modern Context-aware dialer
    dialer := &net.Dialer{
        Timeout:   timeout,
        KeepAlive: 30 * time.Second,
    }
    conn, err := dialer.DialContext(context.Background(), "tcp", addr)
    return conn, false, err
}

func putTCPConn(addr string, conn net.Conn) {
    tcpConnPool.Lock()
    defer tcpConnPool.Unlock()

    wrapper := &tcpConnWrapper{
        conn:     conn,
        lastUsed: time.Now(),
    }

    conns := tcpConnPool.conns[addr]
    if len(conns) < 10 {
        tcpConnPool.conns[addr] = append(conns, wrapper)
    } else {
        conn.Close()
    }
}

func GetMsg() *dns.Msg {
    return msgPool.Get().(*dns.Msg)
}

func PutMsg(m *dns.Msg) {
    if m == nil {
        return
    }
    // Clear slice headers to avoid referencing old data
    m.Question = m.Question[:0]
    m.Answer = m.Answer[:0]
    m.Ns = m.Ns[:0]
    m.Extra = m.Extra[:0]
    m.Pseudo = m.Pseudo[:0]
    m.Data = m.Data[:0]
    
    // Explicit struct reset
    *m = dns.Msg{
        Question: m.Question,
        Answer:   m.Answer,
        Ns:       m.Ns,
        Extra:    m.Extra,
        Pseudo:   m.Pseudo,
        Data:     m.Data,
    }
    msgPool.Put(m)
}

// NormalizeQName was missing/undefined in coldstart.go
// Replaces old implementation with efficient version
func NormalizeQName(str string) (string, error) {
    // Fast path: Check ASCII validity
    for i := 0; i < len(str); i++ {
        if str[i] >= utf8.RuneSelf {
            return "", errors.New("Query name is not an ASCII string")
        }
    }
    
    if len(str) == 0 || str == "." {
        return ".", nil
    }

    // strings.ToLower is SIMD-optimized in modern Go
    s := strings.ToLower(str)
    
    // Ensure trailing dot for FQDN if not present (optional based on your logic, but standard for DNS)
    if s[len(s)-1] != '.' {
        return s + ".", nil
    }
    return s, nil
}

// EmptyResponseFromMessage was undefined in coldstart.go
func EmptyResponseFromMessage(m *dns.Msg) *dns.Msg {
    resp := GetMsg()
    resp.SetReply(m)
    resp.Authoritative = false
    resp.RecursionAvailable = false // Or true, depending on your proxy logic
    // Clear sections that SetReply might have touched if you want it truly empty
    resp.Answer = nil
    resp.Ns = nil
    resp.Extra = nil
    return resp
}

func getMinTTL(msg *dns.Msg, minTTL, maxTTL, cacheNegMinTTL, cacheNegMaxTTL uint32) time.Duration {
    if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
        (len(msg.Answer) == 0 && len(msg.Ns) == 0) {
        return time.Duration(cacheNegMinTTL) * time.Second
    }

    limit := maxTTL
    threshold := minTTL
    if msg.Rcode != dns.RcodeSuccess {
        limit = cacheNegMaxTTL
        threshold = cacheNegMinTTL
    }

    minFound := limit
    
    processRR := func(rrs []dns.RR) {
        if len(rrs) == 0 {
            return
        }
        found := slices.MinFunc(rrs, func(a, b dns.RR) int {
            return int(a.Header().TTL) - int(b.Header().TTL)
        })
        if found.Header().TTL < minFound {
            minFound = found.Header().TTL
        }
    }

    processRR(msg.Answer)
    processRR(msg.Ns)

    // Go 1.21+ built-ins
    finalTTL := min(minFound, limit)
    finalTTL = max(finalTTL, threshold)

    return time.Duration(finalTTL) * time.Second
}

func updateTTL(msg *dns.Msg, expiration time.Time) {
    until := time.Until(expiration)
    ttl := uint32(0)
    
    if until > 0 {
        ttl = uint32(until / time.Second)
        // Round up if > 0.5s
        if until-time.Duration(ttl)*time.Second >= time.Second/2 {
            ttl += 1
        }
    }

    // Helper closure to avoid repetition
    setTTL := func(rrs []dns.RR) {
        for _, rr := range rrs {
            rr.Header().TTL = ttl
        }
    }

    setTTL(msg.Answer)
    setTTL(msg.Ns)
    
    for _, rr := range msg.Extra {
        if dns.RRToType(rr) != dns.TypeOPT {
            rr.Header().TTL = ttl
        }
    }
}

func hasEDNS0Padding(packet []byte) (bool, error) {
    msg := GetMsg()
    defer PutMsg(msg)
    
    msg.Data = packet
    if err := msg.Unpack(packet); err != nil {
        return false, err
    }
    
    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return true, nil
        }
    }
    return false, nil
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
    if msg.UDPSize == 0 {
        msg.UDPSize = uint16(dns.MaxMsgSize)
    }

    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return unpaddedPacket, nil
        }
    }

    // Optimization: Pre-calculate padding string or use cached constant if size is fixed
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

func PackTXTRR(s string) []byte {
    // strings.Builder is optimized for this pattern
    var sb strings.Builder
    sb.Grow(len(s) + len(s)/10) // Heuristic pre-allocation

    for i := 0; i < len(s); i++ {
        c := s[i]
        if c != '\\' {
            sb.WriteByte(c)
            continue
        }

        i++
        if i >= len(s) {
            break
        }

        if i+2 < len(s) {
            a, b, c3 := s[i], s[i+1], s[i+2]
            if (a-'0') < 10 && (b-'0') < 10 && (c3-'0') < 10 {
                // Inline dddToByte3 calculation
                val := (a-'0')*100 + (b-'0')*10 + (c3 - '0')
                sb.WriteByte(val)
                i += 2
                continue
            }
        }

        switch s[i] {
        case 't':
            sb.WriteByte(9)
        case 'r':
            sb.WriteByte(13)
        case 'n':
            sb.WriteByte(10)
        default:
            sb.WriteByte(s[i])
        }
    }

    // Convert string to bytes (copy)
    return []byte(sb.String())
}

type DNSExchangeResponse struct {
    response         *dns.Msg
    rtt              time.Duration
    priority         int
    fragmentsBlocked bool
    err              error
}

// DNSExchange: Fully modernized with Context and netip
func DNSExchange(
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    serverName *string,
    tryFragmentsSupport bool,
) (*dns.Msg, time.Duration, bool, error) {
    
    // Parent context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), proxy.timeout+2*time.Second)
    defer cancel()

    maxTries := 3
    resChan := make(chan DNSExchangeResponse, 2*maxTries)
    var wg sync.WaitGroup

    // Launch strategies in parallel
    for tries := 0; tries < maxTries; tries++ {
        // Strategy 1: Fragmented (Large Packet)
        if tryFragmentsSupport {
            wg.Add(1)
            go func(t int) {
                defer wg.Done()
                
                // Staggered launch
                delay := time.Duration(200*t) * time.Millisecond
                timer := time.NewTimer(delay)
                defer timer.Stop()

                select {
                case <-timer.C:
                case <-ctx.Done():
                    return
                }

                qCopy := query.Copy()
                qCopy.ID += uint16(t * 2)

                resp := _dnsExchange(ctx, proxy, proto, qCopy, serverAddress, relay, 1500)
                resp.fragmentsBlocked = false
                resp.priority = 0 // Preferred

                select {
                case resChan <- resp:
                case <-ctx.Done():
                }
            }(tries)
        }

        // Strategy 2: Standard (Small Packet)
        wg.Add(1)
        go func(t int) {
            defer wg.Done()

            delay := time.Duration(250*t) * time.Millisecond
            timer := time.NewTimer(delay)
            defer timer.Stop()

            select {
            case <-timer.C:
            case <-ctx.Done():
                return
            }

            qCopy := query.Copy()
            qCopy.ID += uint16(t*2 + 1)

            resp := _dnsExchange(ctx, proxy, proto, qCopy, serverAddress, relay, 480)
            resp.fragmentsBlocked = true
            resp.priority = 1

            select {
            case resChan <- resp:
            case <-ctx.Done():
            }
        }(tries)
    }

    // Closer goroutine
    go func() {
        wg.Wait()
        close(resChan)
    }()

    var bestOption *DNSExchangeResponse
    var lastErr error

    for resp := range resChan {
        if resp.err == nil {
            // Optimization: If we get the perfect response (Priority 0), return immediately
            if resp.priority == 0 {
                cancel() // Stop other attempts
                slog.Debug("Public key retrieval succeeded", "server", *serverName)
                return resp.response, resp.rtt, false, nil
            }

            // Keep track of best available result
            if bestOption == nil || resp.priority < bestOption.priority ||
                (resp.priority == bestOption.priority && resp.rtt < bestOption.rtt) {
                val := resp // copy
                bestOption = &val
            }
        } else {
            lastErr = resp.err
        }
    }

    if bestOption != nil {
        slog.Debug("Public key retrieval succeeded (fragments blocked)", "server", *serverName)
        return bestOption.response, bestOption.rtt, bestOption.fragmentsBlocked, nil
    }

    if lastErr == nil {
        lastErr = errors.New("unable to reach the server")
    }

    if relay != nil && proxy.anonDirectCertFallback {
        slog.Info("Retrying direct connection (relay failed)", "server", *serverName, "relay", relay.RelayUDPAddr)
        return DNSExchange(proxy, proto, query, serverAddress, nil, serverName, tryFragmentsSupport)
    }

    return nil, 0, false, lastErr
}

func _dnsExchange(
    ctx context.Context,
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    paddedLen int,
) DNSExchangeResponse {
    var rtt time.Duration

    if proto == "udp" {
        qNameLen := len(query.Question[0].Header().Name)
        padding := 0
        if qNameLen < paddedLen {
            padding = paddedLen - qNameLen
        }
        if padding > 0 {
            paddingRR := &dns.PADDING{Padding: strings.Repeat("X", padding)}
            query.Pseudo = append(query.Pseudo, paddingRR)
            if query.UDPSize == 0 {
                query.UDPSize = uint16(dns.MaxMsgSize)
            }
        }

        if err := query.Pack(); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery := query.Data

        // netip.AddrPort is significantly faster than parsing to net.UDPAddr
        // However, we handle the string input here.
        udpAddrPort, err := netip.ParseAddrPort(serverAddress)
        var upstreamStr string
        
        if err == nil {
            // It is a valid IP:Port, skip resolution
            upstreamStr = udpAddrPort.String()
            if relay != nil {
                // Assuming proxy.prepareForRelay accepts netip.Addr now, or convert
                // NOTE: If prepareForRelay expects net.IP, you must convert it:
                proxy.prepareForRelay(udpAddrPort.Addr().AsSlice(), int(udpAddrPort.Port()), &binQuery)
                upstreamStr = relay.RelayUDPAddr.String()
            }
        } else {
            // Fallback for hostnames
            rAddr, err := net.ResolveUDPAddr("udp", serverAddress)
            if err != nil {
                return DNSExchangeResponse{err: err}
            }
            upstreamStr = rAddr.String()
            // Relay logic for hostname would require resolved IP
            if relay != nil {
                // Keep using net.IP for compatibility with existing code
                proxy.prepareForRelay(rAddr.IP, rAddr.Port, &binQuery)
                upstreamStr = relay.RelayUDPAddr.String()
            }
        }

        now := time.Now()

        // Modern Dialing
        dialer := net.Dialer{}
        pc, err := dialer.DialContext(ctx, "udp", upstreamStr)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        defer pc.Close()

        // Apply deadlines via Context or fallback
        if deadline, ok := ctx.Deadline(); ok {
            pc.SetDeadline(deadline)
        } else {
            pc.SetDeadline(time.Now().Add(proxy.timeout))
        }

        if _, err := pc.Write(binQuery); err != nil {
            return DNSExchangeResponse{err: err}
        }

        // We use the externally defined getBuffer/putBuffer from crypto.go
        buf := getBuffer(dns.MaxMsgSize)
        defer putBuffer(buf)

        // Read
        _, err = pc.Read(buf)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        rtt = time.Since(now)

        response := GetMsg()
        if err := response.Unpack(buf); err != nil {
            PutMsg(response)
            return DNSExchangeResponse{err: err}
        }

        return DNSExchangeResponse{response: response, rtt: rtt}
    }

    return DNSExchangeResponse{err: errors.New("protocol not supported")}
}
