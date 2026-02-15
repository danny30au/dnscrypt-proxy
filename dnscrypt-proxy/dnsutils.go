package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
)

const dnsHeaderLen = 12

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	// Keep behavior compatible with the codeberg/miekg/dns fork used by this project.
	// In this fork, Msg.Question is not a []dns.Question, so avoid referencing dns.Question.
	if srcMsg == nil {
		return &dns.Msg{}
	}
	// Copy only metadata required for a minimal response.
	dstMsg := &dns.Msg{}
	dstMsg.ID = srcMsg.ID
	dstMsg.Opcode = srcMsg.Opcode
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	dstMsg.RecursionAvailable = true
	dstMsg.RecursionDesired = srcMsg.RecursionDesired
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false
	if srcMsg.UDPSize > 0 {
		dstMsg.UDPSize = srcMsg.UDPSize
		dstMsg.Security = srcMsg.Security
	}
	return dstMsg
}

func TruncatedResponse(packet []byte) ([]byte, error) {
	if len(packet) < dnsHeaderLen {
		return nil, errors.New("dns packet too short")
	}
	srcMsg := dns.Msg{Data: packet}
	if err := srcMsg.Unpack(); err != nil {
		return nil, err
	}
	dstMsg := EmptyResponseFromMessage(&srcMsg)
	dstMsg.Truncated = true
	if err := dstMsg.Pack(); err != nil {
		return nil, err
	}
	return dstMsg.Data, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)

	// Add Extended DNS Error (EDE) to the pseudo section, but only if EDNS0 is enabled.
	ede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
	if dstMsg.UDPSize > 0 {
		dstMsg.Pseudo = append(dstMsg.Pseudo, ede)
	}

	if refusedCode {
		dstMsg.Rcode = dns.RcodeRefused
		return dstMsg
	}

	dstMsg.Rcode = dns.RcodeSuccess
	if srcMsg == nil || len(srcMsg.Question) == 0 {
		return dstMsg
	}

	question := srcMsg.Question[0]
	qtype := dns.RRToType(question)
	qname := question.Header().Name
	sendHInfo := true

	switch qtype {
	case dns.TypeA:
		if ipv4 != nil {
			ip4 := ipv4.To4()
			if ip4 != nil {
				var b4 [4]byte
				copy(b4[:], ip4)
				rr := &dns.A{
					Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
					A:   rdata.A{Addr: netip.AddrFrom4(b4)},
				}
				dstMsg.Answer = []dns.RR{rr}
				sendHInfo = false
				ede.InfoCode = dns.ExtendedErrorForgedAnswer
			}
		}

	case dns.TypeAAAA:
		if ipv6 != nil {
			ip6 := ipv6.To16()
			if ip6 != nil {
				var b16 [16]byte
				copy(b16[:], ip6)
				rr := &dns.AAAA{
					Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
					AAAA: rdata.AAAA{Addr: netip.AddrFrom16(b16)},
				}
				dstMsg.Answer = []dns.RR{rr}
				sendHInfo = false
				ede.InfoCode = dns.ExtendedErrorForgedAnswer
			}
		}
	}

	if sendHInfo {
		hinfo := &dns.HINFO{
			Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
			HINFO: rdata.HINFO{
				Cpu: "This query has been locally blocked",
				Os:  "by dnscrypt-proxy",
			},
		}
		dstMsg.Answer = []dns.RR{hinfo}
	} else {
		ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
	}

	return dstMsg
}

func HasTCFlag(packet []byte) bool {
	return len(packet) >= dnsHeaderLen && (packet[2]&2 == 2)
}

func TransactionID(packet []byte) uint16 {
	if len(packet) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(packet[0:2])
}

func SetTransactionID(packet []byte, tid uint16) {
	if len(packet) < 2 {
		return
	}
	binary.BigEndian.PutUint16(packet[0:2], tid)
}

func Rcode(packet []byte) uint8 {
	if len(packet) < 4 {
		return 0
	}
	return packet[3] & 0xf
}

func NormalizeRawQName(name *[]byte) {
	if name == nil {
		return
	}
	for i, c := range *name {
		if 'A' <= c && c <= 'Z' {
			(*name)[i] = c + ('a' - 'A')
		}
	}
}

func NormalizeQName(str string) (string, error) {
	if len(str) == 0 || str == "." {
		return ".", nil
	}
	str = strings.TrimSuffix(str, ".")

	hasUpper := false
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c >= utf8.RuneSelf {
			return str, errors.New("query name is not an ASCII string")
		}
		hasUpper = hasUpper || ('A' <= c && c <= 'Z')
	}
	if !hasUpper {
		return str, nil
	}

	var b strings.Builder
	b.Grow(len(str))
	for i := 0; i < len(str); i++ {
		c := str[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

func getMinTTL(msg *dns.Msg, minTTL, maxTTL, cacheNegMinTTL, cacheNegMaxTTL uint32) time.Duration {
	if msg == nil {
		return time.Duration(cacheNegMinTTL) * time.Second
	}
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || (len(msg.Answer) == 0 && len(msg.Ns) == 0) {
		return time.Duration(cacheNegMinTTL) * time.Second
	}

	ttl := maxTTL
	if msg.Rcode != dns.RcodeSuccess {
		ttl = cacheNegMaxTTL
	}

	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if rr.Header().TTL < ttl {
				ttl = rr.Header().TTL
			}
		}
	} else {
		for _, rr := range msg.Ns {
			if rr.Header().TTL < ttl {
				ttl = rr.Header().TTL
			}
		}
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
	if msg == nil {
		return
	}
	until := time.Until(expiration)
	ttl := uint32(0)
	if until > 0 {
		ttl = uint32(until / time.Second)
		if until-time.Duration(ttl)*time.Second >= time.Second/2 {
			ttl++
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
	if len(packet) < dnsHeaderLen {
		return false, errors.New("dns packet too short")
	}
	msg := dns.Msg{Data: packet}
	if err := msg.Unpack(); err != nil {
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
	if msg == nil {
		return nil, errors.New("dns message is nil")
	}
	if paddingLen <= 0 {
		return unpaddedPacket, nil
	}

	if msg.UDPSize == 0 {
		msg.UDPSize = uint16(MaxDNSPacketSize)
	}
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			return unpaddedPacket, nil
		}
	}

	// Preserve original behavior: padding is encoded as hex; 0x58 repeated.
	paddingRR := &dns.PADDING{Padding: strings.Repeat("58", paddingLen)}
	msg.Pseudo = append(msg.Pseudo, paddingRR)
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	return msg.Data, nil
}

func removeEDNS0Options(msg *dns.Msg) bool {
	if msg == nil || len(msg.Pseudo) == 0 {
		return false
	}
	msg.Pseudo = nil
	return true
}

func dddToByte(s []byte) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	n := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}

func PackTXTRR(s string) []byte {
	bs := []byte(s)
	msg := make([]byte, 0, len(bs))

	for i := 0; i < len(bs); i++ {
		if bs[i] != '\\' {
			msg = append(msg, bs[i])
			continue
		}
		i++
		if i >= len(bs) {
			break
		}
		if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
			if b, ok := dddToByte(bs[i:]); ok {
				msg = append(msg, b)
			}
			i += 2
			continue
		}
		switch bs[i] {
		case 't':
			msg = append(msg, '\t')
		case 'r':
			msg = append(msg, '\r')
		case 'n':
			msg = append(msg, '\n')
		default:
			msg = append(msg, bs[i])
		}
	}
	return msg
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
		ctx, cancel := context.WithCancel(context.Background())

		const maxTries = 3
		channel := make(chan DNSExchangeResponse, 2*maxTries)
		var lastErr error
		options := 0

		var cancelOnce sync.Once
		cancelAll := func() { cancelOnce.Do(cancel) }

		for tries := 0; tries < maxTries; tries++ {
			if tryFragmentsSupport {
				queryCopy := query.Copy()
				queryCopy.ID += uint16(options)
				options++
				go func(q *dns.Msg, delay time.Duration) {
					t := time.NewTimer(delay)
					defer t.Stop()
					select {
					case <-ctx.Done():
						channel <- DNSExchangeResponse{err: context.Canceled}
						return
					case <-t.C:
					}
					opt := _dnsExchange(proxy, proto, q, serverAddress, relay, 1500)
					opt.fragmentsBlocked = false
					opt.priority = 0
					channel <- opt
				}(queryCopy, time.Duration(200*tries)*time.Millisecond)
			}

			queryCopy := query.Copy()
			queryCopy.ID += uint16(options)
			options++
			go func(q *dns.Msg, delay time.Duration) {
				t := time.NewTimer(delay)
				defer t.Stop()
				select {
				case <-ctx.Done():
					channel <- DNSExchangeResponse{err: context.Canceled}
					return
				case <-t.C:
				}
				opt := _dnsExchange(proxy, proto, q, serverAddress, relay, 480)
				opt.fragmentsBlocked = true
				opt.priority = 1
				channel <- opt
			}(queryCopy, time.Duration(250*tries)*time.Millisecond)
		}

		var best *DNSExchangeResponse
		for i := 0; i < options; i++ {
			resp := <-channel
			if resp.err == nil {
				if best == nil || resp.priority < best.priority || (resp.priority == best.priority && resp.rtt < best.rtt) {
					best = &resp
					if best.priority == 0 {
						cancelAll()
						break
					}
				}
				continue
			}
			if lastErr == nil {
				lastErr = resp.err
			}
		}

		cancelAll()

		if best != nil {
			if serverName != nil {
				if best.fragmentsBlocked {
					dlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *serverName)
				} else {
					dlog.Debugf("[%v] public key retrieval succeeded", *serverName)
				}
			}
			return best.response, best.rtt, best.fragmentsBlocked, nil
		}

		if relay == nil || !proxy.anonDirectCertFallback {
			if lastErr == nil {
				lastErr = errors.New("unable to reach the server")
			}
			return nil, 0, false, lastErr
		}

		if serverName != nil {
			dlog.Infof(
				"Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
				*serverName,
				relay.RelayUDPAddr.IP,
			)
		}
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
			paddingRR := &dns.PADDING{Padding: strings.Repeat("00", padding)}
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
			pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
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
	return DNSExchangeResponse{response: &msg, rtt: rtt}
}
