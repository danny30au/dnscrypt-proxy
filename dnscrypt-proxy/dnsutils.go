package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

// EmptyResponseFromMessage creates an empty DNS response based on a source message.
func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	dstMsg := dns.Msg{MsgHdr: srcMsg.MsgHdr, Compress: true}
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	dstMsg.RecursionAvailable = true
	dstMsg.RecursionDesired = srcMsg.RecursionDesired
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false

	if edns0 := srcMsg.IsEdns0(); edns0 != nil {
		dstMsg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}

	return &dstMsg
}

// TruncatedResponse returns a truncated DNS response packet.
func TruncatedResponse(packet []byte) ([]byte, error) {
	srcMsg := dns.Msg{}
	if err := srcMsg.Unpack(packet); err != nil {
		return nil, err
	}

	dstMsg := EmptyResponseFromMessage(&srcMsg)
	dstMsg.Truncated = true

	return dstMsg.Pack()
}

// RefusedResponseFromMessage creates a refused or synthetic response message.
func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	// Create an empty response based on the source message
	dstMsg := EmptyResponseFromMessage(srcMsg)

	// Add Extended DNS Error (EDE) field
	ede := new(dns.EDNS0_EDE)
	if edns0 := dstMsg.IsEdns0(); edns0 != nil {
		edns0.Option = append(edns0.Option, ede)
	}

	ede.InfoCode = dns.ExtendedErrorCodeFiltered

	// Either return with refused code or a synthetic response
	if refusedCode {
		// Return a simple refused response
		dstMsg.Rcode = dns.RcodeRefused
	} else {
		// Return a synthetic response
		dstMsg.Rcode = dns.RcodeSuccess
		questions := srcMsg.Question

		if len(questions) == 0 {
			return dstMsg
		}

		question := questions[0]
		sendHInfoResponse := true

		// For A records, provide synthetic IPv4 if available
		if ipv4 != nil && question.Qtype == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ipv4.To4()

			if rr.A != nil {
				dstMsg.Answer = []dns.RR{rr}
				sendHInfoResponse = false
				ede.InfoCode = dns.ExtendedErrorCodeForgedAnswer
			}
		} else if ipv6 != nil && question.Qtype == dns.TypeAAAA {
			// For AAAA records, provide synthetic IPv6 if available
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ipv6.To16()

			if rr.AAAA != nil {
				dstMsg.Answer = []dns.RR{rr}
				sendHInfoResponse = false
				ede.InfoCode = dns.ExtendedErrorCodeForgedAnswer
			}
		}

		if sendHInfoResponse {
			hinfo := new(dns.HINFO)
			hinfo.Hdr = dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeHINFO,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			hinfo.Cpu = "This query has been locally blocked"
			hinfo.Os = "by dnscrypt-proxy"
			dstMsg.Answer = []dns.RR{hinfo}
		} else {
			ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
		}
	}

	return dstMsg
}

// HasTCFlag checks if the TC (truncated) flag is set in a DNS packet.
// Added bounds checking for safety.
func HasTCFlag(packet []byte) bool {
	if len(packet) < 3 {
		return false
	}
	return packet[2]&2 == 2
}

// TransactionID extracts the transaction ID from a DNS packet.
// Added bounds checking for safety.
func TransactionID(packet []byte) uint16 {
	if len(packet) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(packet[0:2])
}

// SetTransactionID sets the transaction ID in a DNS packet.
// Added bounds checking for safety.
func SetTransactionID(packet []byte, tid uint16) error {
	if len(packet) < 2 {
		return errors.New("packet too short to set transaction ID")
	}
	binary.BigEndian.PutUint16(packet[0:2], tid)
	return nil
}

// Rcode extracts the response code from a DNS packet.
// Added bounds checking for safety.
func Rcode(packet []byte) uint8 {
	if len(packet) < 4 {
		return 0
	}
	return packet[3] & 0xf
}

// NormalizeRawQName converts uppercase bytes to lowercase in-place.
// Improved readability with character constants instead of magic numbers.
func NormalizeRawQName(name *[]byte) {
	for i, c := range *name {
		if c >= 'A' && c <= 'Z' {
			(*name)[i] = c + ('a' - 'A')
		}
	}
}

// NormalizeQName normalizes a DNS query name to lowercase.
// Returns early if no uppercase letters are found (optimization).
func NormalizeQName(str string) (string, error) {
	if len(str) == 0 || str == "." {
		return ".", nil
	}

	hasUpper := false
	str = strings.TrimSuffix(str, ".")
	strLen := len(str)

	for i := 0; i < strLen; i++ {
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
	for i := 0; i < strLen; i++ {
		c := str[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}

	return b.String(), nil
}

// getMinTTL calculates the minimum TTL from a DNS message.
// Improved condition logic: removed redundant '<= 0' comparison.
func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
		(len(msg.Answer) == 0 && len(msg.Ns) == 0) {
		return time.Duration(cacheNegMinTTL) * time.Second
	}

	var ttl uint32
	if msg.Rcode == dns.RcodeSuccess {
		ttl = uint32(maxTTL)
	} else {
		ttl = uint32(cacheNegMaxTTL)
	}

	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		for _, rr := range msg.Ns {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
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

// setMaxTTL sets a maximum TTL cap on all resource records in a message.
// Optimized by caching header references to avoid repeated method calls.
func setMaxTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		header := rr.Header()
		if ttl < header.Ttl {
			header.Ttl = ttl
		}
	}

	for _, rr := range msg.Ns {
		header := rr.Header()
		if ttl < header.Ttl {
			header.Ttl = ttl
		}
	}

	for _, rr := range msg.Extra {
		header := rr.Header()
		if header.Rrtype == dns.TypeOPT {
			continue
		}

		if ttl < header.Ttl {
			header.Ttl = ttl
		}
	}
}

// updateTTL updates all TTL values in a message based on an expiration time.
func updateTTL(msg *dns.Msg, expiration time.Time) {
	until := time.Until(expiration)
	ttl := uint32(0)
	if until > 0 {
		ttl = uint32(until / time.Second)
		if until-time.Duration(ttl)*time.Second >= time.Second/2 {
			ttl++
		}
	}

	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}

	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}

	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

// hasEDNS0Padding checks if a DNS packet contains EDNS0 padding.
func hasEDNS0Padding(packet []byte) (bool, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return false, err
	}

	if edns0 := msg.IsEdns0(); edns0 != nil {
		for _, option := range edns0.Option {
			if option.Option() == dns.EDNS0PADDING {
				return true, nil
			}
		}
	}

	return false, nil
}

// addEDNS0PaddingIfNoneFound adds EDNS0 padding to a message if none exists.
// Optimized: removed unnecessary loop when creating padding (already zero-filled).
func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		edns0 = msg.IsEdns0()

		if edns0 == nil {
			return unpaddedPacket, nil
		}
	}

	for _, option := range edns0.Option {
		if option.Option() == dns.EDNS0PADDING {
			return unpaddedPacket, nil
		}
	}

	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, paddingLen) // Already zero-filled, no loop needed
	edns0.Option = append(edns0.Option, ext)

	return msg.Pack()
}

// removeEDNS0Options removes all EDNS0 options from a message.
func removeEDNS0Options(msg *dns.Msg) bool {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}

	edns0.Option = []dns.EDNS0{}
	return true
}

// dddToByte converts three ASCII digit bytes to a single byte value.
func dddToByte(s []byte) byte {
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

// isDigit is a helper function to check if a byte is a digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// PackTXTRR processes an escape sequence string and returns packed bytes.
// Optimized: eliminate unnecessary memory copy and pre-allocate capacity.
func PackTXTRR(s string) []byte {
	msg := make([]byte, 0, len(s)) // Pre-allocate capacity

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}

			if i+2 < len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]) {
				msg = append(msg, dddToByte([]byte(s[i:])))
				i += 2
			} else if s[i] == 't' {
				msg = append(msg, '\t')
			} else if s[i] == 'r' {
				msg = append(msg, '\r')
			} else if s[i] == 'n' {
				msg = append(msg, '\n')
			} else {
				msg = append(msg, s[i])
			}
		} else {
			msg = append(msg, s[i])
		}
	}

	return msg
}

// DNSExchangeResponse represents a DNS exchange response with metadata.
type DNSExchangeResponse struct {
	response         *dns.Msg
	rtt              time.Duration
	priority         int
	fragmentsBlocked bool
	err              error
}

// DNSExchange performs a DNS query with retry logic and fragment support detection.
// Parameters:
//   - proxy: The DNS proxy instance
//   - proto: Protocol ("udp" or "tcp")
//   - query: The DNS query message
//   - serverAddress: Server address (host:port)
//   - relay: Optional DNS relay
//   - serverName: Server name for logging
//   - tryFragmentsSupport: Whether to test fragment support
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
				queryCopy.Id += uint16(options)

				go func(query *dns.Msg, delay time.Duration) {
					time.Sleep(delay)
					option := DNSExchangeResponse{err: errors.New("canceled")}
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
			queryCopy.Id += uint16(options)

			go func(query *dns.Msg, delay time.Duration) {
				time.Sleep(delay)
				option := DNSExchangeResponse{err: errors.New("canceled")}
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
				err = errors.New("unable to reach the server")
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

// _dnsExchange performs the actual DNS exchange with specified parameters.
// Parameters:
//   - proxy: The DNS proxy instance
//   - proto: Protocol ("udp" or "tcp")
//   - query: The DNS query message
//   - serverAddress: Server address (host:port)
//   - relay: Optional DNS relay
//   - paddedLen: Desired padded packet length
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
		qNameLen, padding := len(query.Question[0].Name), 0
		if qNameLen < paddedLen {
			padding = paddedLen - qNameLen
		}

		if padding > 0 {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			ext := new(dns.EDNS0_PADDING)
			ext.Padding = make([]byte, padding)
			opt.Option = append(opt.Option, ext)
			query.Extra = []dns.RR{opt}
		}

		binQuery, err := query.Pack()
		if err != nil {
			return DNSExchangeResponse{err: err}
		}

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
		binQuery, err := query.Pack()
		if err != nil {
			return DNSExchangeResponse{err: err}
		}

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

	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return DNSExchangeResponse{err: err}
	}

	return DNSExchangeResponse{response: &msg, rtt: rtt, err: nil}
}
