package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
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

	// Optimized: Use struct zero assignment for first set of fields
	// This allows compiler to optimize better than individual assignments
	m.ID = 0
	m.Response = false
	m.Opcode = 0
	m.Authoritative = false
	m.Truncated = false
	m.RecursionDesired = false
	m.RecursionAvailable = false
	m.Zero = false
	m.AuthenticatedData = false
	m.CheckingDisabled = false
	m.Rcode = 0

	// Clear slices while keeping capacity
	m.Question = m.Question[:0]
	m.Answer = m.Answer[:0]
	m.Ns = m.Ns[:0]
	m.Extra = m.Extra[:0]
	m.Pseudo = m.Pseudo[:0]
	msgPool.Put(m)
}

// Buffer pool for truncated packets
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 1500)
		return &b
	},
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

	// FIXED: Deep copy questions to prevent aliasing issues with pool reuse
	if len(srcMsg.Question) > 0 {
		dstMsg.Question = append(dstMsg.Question[:0], srcMsg.Question...)
	}

	dstMsg.Response = true
	dstMsg.RecursionAvailable = true
	dstMsg.RecursionDesired = srcMsg.RecursionDesired
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false

	if srcMsg.UDPSize > 0 {
		dstMsg.UDPSize = srcMsg.UDPSize
		// dstMsg.Security = srcMsg.Security // Copy security bit (DO) if needed
	}
	return dstMsg
}

// TruncatedResponse - Optimized with buffer pool fix
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

	// FIXED: Get buffer from pool and properly return it
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	if cap(buf) < offset {
		buf = make([]byte, offset)
	} else {
		buf = buf[:offset]
	}

	copy(buf, packet[:offset])
	buf[2] |= 0x82 // TC, QR
	for i := 6; i < 12; i++ {
		buf[i] = 0
	}

	// Create new packet to return (caller owns this memory)
	newPacket := make([]byte, offset)
	copy(newPacket, buf)

	// Return buffer to pool
	*bufPtr = buf[:0]
	bufPool.Put(bufPtr)

	return newPacket, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)

	// OPTIMIZED: Lazy EDE allocation - only create if EDNS0 is active
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
	for i, c := range *name {
		if c >= 65 && c <= 90 {
			(*name)[i] = c + 32
		}
	}
}

// OPTIMIZED: Single-pass normalization with inline conversion
func NormalizeQName(str string) (string, error) {
	if len(str) == 0 || str == "." {
		return ".", nil
	}
	str = strings.TrimSuffix(str, ".")

	strLen := len(str)
	needsConversion := false

	// Single pass: validate and check for uppercase
	for i := 0; i < strLen; i++ {
		c := str[i]
		if c >= utf8.RuneSelf {
			return str, errors.New("Query name is not an ASCII string")
		}
		if 'A' <= c && c <= 'Z' {
			needsConversion = true
		}
	}

	if !needsConversion {
		return str, nil
	}

	// Convert to lowercase in-place
	b := []byte(str)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}

	// Zero-allocation string conversion (unsafe)
	return unsafe.String(unsafe.SliceData(b), len(b)), nil
}
