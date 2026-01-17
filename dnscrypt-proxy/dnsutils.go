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

var msgPool = sync.Pool{
New: func() interface{} {
return new(dns.Msg)
},
}

func GetMsg() *dns.Msg {
return msgPool.Get().(*dns.Msg)
}

func PutMsg(m *dns.Msg) {
if m == nil {
return
}

q := m.Question[:0]
a := m.Answer[:0]
ns := m.Ns[:0]
ex := m.Extra[:0]
ps := m.Pseudo[:0]
data := m.Data[:0]

*m = dns.Msg{}
m.Question = q
m.Answer = a
m.Ns = ns
m.Extra = ex
m.Pseudo = ps
m.Data = data

msgPool.Put(m)
}

var (
blockedHinfoCPU = "This query has been locally blocked"
blockedHinfoOS  = "by dnscrypt-proxy"
)

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

func TruncatedResponse(packet []byte) ([]byte, error) {
plen := len(packet)
if plen < 12 {
return nil, errors.New("packet too short")
}

qdCount := binary.BigEndian.Uint16(packet[4:6])
offset := 12

if qdCount == 1 {
for offset < plen {
labelLen := packet[offset]
if (labelLen & 0xC0) == 0xC0 {
offset += 6
goto build
}
offset++
if labelLen == 0 {
offset += 4
goto build
}
offset += int(labelLen)
}
} else {
for i := uint16(0); i < qdCount; i++ {
for offset < plen {
labelLen := packet[offset]
if (labelLen & 0xC0) == 0xC0 {
offset += 2
break
}
offset++
if labelLen == 0 {
break
}
offset += int(labelLen)
}
offset += 4
}
}

build:
if offset > plen {
return nil, errors.New("packet malformed")
}

truncated := make([]byte, offset)
copy(truncated, packet[:offset])
truncated[2] |= 0x82

binary.BigEndian.PutUint16(truncated[6:8], 0)
binary.BigEndian.PutUint32(truncated[8:12], 0)

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

//go:inline
func HasTCFlag(packet []byte) bool {
return packet[2]&2 != 0
}

//go:inline
func TransactionID(packet []byte) uint16 {
return binary.BigEndian.Uint16(packet[0:2])
}

//go:inline
func SetTransactionID(packet []byte, tid uint16) {
binary.BigEndian.PutUint16(packet[0:2], tid)
}

//go:inline
func Rcode(packet []byte) uint8 {
return packet[3] & 0xf
}

func NormalizeRawQName(name *[]byte) {
b := *name
for i := range b {
c := b[i]
if c >= 'A' && c <= 'Z' {
b[i] = c + ('a' - 'A')
}
}
}

func NormalizeQName(str string) (string, error) {
n := len(str)
if n == 0 || str == "." {
return ".", nil
}

if str[n-1] == '.' {
str = str[:n-1]
n--
}

upperAt := -1
for i := 0; i < n; i++ {
c := str[i]
if c >= utf8.RuneSelf {
return str, errors.New("Query name is not an ASCII string")
}
if c >= 'A' && c <= 'Z' {
if upperAt < 0 {
upperAt = i
}
}
}

if upperAt < 0 {
return str, nil
}

b := unsafe.Slice(unsafe.StringData(str), n)
result := make([]byte, n)
copy(result, b)

for i := upperAt; i < n; i++ {
if result[i] >= 'A' && result[i] <= 'Z' {
result[i] = result[i] + ('a' - 'A')
}
}

return unsafe.String(&result[0], n), nil
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

rrs := msg.Answer
if len(rrs) == 0 {
rrs = msg.Ns
}

for i := range rrs {
if t := rrs[i].Header().TTL; t < ttl {
ttl = t
}
}

threshold := minTTL
if msg.Rcode != dns.RcodeSuccess {
threshold = cacheNegMinTTL
}

if ttl < threshold {
ttl = threshold
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

i++
if i >= len(s) {
break
}

if i+2 < len(s) {
a, b, c3 := s[i], s[i+1], s[i+2]
if (a-'0') < 10 && (b-'0') < 10 && (c3-'0') < 10 {
buf.WriteByte(dddToByte3(a, b, c3))
i += 2
continue
}
}

switch s[i] {
case 't':
buf.WriteByte(9)
case 'r':
buf.WriteByte(13)
case 'n':
buf.WriteByte(10)
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
qNameLen := len(query.Question[0].Header().Name)
padding := 0
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

buf := getBuffer(MaxDNSPacketSize)
defer putBuffer(buf)

length, err := pc.Read(buf)
if err != nil {
return DNSExchangeResponse{err: err}
}
rtt = time.Since(now)

packet = make([]byte, length)
copy(packet, buf[:length])
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
