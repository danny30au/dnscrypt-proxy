package main

import (
"bufio"
"errors"
"fmt"
"net"
"net/netip"
"os"
"runtime"
"strings"
"sync"
"sync/atomic"

"codeberg.org/miekg/dns"
"codeberg.org/miekg/dns/rdata"
"github.com/jedisct1/dlog"
)

const DNSBufferSize = 4096

var (
ErrSyntaxError        = errors.New("syntax error for a captive portal rule")
ErrWildcardNotAllowed = errors.New("captive portal rule must use an exact host name")
)

var msgPool = sync.Pool{
New: func() interface{} {
return &dns.Msg{}
},
}

var bufferPool = sync.Pool{
New: func() interface{} {
buf := make([]byte, DNSBufferSize)
return &buf
},
}

type CaptivePortalEntryIPs []netip.Addr

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
wg         sync.WaitGroup
mu         sync.Mutex
conns      []*net.UDPConn
queryCount atomic.Uint64
errorCount atomic.Uint64
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
hdr := question.Header()
qtype := dns.RRToType(question)

if qtype != dns.TypeA && qtype != dns.TypeAAAA {
return nil
}

respMsg := EmptyResponseFromMessage(msg)
hdrTemplate := dns.Header{
Name:  hdr.Name,
Class: dns.ClassINET,
TTL:   1,
}

matchCount := 0
for _, ip := range ips {
if (qtype == dns.TypeA && ip.Is4()) || (qtype == dns.TypeAAAA && ip.Is6()) {
matchCount++
}
}

if matchCount == 0 {
return nil
}

respMsg.Answer = make([]dns.RR, 0, matchCount)

for _, ip := range ips {
if qtype == dns.TypeA && ip.Is4() {
respMsg.Answer = append(respMsg.Answer, &dns.A{
Hdr: hdrTemplate,
A:   rdata.A{Addr: ip},
})
} else if qtype == dns.TypeAAAA && ip.Is6() {
respMsg.Answer = append(respMsg.Answer, &dns.AAAA{
Hdr: hdrTemplate,
AAAA: rdata.AAAA{Addr: ip},
})
}
}

if dlog.ShouldLog(dlog.SeverityDebug) {
qTypeStr, ok := dns.TypeToString[qtype]
if !ok {
qTypeStr = fmt.Sprint(qtype)
}
dlog.Debugf("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)
}

return respMsg
}

func handlePacket(packet []byte, clientAddr *net.UDPAddr, conn *net.UDPConn, ipsMap *CaptivePortalMap, h *CaptivePortalHandler) {
msg := msgPool.Get().(*dns.Msg)
defer msgPool.Put(msg)

msg.Data = packet
if err := msg.Unpack(); err != nil {
h.errorCount.Add(1)
return
}

question, ips, ok := ipsMap.GetEntry(msg)
if !ok {
return
}

h.queryCount.Add(1)

respMsg := HandleCaptivePortalQuery(msg, question, ips)
if respMsg == nil {
return
}

if err := respMsg.Pack(); err == nil {
conn.WriteToUDP(respMsg.Data, clientAddr)
}
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

if err := clientPc.SetReadBuffer(2 * 1024 * 1024); err != nil {
dlog.Warnf("Failed to set read buffer: %v", err)
}
if err := clientPc.SetWriteBuffer(2 * 1024 * 1024); err != nil {
dlog.Warnf("Failed to set write buffer: %v", err)
}

h.mu.Lock()
h.conns = append(h.conns, clientPc)
h.mu.Unlock()

numReaders := runtime.NumCPU()
if numReaders > 4 {
numReaders = 4
}

for i := 0; i < numReaders; i++ {
h.wg.Add(1)
go func() {
defer h.wg.Done()

bufPtr := bufferPool.Get().(*[]byte)
buffer := *bufPtr
defer bufferPool.Put(bufPtr)

for {
length, clientAddr, err := clientPc.ReadFromUDP(buffer)
if err != nil {
var netErr *net.OpError
if errors.As(err, &netErr) || errors.Is(err, net.ErrClosed) {
return
}
h.errorCount.Add(1)
continue
}

packetCopy := make([]byte, length)
copy(packetCopy, buffer[:length])
handlePacket(packetCopy, clientAddr, clientPc, ipsMap, h)
}
}()
}

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

fileInfo, _ := file.Stat()
estimatedRules := 100
if fileInfo != nil && fileInfo.Size() > 0 {
estimatedRules = int(fileInfo.Size() / 40)
}

ipsMap := make(CaptivePortalMap, estimatedRules)
scanner := bufio.NewScanner(file)
buf := make([]byte, 128*1024)
scanner.Buffer(buf, 1024*1024)
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

ips := make([]netip.Addr, 0, 4)
for len(ipsStr) > 0 {
var ipStr string
ipStr, ipsStr, _ = strings.Cut(ipsStr, ",")
ipStr = strings.TrimSpace(ipStr)

if ipStr != "" {
ip, err := netip.ParseAddr(ipStr)
if err != nil {
return nil, fmt.Errorf("%w at line %d", ErrSyntaxError, lineNo)
}
ips = append(ips, ip)
}
}

if len(ips) > 0 {
ipsMap[name] = ips
}
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
