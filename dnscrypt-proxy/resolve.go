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
myResolverHost  string = "resolver.dnscrypt.info."
nonexistentName string = "nonexistent-zone.dnscrypt-test."
MaxDNSPacketSize = 1232
)

type resultPair struct {
qType uint16
msg   *dns.Msg
}

type Resolver struct {
server    string
transport *dns.Transport
client    *dns.Client
ecsOpt    *dns.SUBNET
msgPool   sync.Pool
}

func NewResolver(server string, sendClientSubnet bool) *Resolver {
tr := dns.NewTransport()
tr.ReadTimeout = 1500 * time.Millisecond

c := &dns.Client{Transport: tr}

var ecs *dns.SUBNET
if sendClientSubnet {
subnet := net.IPNet{IP: net.IPv4(93, 184, 216, 0), Mask: net.CIDRMask(24, 32)}
bits, totalSize := subnet.Mask.Size()
var family uint16
if totalSize == 32 {
family = 1
} else if totalSize == 128 {
family = 2
}
addr, _ := netip.AddrFromSlice(subnet.IP)
ecs = &dns.SUBNET{
Family:  family,
Netmask: uint8(bits),
Scope:   0,
Address: addr,
}
}

return &Resolver{
server:    server,
transport: tr,
client:    c,
ecsOpt:    ecs,
msgPool: sync.Pool{
New: func() interface{} {
return new(dns.Msg)
},
},
}
}

func (r *Resolver) getMessage() *dns.Msg {
return r.msgPool.Get().(*dns.Msg)
}

func (r *Resolver) putMessage(msg *dns.Msg) {
if msg != nil {
msg.Answer = nil
msg.Ns = nil
msg.Extra = nil
msg.Pseudo = nil
msg.Question = nil
r.msgPool.Put(msg)
}
}

func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
msg := r.getMessage()
defer r.putMessage(msg)

msg.SetQuestion(dns.Fqdn(qName), qType)
msg.RecursionDesired = true
msg.SetEdns0(MaxDNSPacketSize, true)

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

if err == nil && response != nil {
if response.Truncated {
msg.Id = dns.Id()
tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
response, _, err = r.client.ExchangeContext(tcpCtx, msg, r.server)
tcpCancel()
if err == nil {
return response.Copy(), nil
}
return nil, err
}
return response.Copy(), nil
}

if errors.Is(err, context.DeadlineExceeded) {
timeout = timeout * 3 / 2
continue
}
if errors.Is(err, context.Canceled) {
return nil, err
}
if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
timeout = timeout * 3 / 2
continue
}
return nil, err
}
return nil, errors.New("timeout")
}

func (r *Resolver) parallelQueries(ctx context.Context, qName string, qTypes []uint16) map[uint16]*dns.Msg {
results := make(map[uint16]*dns.Msg, len(qTypes))
resultCh := make(chan resultPair, len(qTypes))
queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
defer cancel()

for _, qType := range qTypes {
go func(qt uint16) {
if resp, err := r.resolveQuery(queryCtx, qName, qt, false); err == nil && resp != nil {
resultCh <- resultPair{qType: qt, msg: resp}
}
}(qType)
}

for i := 0; i < len(qTypes); i++ {
select {
case res := <-resultCh:
results[res.qType] = res.msg
case <-queryCtx.Done():
return results
}
}
return results
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

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resolver := NewResolver(server, true)

cname := name
var clientSubnet string

for once := true; once; once = false {
response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
if err != nil {
fmt.Printf("Unable to resolve: [%s]\n", err)
os.Exit(1)
}
fmt.Printf("Resolver      : ")

type resolverInfo struct {
ip  string
ptr string
}

infos := make([]resolverInfo, 0, len(response.Answer))

for _, answer := range response.Answer {
if answer.Header().Class != dns.ClassINET || answer.Header().Rrtype != dns.TypeTXT {
continue
}
var ip string
for _, txt := range answer.(*dns.TXT).Txt {
if strings.HasPrefix(txt, "Resolver IP: ") {
ip = strings.TrimPrefix(txt, "Resolver IP: ")
} else if strings.HasPrefix(txt, "EDNS0 client subnet: ") {
clientSubnet = strings.TrimPrefix(txt, "EDNS0 client subnet: ")
}
}
if ip != "" {
infos = append(infos, resolverInfo{ip: ip})
}
}

ptrCtx, ptrCancel := context.WithTimeout(ctx, 2*time.Second)
var wg sync.WaitGroup
for i := range infos {
if rev, err := reverseAddr(infos[i].ip); err == nil {
wg.Add(1)
go func(idx int, revAddr string) {
defer wg.Done()
if response, err := resolver.resolveQuery(ptrCtx, revAddr, dns.TypePTR, false); err == nil {
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypePTR && answer.Header().Class == dns.ClassINET {
infos[idx].ptr = answer.(*dns.PTR).Ptr
break
}
}
}
}(i, rev)
}
}
wg.Wait()
ptrCancel()

res := make([]string, 0, len(infos))
var sb strings.Builder
for _, info := range infos {
if info.ptr != "" {
sb.WriteString(info.ip)
sb.WriteString(" (")
sb.WriteString(info.ptr)
sb.WriteString(")")
res = append(res, sb.String())
sb.Reset()
} else {
res = append(res, info.ip)
}
}

if len(res) == 0 {
fmt.Println("-")
} else {
fmt.Println(strings.Join(res, ", "))
}
}

if singleResolver {
for once := true; once; once = false {
fmt.Printf("Lying         : ")
response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
if err != nil {
fmt.Printf("[%v]", err)
break
}
if response.Rcode == dns.RcodeSuccess {
fmt.Println("yes. That resolver returns wrong responses")
} else if response.Rcode == dns.RcodeNameError {
fmt.Println("no")
} else {
fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
}

if response.Rcode == dns.RcodeNameError {
fmt.Printf("DNSSEC        : ")
if response.AuthenticatedData {
fmt.Println("yes, the resolver supports DNSSEC")
} else {
fmt.Println("no, the resolver doesn't support DNSSEC")
}
}

fmt.Printf("ECS           : ")
if clientSubnet != "" {
fmt.Println("client network address is sent to authoritative servers")
} else {
fmt.Println("ignored or selective")
}
}
}

fmt.Println("")

cname:
for once := true; once; once = false {
fmt.Printf("Canonical name: ")
for i := 0; i < 5; i++ {
response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
if err != nil {
break cname
}
found := false
for _, answer := range response.Answer {
if answer.Header().Rrtype != dns.TypeCNAME || answer.Header().Class != dns.ClassINET {
continue
}
cname = answer.(*dns.CNAME).Target
found = true
break
}
if !found {
break
}
}
fmt.Println(cname)
}

fmt.Println("")

ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

fmt.Printf("IPv4 addresses: ")
if resp, ok := ipQueries[dns.TypeA]; ok {
ipv4 := make([]string, 0, len(resp.Answer))
for _, answer := range resp.Answer {
if answer.Header().Rrtype == dns.TypeA && answer.Header().Class == dns.ClassINET {
ipv4 = append(ipv4, answer.(*dns.A).A.String())
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
if answer.Header().Rrtype == dns.TypeAAAA && answer.Header().Class == dns.ClassINET {
ipv6 = append(ipv6, answer.(*dns.AAAA).AAAA.String())
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

fmt.Printf("Name servers  : ")
if response, ok := recordQueries[dns.TypeNS]; ok {
nss := make([]string, 0, len(response.Answer))
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeNS && answer.Header().Class == dns.ClassINET {
nss = append(nss, answer.(*dns.NS).Ns)
}
}
if response.Rcode == dns.RcodeNameError {
fmt.Println("name does not exist")
} else if response.Rcode != dns.RcodeSuccess {
fmt.Printf("server returned %s", dns.RcodeToString[response.Rcode])
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

fmt.Printf("Mail servers  : ")
if response, ok := recordQueries[dns.TypeMX]; ok {
mxs := make([]string, 0, len(response.Answer))
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeMX && answer.Header().Class == dns.ClassINET {
mxs = append(mxs, answer.(*dns.MX).Mx)
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

fmt.Printf("HTTPS alias   : ")
if response, ok := recordQueries[dns.TypeHTTPS]; ok {
aliases := make([]string, 0, len(response.Answer))
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
https := answer.(*dns.HTTPS)
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

fmt.Printf("HTTPS info    : ")
info := make([]string, 0, len(response.Answer)*2)
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
https := answer.(*dns.HTTPS)
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
fmt.Printf("HTTPS info    : -\n")
}

fmt.Println("")

fmt.Printf("Host info     : ")
if response, ok := recordQueries[dns.TypeHINFO]; ok {
hinfo := make([]string, 0, len(response.Answer))
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeHINFO && answer.Header().Class == dns.ClassINET {
hinfo = append(hinfo, fmt.Sprintf("%s %s", answer.(*dns.HINFO).Cpu, answer.(*dns.HINFO).Os))
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

fmt.Printf("TXT records   : ")
if response, ok := recordQueries[dns.TypeTXT]; ok {
txt := make([]string, 0, len(response.Answer))
for _, answer := range response.Answer {
if answer.Header().Rrtype == dns.TypeTXT && answer.Header().Class == dns.ClassINET {
txt = append(txt, strings.Join(answer.(*dns.TXT).Txt, " "))
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
