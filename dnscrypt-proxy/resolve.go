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
)

type Resolver struct {
server    string
transport *dns.Transport
client    *dns.Client
ecsOpt    *dns.SUBNET
}

func NewResolver(server string, sendClientSubnet bool) *Resolver {
tr := dns.NewTransport()
tr.ReadTimeout = 1500 * time.Millisecond
c := &dns.Client{Transport: tr}

var ecs *dns.SUBNET
if sendClientSubnet {
// Use netip.Prefix for more efficient Go 1.26 address handling
prefix, _ := netip.ParsePrefix("93.184.216.0/24")

// Go 1.26 new(expr) pointer creation
ecs = &dns.SUBNET{
Family:  new(uint16(1)),
Netmask: uint8(prefix.Bits()),
Address: prefix.Addr(),
}
}

return &Resolver{
server:    server,
transport: tr,
client:    c,
ecsOpt:    ecs,
}
}

func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
msg := dns.NewMsg(qName, qType)
msg.RecursionDesired = true
msg.Opcode = dns.OpcodeQuery
msg.UDPSize = uint16(4096)
msg.Security = true

if useECS && r.ecsOpt != nil {
msg.Pseudo = append(msg.Pseudo, r.ecsOpt)
}

timeout := r.transport.ReadTimeout
for attempt := 0; attempt < 2; attempt++ {
queryCtx, cancel := context.WithTimeout(ctx, timeout)
response, _, err := r.client.Exchange(queryCtx, msg, "udp", r.server)
cancel()

if err == nil && response != nil && response.Truncated {
tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
response, _, err = r.client.Exchange(tcpCtx, msg, "tcp", r.server)
tcpCancel()
return response, err
}

if err == nil {
return response, nil
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
var mu sync.Mutex
var wg sync.WaitGroup

for _, qType := range qTypes {
// Utilize Go 1.25 sync.WaitGroup.Go for cleaner concurrency
wg.Go(func() {
resp, err := r.resolveQuery(ctx, qName, qType, false)
if err == nil && resp != nil {
mu.Lock()
results[qType] = resp
mu.Unlock()
}
})
}

wg.Wait()
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

fmt.Printf("Resolving [%s] using %s port %d

", name, host, port)
name = fqdn(name)

ctx := context.Background()
resolver := NewResolver(server, true)

cname := name
var clientSubnet string

response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
if err != nil {
fmt.Printf("Unable to resolve: [%s]
", err)
os.Exit(1)
}
fmt.Printf("Resolver      : ")

type resolverInfo struct {
ip  string
ptr string
}

// Optimization: Pre-allocate slice with capacity
infos := make([]resolverInfo, 0, len(response.Answer))

for _, answer := range response.Answer {
if answer.Header().Class != dns.ClassINET || dns.RRToType(answer) != dns.TypeTXT {
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

var wg sync.WaitGroup
for i := range infos {
if rev, err := reverseAddr(infos[i].ip); err == nil {
wg.Go(func() {
if response, err := resolver.resolveQuery(ctx, rev, dns.TypePTR, false); err == nil {
for _, answer := range response.Answer {
if dns.RRToType(answer) == dns.TypePTR && answer.Header().Class == dns.ClassINET {
infos[i].ptr = answer.(*dns.PTR).Ptr
break
}
}
}
})
}
}
wg.Wait()

res := make([]string, 0, len(infos))
for _, info := range infos {
if info.ptr != "" {
res = append(res, info.ip+" ("+info.ptr+")")
} else {
res = append(res, info.ip)
}
}

if len(res) == 0 {
fmt.Println("-")
} else {
fmt.Println(strings.Join(res, ", "))
}

if singleResolver {
fmt.Printf("Lying         : ")
response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
if err != nil {
fmt.Printf("[%v]", err)
} else {
if response.Rcode == dns.RcodeSuccess {
fmt.Println("yes. That resolver returns wrong responses")
} else if response.Rcode == dns.RcodeNameError {
fmt.Println("no")
} else {
fmt.Printf("unknown - query returned %s
", dns.RcodeToString[response.Rcode])
}

if response.Rcode == dns.RcodeNameError {
fmt.Printf("DNSSEC        : ")
if response.AuthenticatedData {
fmt.Println("yes, the resolver supports DNSSEC")
} else {
fmt.Println("no, the resolver doesn't support DNSSEC")
}
}
}

fmt.Printf("ECS           : ")
if clientSubnet != "" {
fmt.Println("client network address is sent to authoritative servers")
} else {
fmt.Println("ignored or selective")
}
}

fmt.Println("")

cname_loop:
for i := 0; i < 10; i++ {
fmt.Printf("Canonical name: ")
response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
if err != nil {
break cname_loop
}
found := false
for _, answer := range response.Answer {
if dns.RRToType(answer) == dns.TypeCNAME && answer.Header().Class == dns.ClassINET {
cname = answer.(*dns.CNAME).Target
found = true
break
}
}
if !found {
break
}
}
fmt.Println(cname)
fmt.Println("")

ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

fmt.Printf("IPv4 addresses: ")
if resp, ok := ipQueries[dns.TypeA]; ok {
ipv4 := make([]string, 0, len(resp.Answer))
for _, answer := range resp.Answer {
if dns.RRToType(answer) == dns.TypeA && answer.Header().Class == dns.ClassINET {
ipv4 = append(ipv4, answer.(*dns.A).A.String())
}
}
fmt.Println(strings.Join(ipv4, ", "))
} else {
fmt.Println("-")
}
}
