package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

const (
	myResolverHost  string = "resolver.dnscrypt.info."
	nonexistentName string = "nonexistent-zone.dnscrypt-test."
	tcpTimeoutMult  = 2 // TCP timeout = UDP timeout * this
)

// Resolver holds reusable client state to avoid per-query allocations
type Resolver struct {
	server    string
	transport *dns.Transport
	client    *dns.Client
	ecsOpt    *dns.SUBNET // pre-built ECS option
	msgPool   sync.Pool   // Reuse *dns.Msg across queries
}

// NewResolver creates a reusable resolver instance with optimized pooling
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
				return &dns.Msg{}
			},
		},
	}
}

// resolveQuery performs a DNS query with automatic TCP fallback on truncation
// Optimized: reuses message objects, better timeout handling, reduced allocations
func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
	msg := r.msgPool.Get().(*dns.Msg)
	defer r.msgPool.Put(msg)
	msg.SetQuestion(qName, qType)
	msg.RecursionDesired = true
	msg.Opcode = dns.OpcodeQuery
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

	if useECS && r.ecsOpt != nil {
		msg.Pseudo = append(msg.Pseudo[:0], r.ecsOpt) // Reuse slice capacity
	}

	udpTimeout := r.transport.ReadTimeout
	tcpTimeout := udpTimeout * time.Duration(tcpTimeoutMult)

	// Single attempt - UDP with TCP fallback
	msg.ID = dns.ID()

	queryCtx, cancel := context.WithTimeout(ctx, udpTimeout)
	response, _, err := r.client.Exchange(queryCtx, msg, "udp", r.server)
	cancel()

	// TCP fallback on truncation
	if err == nil && response != nil && response.Truncated {
		msg.ID = dns.ID()
		tcpCtx, tcpCancel := context.WithTimeout(ctx, tcpTimeout)
		response, _, err = r.client.Exchange(tcpCtx, msg, "tcp", r.server)
		tcpCancel()
		return response, err
	}

	return response, err
}

// parallelQueries executes multiple DNS queries concurrently with lock-free result collection
func (r *Resolver) parallelQueries(ctx context.Context, qName string, qTypes []uint16) map[uint16]*dns.Msg {
	results := make(map[uint16]*dns.Msg, len(qTypes))
	resultsChan := make(chan struct {
		qType uint16
		msg   *dns.Msg
	}, len(qTypes))

	var wg sync.WaitGroup
	for _, qType := range qTypes {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			if resp, err := r.resolveQuery(ctx, qName, qt, false); err == nil && resp != nil {
				resultsChan <- struct {
					qType uint16
					msg   *dns.Msg
				}{qType: qt, msg: resp}
			}
		}(qType)
	}

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		results[result.qType] = result.msg
	}
	return results
}

// parseTXTFields efficiently extracts IP and ECS from TXT records
func parseTXTFields(txt []string) (ip, clientSubnet string) {
	for _, line := range txt {
		if strings.HasPrefix(line, "Resolver IP: ") {
			ip = line[13:] // Direct slice instead of TrimPrefix
		} else if strings.HasPrefix(line, "EDNS0 client subnet: ") {
			clientSubnet = line[21:]
		}
	}
	return
}

// Resolve queries DNS resolver capabilities and target records
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

	ctx := context.Background()
	resolver := NewResolver(server, true)

	cname := name
	var clientSubnet string

	// Resolver identification with parallel PTR lookups
	{
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

		// Pre-allocate with exact capacity if possible
		infos := make([]resolverInfo, 0, len(response.Answer))

		for _, answer := range response.Answer {
			if answer.Header().Class != dns.ClassINET || dns.RRToType(answer) != dns.TypeTXT {
				continue
			}
			ip, cs := parseTXTFields(answer.(*dns.TXT).Txt)
			if cs != "" {
				clientSubnet = cs
			}
			if ip != "" {
				infos = append(infos, resolverInfo{ip: ip})
			}
		}

		// Parallel PTR lookups with result channel
		type ptrResult struct {
			idx int
			ptr string
		}
		ptrChan := make(chan ptrResult, len(infos))
		var wg sync.WaitGroup

		for i := range infos {
			if rev, err := reverseAddr(infos[i].ip); err == nil {
				wg.Add(1)
				go func(idx int, revAddr string) {
					defer wg.Done()
					if response, err := resolver.resolveQuery(ctx, revAddr, dns.TypePTR, false); err == nil {
						for _, answer := range response.Answer {
							if dns.RRToType(answer) == dns.TypePTR && answer.Header().Class == dns.ClassINET {
								ptrChan <- ptrResult{idx: idx, ptr: answer.(*dns.PTR).Ptr}
								return
							}
						}
					}
				}(i, rev)
			}
		}

		wg.Wait()
		close(ptrChan)

		// Apply PTR results
		for result := range ptrChan {
			infos[result.idx].ptr = result.ptr
		}

		// Format output with pre-built strings.Builder for efficiency
		var sb strings.Builder
		for i, info := range infos {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(info.ip)
			if info.ptr != "" {
				sb.WriteString(" (")
				sb.WriteString(info.ptr)
				sb.WriteString(")")
			}
		}

		if sb.Len() == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(sb.String())
		}
	}

	if singleResolver {
		fmt.Printf("Lying         : ")
		response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
		if err != nil {
			fmt.Printf("[%v]\n", err)
		} else if response.Rcode == dns.RcodeSuccess {
			fmt.Println("yes. That resolver returns wrong responses")
		} else if response.Rcode == dns.RcodeNameError {
			fmt.Println("no")
			fmt.Printf("DNSSEC        : ")
			if response.AuthenticatedData {
				fmt.Println("yes, the resolver supports DNSSEC")
			} else {
				fmt.Println("no, the resolver doesn't support DNSSEC")
			}
		} else {
			fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
		}

		fmt.Printf("ECS           : ")
		if clientSubnet != "" {
			fmt.Println("client network address is sent to authoritative servers")
		} else {
			fmt.Println("ignored or selective")
		}
	}

	fmt.Println("")

	// CNAME resolution with early exit and string reuse
	fmt.Printf("Canonical name: ")
	const maxCNAMEHops = 10
	for i := 0; i < maxCNAMEHops; i++ {
		response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
		if err != nil {
			break
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

	// Parallel A/AAAA queries with optimized result formatting
	ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

	// Format IPv4
	fmt.Printf("IPv4 addresses: ")
	if resp, ok := ipQueries[dns.TypeA]; ok {
		ipv4 := make([]string, 0, len(resp.Answer))
		for _, answer := range resp.Answer {
			if dns.RRToType(answer) == dns.TypeA && answer.Header().Class == dns.ClassINET {
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

	// Format IPv6 (assuming this continues in original code)
	fmt.Printf("IPv6 addresses: ")
	if resp, ok := ipQueries[dns.TypeAAAA]; ok {
		ipv6 := make([]string, 0, len(resp.Answer))
		for _, answer := range resp.Answer {
			if dns.RRToType(answer) == dns.TypeAAAA && answer.Header().Class == dns.ClassINET {
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
}
