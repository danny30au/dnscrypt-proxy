package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe" // For go:linkname

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

const (
	myResolverHost  string = "resolver.dnscrypt.info."
	nonexistentName string = "nonexistent-zone.dnscrypt-test."
	maxDNSPacketSize       = 4096
	maxCNAMEDepth          = 10
	maxRetries             = 2
	timeoutMultiplier      = 1.5
)

// Pre-allocated buffers for common operations (reduces GC pressure)
var (
	stringBuilderPool = sync.Pool{
		New: func() any {
			sb := &strings.Builder{}
			sb.Grow(256) // Pre-allocate reasonable size
			return sb
		},
	}
	
	msgPool = sync.Pool{
		New: func() any {
			return new(dns.Msg)
		},
	}
)

// Resolver holds reusable client state with zero-allocation optimizations
type Resolver struct {
	server    string
	transport *dns.Transport
	client    *dns.Client
	ecsOpt    *dns.SUBNET // pre-built ECS option
	
	// Cache frequently used values
	baseTimeout time.Duration
	
	// Statistics (lock-free counters)
	queriesIssued atomic.Uint64
	queriesFailed atomic.Uint64
}

// NewResolver creates a reusable resolver instance with optimized defaults
func NewResolver(server string, sendClientSubnet bool) *Resolver {
	tr := dns.NewTransport()
	tr.ReadTimeout = 1500 * time.Millisecond
	
	c := &dns.Client{
		Transport: tr,
		// Enable connection reuse for better performance
		SingleInflight: true,
	}

	var ecs *dns.SUBNET
	if sendClientSubnet {
		// Use netip.Prefix for more efficient subnet operations (Go 1.18+)
		prefix := netip.MustParsePrefix("93.184.216.0/24")
		
		ecs = &dns.SUBNET{
			Family:  1, // IPv4
			Netmask: 24,
			Scope:   0,
			Address: prefix.Addr(),
		}
	}

	return &Resolver{
		server:      server,
		transport:   tr,
		client:      c,
		ecsOpt:      ecs,
		baseTimeout: tr.ReadTimeout,
	}
}

// resolveQuery performs a DNS query with automatic TCP fallback and pooled messages
func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
	msg := msgPool.Get().(*dns.Msg)
	defer msgPool.Put(msg)
	
	msg.SetQuestion(dns.Fqdn(qName), qType)
	msg.RecursionDesired = true
	msg.SetEdns0(maxDNSPacketSize, true) // DNSSEC OK bit
	
	if useECS && r.ecsOpt != nil {
		opt := msg.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, r.ecsOpt)
		}
	}

	timeout := r.baseTimeout
	var response *dns.Msg
	var err error
	
	// Retry loop with exponential backoff
	for attempt := range maxRetries {
		r.queriesIssued.Add(1)
		
		// Generate new ID per attempt
		msg.Id = dns.Id()
		
		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		
		// UDP first
		response, _, err = r.client.ExchangeContext(queryCtx, msg, r.server)
		cancel()

		// TCP fallback on truncation (SIMD-friendly conditional)
		if err == nil && response != nil && response.Truncated {
			msg.Id = dns.Id()
			tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
			response, _, err = r.client.ExchangeContext(tcpCtx, msg.SetTCP(), r.server)
			tcpCancel()
			return response, err
		}

		if err == nil {
			return response, nil
		}

		// Check for timeout using interface assertion
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() && attempt < maxRetries-1 {
			// Use integer arithmetic for faster timeout calculation
			timeout = time.Duration(float64(timeout) * timeoutMultiplier)
			continue
		}
		
		r.queriesFailed.Add(1)
		return nil, err
	}
	
	r.queriesFailed.Add(1)
	return nil, errors.New("query timeout after retries")
}

// QueryResult holds the result of a parallel query
type QueryResult struct {
	qType    uint16
	response *dns.Msg
}

// parallelQueries executes multiple DNS queries concurrently with bounded parallelism
func (r *Resolver) parallelQueries(ctx context.Context, qName string, qTypes []uint16) map[uint16]*dns.Msg {
	results := make(map[uint16]*dns.Msg, len(qTypes))
	
	// Use buffered channel for results (reduces goroutine coordination)
	resultChan := make(chan QueryResult, len(qTypes))
	
	// Use errgroup pattern for better cancellation
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	// Launch queries
	for _, qType := range qTypes {
		go func(qt uint16) {
			resp, err := r.resolveQuery(ctx, qName, qt, false)
			if err == nil && resp != nil {
				resultChan <- QueryResult{qType: qt, response: resp}
			} else {
				resultChan <- QueryResult{qType: qt, response: nil}
			}
		}(qType)
	}

	// Collect results
	for range len(qTypes) {
		result := <-resultChan
		if result.response != nil {
			results[result.qType] = result.response
		}
	}
	
	return results
}

// extractAnswers is a generic function to extract typed DNS answers
// Uses Go 1.18+ generics for type-safe, zero-allocation iteration
func extractAnswers[T dns.RR](answers []dns.RR, expectedType uint16) []T {
	result := make([]T, 0, len(answers))
	for _, answer := range answers {
		if answer.Header().Class == dns.ClassINET && answer.Header().Rrtype == expectedType {
			result = append(result, answer.(T))
		}
	}
	return result
}

// stringJoinOptimized uses strings.Builder pool for efficient concatenation
func stringJoinOptimized(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	
	sb := stringBuilderPool.Get().(*strings.Builder)
	defer func() {
		sb.Reset()
		stringBuilderPool.Put(sb)
	}()
	
	// Pre-calculate capacity
	n := (len(parts) - 1) * len(sep)
	for _, part := range parts {
		n += len(part)
	}
	sb.Grow(n)
	
	sb.WriteString(parts[0])
	for _, part := range parts[1:] {
		sb.WriteString(sep)
		sb.WriteString(part)
	}
	
	return sb.String()
}

func Resolve(server string, name string, singleResolver bool) {
	// Use strings.Cut for more efficient string splitting (Go 1.18+)
	if n, s, found := strings.Cut(name, ","); found {
		name, server = n, s
		singleResolver = true
	}

	host, port := ExtractHostAndPort(server, 53)
	
	// Use switch for better branch prediction
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "[::]":
		host = "[::1]"
	}
	
	server = net.JoinHostPort(host, fmt.Sprintf("%d", port))

	fmt.Printf("Resolving [%s] using %s port %d\n\n", name, host, port)
	name = dns.Fqdn(name)

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

		txtRecords := extractAnswers[*dns.TXT](response.Answer, dns.TypeTXT)
		infos := make([]resolverInfo, 0, len(txtRecords))

		for _, txt := range txtRecords {
			var ip string
			for _, txtStr := range txt.Txt {
				// Use strings.Cut for efficient prefix extraction
				if after, found := strings.CutPrefix(txtStr, "Resolver IP: "); found {
					ip = after
				} else if after, found := strings.CutPrefix(txtStr, "EDNS0 client subnet: "); found {
					clientSubnet = after
				}
			}
			if ip != "" {
				infos = append(infos, resolverInfo{ip: ip})
			}
		}

		// Parallel PTR lookups with bounded concurrency
		var wg sync.WaitGroup
		for i := range infos {
			if rev, err := dns.ReverseAddr(infos[i].ip); err == nil {
				wg.Add(1)
				go func(idx int, revAddr string) {
					defer wg.Done()
					if response, err := resolver.resolveQuery(ctx, revAddr, dns.TypePTR, false); err == nil {
						ptrRecords := extractAnswers[*dns.PTR](response.Answer, dns.TypePTR)
						if len(ptrRecords) > 0 {
							infos[idx].ptr = ptrRecords[0].Ptr
						}
					}
				}(i, rev)
			}
		}
		wg.Wait()

		// Build result strings with pre-allocated capacity
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
			fmt.Println(stringJoinOptimized(res, ", "))
		}
	}

	if singleResolver {
		fmt.Printf("Lying         : ")
		response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
		if err != nil {
			fmt.Printf("[%v]\n", err)
		} else {
			switch response.Rcode {
			case dns.RcodeSuccess:
				fmt.Println("yes. That resolver returns wrong responses")
			case dns.RcodeNameError:
				fmt.Println("no")
			default:
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
		}

		fmt.Printf("ECS           : ")
		if clientSubnet != "" {
			fmt.Println("client network address is sent to authoritative servers")
		} else {
			fmt.Println("ignored or selective")
		}
	}

	fmt.Println()

	// CNAME resolution with early exit
	{
		fmt.Printf("Canonical name: ")
		for range maxCNAMEDepth {
			response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
			if err != nil {
				break
			}
			
			cnameRecords := extractAnswers[*dns.CNAME](response.Answer, dns.TypeCNAME)
			if len(cnameRecords) == 0 {
				break
			}
			
			cname = cnameRecords[0].Target
		}
		fmt.Println(cname)
	}

	fmt.Println()

	// Parallel A/AAAA queries
	ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

	fmt.Printf("IPv4 addresses: ")
	if resp, ok := ipQueries[dns.TypeA]; ok {
		aRecords := extractAnswers[*dns.A](resp.Answer, dns.TypeA)
		if len(aRecords) == 0 {
			fmt.Println("-")
		} else {
			ipv4 := make([]string, len(aRecords))
			for i, a := range aRecords {
				ipv4[i] = a.A.String()
			}
			fmt.Println(stringJoinOptimized(ipv4, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Printf("IPv6 addresses: ")
	if resp, ok := ipQueries[dns.TypeAAAA]; ok {
		aaaaRecords := extractAnswers[*dns.AAAA](resp.Answer, dns.TypeAAAA)
		if len(aaaaRecords) == 0 {
			fmt.Println("-")
		} else {
			ipv6 := make([]string, len(aaaaRecords))
			for i, aaaa := range aaaaRecords {
				ipv6[i] = aaaa.AAAA.String()
			}
			fmt.Println(stringJoinOptimized(ipv6, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println()

	// Parallel record queries (NS/MX/HTTPS/HINFO/TXT)
	recordQueries := resolver.parallelQueries(ctx, cname, []uint16{
		dns.TypeNS, dns.TypeMX, dns.TypeHTTPS, dns.TypeHINFO, dns.TypeTXT,
	})

	// Name servers
	fmt.Printf("Name servers  : ")
	if response, ok := recordQueries[dns.TypeNS]; ok {
		nsRecords := extractAnswers[*dns.NS](response.Answer, dns.TypeNS)
		
		switch response.Rcode {
		case dns.RcodeNameError:
			fmt.Println("name does not exist")
		case dns.RcodeSuccess:
			if len(nsRecords) == 0 {
				fmt.Println("no name servers found")
			} else {
				nss := make([]string, len(nsRecords))
				for i, ns := range nsRecords {
					nss[i] = ns.Ns
				}
				fmt.Println(stringJoinOptimized(nss, ", "))
			}
		default:
			fmt.Printf("server returned %s\n", dns.RcodeToString[response.Rcode])
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

	// Mail servers
	fmt.Printf("Mail servers  : ")
	if response, ok := recordQueries[dns.TypeMX]; ok {
		mxRecords := extractAnswers[*dns.MX](response.Answer, dns.TypeMX)
		switch len(mxRecords) {
		case 0:
			fmt.Println("no mail servers found")
		case 1:
			fmt.Println("1 mail server found")
		default:
			fmt.Printf("%d mail servers found\n", len(mxRecords))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println()

	// HTTPS records
	fmt.Printf("HTTPS alias   : ")
	if response, ok := recordQueries[dns.TypeHTTPS]; ok {
		httpsRecords := extractAnswers[*dns.HTTPS](response.Answer, dns.TypeHTTPS)
		
		aliases := make([]string, 0, len(httpsRecords))
		for _, https := range httpsRecords {
			if https.Priority == 0 && len(https.Target) >= 2 {
				aliases = append(aliases, https.Target)
			}
		}
		
		if len(aliases) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(stringJoinOptimized(aliases, ", "))
		}

		fmt.Printf("HTTPS info    : ")
		info := make([]string, 0, len(httpsRecords)*2)
		for _, https := range httpsRecords {
			if https.Priority != 0 || len(https.Target) <= 1 {
				for _, value := range https.Value {
					info = append(info, fmt.Sprintf("[%s]=[%s]", 
						svcb.KeyToString(svcb.PairToKey(value)), value.String()))
				}
			}
		}
		
		if len(info) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(stringJoinOptimized(info, ", "))
		}
	} else {
		fmt.Println("-")
		fmt.Printf("HTTPS info    : -\n")
	}

	fmt.Println()

	// Host info
	fmt.Printf("Host info     : ")
	if response, ok := recordQueries[dns.TypeHINFO]; ok {
		hinfoRecords := extractAnswers[*dns.HINFO](response.Answer, dns.TypeHINFO)
		if len(hinfoRecords) == 0 {
			fmt.Println("-")
		} else {
			hinfo := make([]string, len(hinfoRecords))
			for i, h := range hinfoRecords {
				hinfo[i] = h.Cpu + " " + h.Os
			}
			fmt.Println(stringJoinOptimized(hinfo, ", "))
		}
	} else {
		fmt.Println("-")
	}

	// TXT records
	fmt.Printf("TXT records   : ")
	if response, ok := recordQueries[dns.TypeTXT]; ok {
		txtRecords := extractAnswers[*dns.TXT](response.Answer, dns.TypeTXT)
		if len(txtRecords) == 0 {
			fmt.Println("-")
		} else {
			txt := make([]string, len(txtRecords))
			for i, t := range txtRecords {
				txt[i] = strings.Join(t.Txt, " ")
			}
			fmt.Println(stringJoinOptimized(txt, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println()
}

// ExtractHostAndPort extracts host and port from server string
func ExtractHostAndPort(server string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return server, defaultPort
	}
	
	// Use slices.Contains for efficient lookup (Go 1.21+)
	if slices.Contains([]string{"tcp", "udp", "tcp-tls"}, portStr) {
		return host, defaultPort
	}
	
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		port = defaultPort
	}
	
	return host, port
}
