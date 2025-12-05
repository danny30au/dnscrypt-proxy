package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	myResolverHost  string = "resolver.dnscrypt.info."
	nonexistentName string = "nonexistent-zone.dnscrypt-test."
)

var (
	// Reusable client pool for better performance
	clientPool = sync.Pool{
		New: func() interface{} {
			return &dns.Client{
				ReadTimeout: 2 * time.Second,
			}
		},
	}
)

func resolveQuery(server string, qName string, qType uint16, sendClientSubnet bool) (*dns.Msg, error) {
	client := clientPool.Get().(*dns.Client)
	defer clientPool.Put(client)

	// Reset timeout in case it was modified
	client.ReadTimeout = 2 * time.Second

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	options := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}

	if sendClientSubnet {
		subnet := net.IPNet{IP: net.IPv4(93, 184, 216, 0), Mask: net.CIDRMask(24, 32)}
		prr := dns.EDNS0_SUBNET{}
		prr.Code = dns.EDNS0SUBNET
		bits, totalSize := subnet.Mask.Size()
		if totalSize == 32 {
			prr.Family = 1
		} else if totalSize == 128 { // if we want to test with IPv6
			prr.Family = 2
		}
		prr.SourceNetmask = uint8(bits)
		prr.SourceScope = 0
		prr.Address = subnet.IP
		options.Option = append(options.Option, &prr)
	}

	msg.Extra = append(msg.Extra, options)
	options.SetDo()
	options.SetUDPSize(uint16(MaxDNSPacketSize))

	msg.Question[0] = dns.Question{Name: qName, Qtype: qType, Qclass: dns.ClassINET}
	for i := 0; i < 3; i++ {
		msg.Id = dns.Id()
		response, rtt, err := client.Exchange(msg, server)
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			client.ReadTimeout *= 2
			continue
		}
		_ = rtt
		if err != nil {
			return nil, fmt.Errorf("query failed: %w", err)
		}
		if response == nil {
			return nil, errors.New("received nil response")
		}
		return response, nil
	}
	return nil, errors.New("timeout after 3 attempts")
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
	name = dns.Fqdn(name)

	cname := name
	var clientSubnet string

	// Resolver information
	response, err := resolveQuery(server, myResolverHost, dns.TypeTXT, true)
	if err != nil {
		fmt.Printf("Unable to resolve: [%s]\n", err)
		os.Exit(1)
	}
	fmt.Printf("Resolver      : ")
	res := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if answer.Header().Class != dns.ClassINET || answer.Header().Rrtype != dns.TypeTXT {
			continue
		}
		txtRecord, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		var ip string
		for _, txt := range txtRecord.Txt {
			if strings.HasPrefix(txt, "Resolver IP: ") {
				ip = strings.TrimPrefix(txt, "Resolver IP: ")
			} else if strings.HasPrefix(txt, "EDNS0 client subnet: ") {
				clientSubnet = strings.TrimPrefix(txt, "EDNS0 client subnet: ")
			}
		}
		if ip == "" {
			continue
		}
		if rev, err := dns.ReverseAddr(ip); err == nil {
			response, err = resolveQuery(server, rev, dns.TypePTR, false)
			if err != nil {
				res = append(res, ip)
				continue
			}
			for _, answer := range response.Answer {
				if answer.Header().Rrtype != dns.TypePTR || answer.Header().Class != dns.ClassINET {
					continue
				}
				if ptrRecord, ok := answer.(*dns.PTR); ok {
					ip = ip + " (" + ptrRecord.Ptr + ")"
					break
				}
			}
		}
		res = append(res, ip)
	}
	if len(res) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(res, ", "))
	}

	if singleResolver {
		fmt.Printf("Lying         : ")
		response, err := resolveQuery(server, nonexistentName, dns.TypeA, false)
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

	// Resolve CNAME chain
	fmt.Printf("Canonical name: ")
	for i := 0; i < 100; i++ {
		response, err := resolveQuery(server, cname, dns.TypeCNAME, false)
		if err != nil {
			break
		}
		found := false
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeCNAME || answer.Header().Class != dns.ClassINET {
				continue
			}
			if cnameRecord, ok := answer.(*dns.CNAME); ok {
				cname = cnameRecord.Target
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

	// IPv4 addresses
	fmt.Printf("IPv4 addresses: ")
	response, err = resolveQuery(server, cname, dns.TypeA, false)
	if err == nil {
		ipv4 := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeA || answer.Header().Class != dns.ClassINET {
				continue
			}
			if aRecord, ok := answer.(*dns.A); ok {
				ipv4 = append(ipv4, aRecord.A.String())
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

	// IPv6 addresses
	fmt.Printf("IPv6 addresses: ")
	response, err = resolveQuery(server, cname, dns.TypeAAAA, false)
	if err == nil {
		ipv6 := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeAAAA || answer.Header().Class != dns.ClassINET {
				continue
			}
			if aaaaRecord, ok := answer.(*dns.AAAA); ok {
				ipv6 = append(ipv6, aaaaRecord.AAAA.String())
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

	// Name servers
	fmt.Printf("Name servers  : ")
	response, err = resolveQuery(server, cname, dns.TypeNS, false)
	if err == nil {
		nss := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeNS || answer.Header().Class != dns.ClassINET {
				continue
			}
			if nsRecord, ok := answer.(*dns.NS); ok {
				nss = append(nss, nsRecord.Ns)
			}
		}
		if response.Rcode == dns.RcodeNameError {
			fmt.Println("name does not exist")
		} else if response.Rcode != dns.RcodeSuccess {
			fmt.Printf("server returned %s\n", dns.RcodeToString[response.Rcode])
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
	}

	// Mail servers
	fmt.Printf("Mail servers  : ")
	response, err = resolveQuery(server, cname, dns.TypeMX, false)
	if err == nil {
		mxs := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeMX || answer.Header().Class != dns.ClassINET {
				continue
			}
			if mxRecord, ok := answer.(*dns.MX); ok {
				mxs = append(mxs, mxRecord.Mx)
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

	// HTTPS records
	fmt.Printf("HTTPS alias   : ")
	response, err = resolveQuery(server, cname, dns.TypeHTTPS, false)
	if err == nil {
		aliases := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
				continue
			}
			if httpsRecord, ok := answer.(*dns.HTTPS); ok {
				if httpsRecord.Priority != 0 || len(httpsRecord.Target) < 2 {
					continue
				}
				aliases = append(aliases, httpsRecord.Target)
			}
		}
		if len(aliases) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(aliases, ", "))
		}

		fmt.Printf("HTTPS info    : ")
		info := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
				continue
			}
			if httpsRecord, ok := answer.(*dns.HTTPS); ok {
				if httpsRecord.Priority == 0 || len(httpsRecord.Target) > 1 {
					continue
				}
				for _, value := range httpsRecord.Value {
					info = append(info, fmt.Sprintf("[%s]=[%s]", value.Key(), value.String()))
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
		fmt.Println("-")
	}

	fmt.Println("")

	// Host info
	fmt.Printf("Host info     : ")
	response, err = resolveQuery(server, cname, dns.TypeHINFO, false)
	if err == nil {
		hinfo := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeHINFO || answer.Header().Class != dns.ClassINET {
				continue
			}
			if hinfoRecord, ok := answer.(*dns.HINFO); ok {
				hinfo = append(hinfo, fmt.Sprintf("%s %s", hinfoRecord.Cpu, hinfoRecord.Os))
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

	// TXT records
	fmt.Printf("TXT records   : ")
	response, err = resolveQuery(server, cname, dns.TypeTXT, false)
	if err == nil {
		txt := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer.Header().Rrtype != dns.TypeTXT || answer.Header().Class != dns.ClassINET {
				continue
			}
			if txtRecord, ok := answer.(*dns.TXT); ok {
				txt = append(txt, strings.Join(txtRecord.Txt, " "))
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
