package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

// DNS resolver configuration constants
const (
	myResolverHost  = "resolver.dnscrypt.info."
	nonexistentName = "nonexistent-zone.dnscrypt-test."

	// Query retry and timeout settings
	initialTimeout   = 2 * time.Second
	maxRetries       = 3
	timeoutMultiplier = 2

	// CNAME chain limit to prevent infinite loops
	maxCNAMEChain = 100

	// EDNS Client Subnet constants
	ecsIPv4Family = 1
	ecsIPv6Family = 2
	ecsTestSubnet = "93.184.216.0/24"
)

// Common errors
var (
	ErrTimeout               = errors.New("DNS query timeout")
	ErrUnsupportedRecordType = errors.New("unsupported DNS record type")
	ErrInvalidAddress        = errors.New("invalid IP address")
)

// resolveQuery performs a DNS query with retry logic and exponential backoff.
// Go 1.26: Improved error handling, context management, and timeout logic.
func resolveQuery(server, qName string, qType uint16, sendClientSubnet bool) (*dns.Msg, error) {
	// Create DNS client with initial timeout
	transport := dns.NewTransport()
	transport.ReadTimeout = initialTimeout
	client := &dns.Client{Transport: transport}

	// Create DNS message
	msg := dns.NewMsg(qName, qType)
	if msg == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedRecordType, qType)
	}

	// Configure message
	msg.RecursionDesired = true
	msg.Opcode = dns.OpcodeQuery
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

	// Add EDNS Client Subnet option if requested
	if sendClientSubnet {
		if err := addClientSubnetOption(msg); err != nil {
			return nil, fmt.Errorf("failed to add client subnet option: %w", err)
		}
	}

	// Retry with exponential backoff
	timeout := transport.ReadTimeout
	for attempt := range maxRetries {
		// Generate new message ID for each attempt
		msg.ID = dns.ID()
		msg.Data = nil // Clear packed data so Exchange will re-pack with new ID

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		response, _, err := client.Exchange(ctx, msg, "udp", server)
		cancel()

		// Check for timeout and retry
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if attempt < maxRetries-1 {
				timeout *= timeoutMultiplier
				continue
			}
			return nil, fmt.Errorf("%w after %d attempts", ErrTimeout, maxRetries)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS query failed: %w", err)
		}

		return response, nil
	}

	return nil, fmt.Errorf("%w after %d attempts", ErrTimeout, maxRetries)
}

// addClientSubnetOption adds an EDNS Client Subnet option to the DNS message.
// Go 1.26: Extracted for better testability and error handling.
func addClientSubnetOption(msg *dns.Msg) error {
	// Parse test subnet
	_, subnet, err := net.ParseCIDR(ecsTestSubnet)
	if err != nil {
		return fmt.Errorf("invalid test subnet: %w", err)
	}

	// Get subnet mask size
	bits, totalSize := subnet.Mask.Size()

	// Determine address family
	var family uint16
	switch totalSize {
	case 32:
		family = ecsIPv4Family
	case 128:
		family = ecsIPv6Family
	default:
		return fmt.Errorf("unexpected address size: %d", totalSize)
	}

	// Convert IP to netip.Addr
	addr, ok := netip.AddrFromSlice(subnet.IP)
	if !ok {
		return fmt.Errorf("%w: %s", ErrInvalidAddress, subnet.IP)
	}

	// Create EDNS Client Subnet option
	ecsOpt := &dns.SUBNET{
		Family:  family,
		Netmask: uint8(bits),
		Scope:   0,
		Address: addr,
	}

	msg.Pseudo = append(msg.Pseudo, ecsOpt)
	return nil
}

// Resolve performs comprehensive DNS resolution for a given name.
// Go 1.26: Refactored into smaller helper functions for better maintainability.
func Resolve(server, name string, singleResolver bool) {
	// Parse server override from name if present (format: name,server)
	name, server, singleResolver = parseNameAndServer(name, server, singleResolver)

	// Normalize server address
	server = normalizeServer(server)

	// Extract host and port for display
	host, port := ExtractHostAndPort(server, 53)
	fmt.Printf("Resolving [%s] using %s port %d\n\n", name, host, port)

	// Ensure name is FQDN
	name = fqdn(name)

	// Resolve and display all DNS information
	cname, clientSubnet := resolveResolverInfo(server, name, singleResolver)

	if singleResolver {
		checkResolverCapabilities(server, clientSubnet)
	}

	fmt.Println()

	cname = resolveCNAMEChain(server, cname)

	fmt.Println()

	resolveAddresses(server, cname)

	fmt.Println()

	resolveNameServers(server, cname)
	resolveMailServers(server, cname)

	fmt.Println()

	resolveHTTPSRecords(server, cname)

	fmt.Println()

	resolveHostInfo(server, cname)
	resolveTXTRecords(server, cname)

	fmt.Println()
}

// parseNameAndServer extracts server from name if specified as "name,server".
// Go 1.26: Clear separation of parsing logic.
func parseNameAndServer(name, server string, singleResolver bool) (string, string, bool) {
	parts := strings.SplitN(name, ",", 2)
	if len(parts) == 2 {
		return parts[0], parts[1], true
	}
	return name, server, singleResolver
}

// normalizeServer converts wildcard addresses to localhost.
// Go 1.26: Explicit normalization function.
func normalizeServer(server string) string {
	host, port := ExtractHostAndPort(server, 53)

	// Convert wildcard addresses to localhost
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "[::]":
		host = "[::1]"
	}

	return fmt.Sprintf("%s:%d", host, port)
}

// resolveResolverInfo queries resolver information and returns canonical name and client subnet.
// Go 1.26: Extracted for better code organization.
func resolveResolverInfo(server, name string, singleResolver bool) (cname, clientSubnet string) {
	cname = name

	response, err := resolveQuery(server, myResolverHost, dns.TypeTXT, true)
	if err != nil {
		fmt.Printf("Unable to resolve: [%s]\n", err)
		os.Exit(1)
	}

	fmt.Print("Resolver      : ")
	resolverIPs := extractResolverIPs(server, response, &clientSubnet)

	if len(resolverIPs) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(resolverIPs, ", "))
	}

	return cname, clientSubnet
}

// extractResolverIPs extracts and enriches resolver IP addresses with PTR records.
// Go 1.26: Separated IP extraction and PTR lookup logic.
func extractResolverIPs(server string, response *dns.Msg, clientSubnet *string) []string {
	results := make([]string, 0, len(response.Answer))

	for _, answer := range response.Answer {
		// Check record type and class
		if answer.Header().Class != dns.ClassINET || dns.RRToType(answer) != dns.TypeTXT {
			continue
		}

		// Safe type assertion
		txtRecord, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}

		// Extract IP and client subnet from TXT records
		ip := extractIPFromTXT(txtRecord, clientSubnet)
		if ip == "" {
			continue
		}

		// Enrich with PTR record if available
		ip = enrichWithPTR(server, ip)
		results = append(results, ip)
	}

	return results
}

// extractIPFromTXT extracts resolver IP and client subnet from TXT record.
// Go 1.26: Clear extraction logic with strings.CutPrefix.
func extractIPFromTXT(txtRecord *dns.TXT, clientSubnet *string) string {
	var ip string

	for _, txt := range txtRecord.Txt {
		if after, ok := strings.CutPrefix(txt, "Resolver IP: "); ok {
			ip = after
		} else if after, ok := strings.CutPrefix(txt, "EDNS0 client subnet: "); ok {
			*clientSubnet = after
		}
	}

	return ip
}

// enrichWithPTR adds PTR record information to an IP address.
// Go 1.26: Separate PTR lookup with proper error handling.
func enrichWithPTR(server, ip string) string {
	rev, err := reverseAddr(ip)
	if err != nil {
		return ip
	}

	response, err := resolveQuery(server, rev, dns.TypePTR, false)
	if err != nil {
		return ip
	}

	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypePTR || answer.Header().Class != dns.ClassINET {
			continue
		}

		// Safe type assertion
		if ptrRecord, ok := answer.(*dns.PTR); ok {
			return fmt.Sprintf("%s (%s)", ip, ptrRecord.Ptr)
		}
	}

	return ip
}

// checkResolverCapabilities tests resolver for lying, DNSSEC, and ECS support.
// Go 1.26: Extracted resolver capability checks.
func checkResolverCapabilities(server, clientSubnet string) {
	response, err := resolveQuery(server, nonexistentName, dns.TypeA, false)

	fmt.Print("Lying         : ")
	if err != nil {
		fmt.Printf("[%v]\n", err)
		return
	}

	// Check if resolver returns fake responses
	switch response.Rcode {
	case dns.RcodeSuccess:
		fmt.Println("yes. That resolver returns wrong responses")
	case dns.RcodeNameError:
		fmt.Println("no")
	default:
		fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
	}

	// Check DNSSEC support
	if response.Rcode == dns.RcodeNameError {
		fmt.Print("DNSSEC        : ")
		if response.AuthenticatedData {
			fmt.Println("yes, the resolver supports DNSSEC")
		} else {
			fmt.Println("no, the resolver doesn't support DNSSEC")
		}
	}

	// Check ECS support
	fmt.Print("ECS           : ")
	if clientSubnet != "" {
		fmt.Println("client network address is sent to authoritative servers")
	} else {
		fmt.Println("ignored or selective")
	}
}

// resolveCNAMEChain follows the CNAME chain and returns the canonical name.
// Go 1.26: Protected against infinite loops with max chain limit.
func resolveCNAMEChain(server, name string) string {
	fmt.Print("Canonical name: ")

	cname := name
	for i := range maxCNAMEChain {
		response, err := resolveQuery(server, cname, dns.TypeCNAME, false)
		if err != nil {
			break
		}

		found := false
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeCNAME || answer.Header().Class != dns.ClassINET {
				continue
			}

			// Safe type assertion
			if cnameRecord, ok := answer.(*dns.CNAME); ok {
				cname = cnameRecord.Target
				found = true
				break
			}
		}

		if !found {
			break
		}

		// Prevent infinite loops
		if i == maxCNAMEChain-1 {
			fmt.Printf("%s (truncated - max chain length reached)\n", cname)
			return cname
		}
	}

	fmt.Println(cname)
	return cname
}

// resolveAddresses resolves and displays IPv4 and IPv6 addresses.
// Go 1.26: Combined address resolution with helper function.
func resolveAddresses(server, cname string) {
	resolveAndPrintAddresses(server, cname, dns.TypeA, "IPv4 addresses")
	resolveAndPrintAddresses(server, cname, dns.TypeAAAA, "IPv6 addresses")
}

// resolveAndPrintAddresses is a helper to resolve and print IP addresses.
// Go 1.26: Generic address resolution function.
func resolveAndPrintAddresses(server, cname string, qType uint16, label string) {
	fmt.Printf("%-15s: ", label)

	response, err := resolveQuery(server, cname, qType, false)
	if err != nil {
		fmt.Println("-")
		return
	}

	addresses := extractIPAddresses(response, qType)

	if len(addresses) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(addresses, ", "))
	}
}

// extractIPAddresses extracts IP addresses from DNS response.
// Go 1.26: Type-safe IP address extraction.
func extractIPAddresses(response *dns.Msg, qType uint16) []string {
	addresses := make([]string, 0, len(response.Answer))

	for _, answer := range response.Answer {
		if dns.RRToType(answer) != qType || answer.Header().Class != dns.ClassINET {
			continue
		}

		switch qType {
		case dns.TypeA:
			if aRecord, ok := answer.(*dns.A); ok {
				addresses = append(addresses, aRecord.A.String())
			}
		case dns.TypeAAAA:
			if aaaaRecord, ok := answer.(*dns.AAAA); ok {
				addresses = append(addresses, aaaaRecord.AAAA.String())
			}
		}
	}

	return addresses
}

// resolveNameServers resolves and displays name servers with DNSSEC status.
// Go 1.26: Clear separation of NS resolution and display.
func resolveNameServers(server, cname string) {
	fmt.Print("Name servers  : ")

	response, err := resolveQuery(server, cname, dns.TypeNS, false)
	if err != nil {
		fmt.Println("-")
		fmt.Print("DNSSEC signed : -\n")
		return
	}

	// Extract name servers
	nameServers := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeNS || answer.Header().Class != dns.ClassINET {
			continue
		}

		if nsRecord, ok := answer.(*dns.NS); ok {
			nameServers = append(nameServers, nsRecord.Ns)
		}
	}

	// Display name servers
	switch {
	case response.Rcode == dns.RcodeNameError:
		fmt.Println("name does not exist")
	case response.Rcode != dns.RcodeSuccess:
		fmt.Printf("server returned %s\n", dns.RcodeToString[response.Rcode])
	case len(nameServers) == 0:
		fmt.Println("no name servers found")
	default:
		fmt.Println(strings.Join(nameServers, ", "))
	}

	// Display DNSSEC status
	fmt.Print("DNSSEC signed : ")
	if response.AuthenticatedData {
		fmt.Println("yes")
	} else {
		fmt.Println("no")
	}
}

// resolveMailServers resolves and displays mail servers.
// Go 1.26: Simplified MX record handling.
func resolveMailServers(server, cname string) {
	fmt.Print("Mail servers  : ")

	response, err := resolveQuery(server, cname, dns.TypeMX, false)
	if err != nil {
		fmt.Println("-")
		return
	}

	mailServers := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeMX || answer.Header().Class != dns.ClassINET {
			continue
		}

		if mxRecord, ok := answer.(*dns.MX); ok {
			mailServers = append(mailServers, mxRecord.Mx)
		}
	}

	switch len(mailServers) {
	case 0:
		fmt.Println("no mail servers found")
	case 1:
		fmt.Println("1 mail server found")
	default:
		fmt.Printf("%d mail servers found\n", len(mailServers))
	}
}

// resolveHTTPSRecords resolves and displays HTTPS/SVCB records.
// Go 1.26: Separated alias and service parameter display.
func resolveHTTPSRecords(server, cname string) {
	response, err := resolveQuery(server, cname, dns.TypeHTTPS, false)
	if err != nil {
		fmt.Println("HTTPS alias   : -")
		fmt.Println("HTTPS info    : -")
		return
	}

	displayHTTPSAliases(response)
	displayHTTPSServiceInfo(response)
}

// displayHTTPSAliases displays HTTPS alias records (priority 0).
// Go 1.26: Clear HTTPS alias extraction.
func displayHTTPSAliases(response *dns.Msg) {
	fmt.Print("HTTPS alias   : ")

	aliases := make([]string, 0)
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
			continue
		}

		if httpsRecord, ok := answer.(*dns.HTTPS); ok {
			// Priority 0 indicates an alias
			if httpsRecord.Priority == 0 && len(httpsRecord.Target) >= 2 {
				aliases = append(aliases, httpsRecord.Target)
			}
		}
	}

	if len(aliases) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(aliases, ", "))
	}
}

// displayHTTPSServiceInfo displays HTTPS service parameters (priority > 0).
// Go 1.26: Clear SVCB parameter extraction.
func displayHTTPSServiceInfo(response *dns.Msg) {
	fmt.Print("HTTPS info    : ")

	info := make([]string, 0)
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
			continue
		}

		if httpsRecord, ok := answer.(*dns.HTTPS); ok {
			// Priority > 0 indicates service parameters
			if httpsRecord.Priority > 0 && len(httpsRecord.Target) <= 1 {
				for _, value := range httpsRecord.Value {
					key := svcb.KeyToString(svcb.PairToKey(value))
					info = append(info, fmt.Sprintf("[%s]=[%s]", key, value.String()))
				}
			}
		}
	}

	if len(info) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(info, ", "))
	}
}

// resolveHostInfo resolves and displays HINFO records.
// Go 1.26: Type-safe HINFO record extraction.
func resolveHostInfo(server, cname string) {
	fmt.Print("Host info     : ")

	response, err := resolveQuery(server, cname, dns.TypeHINFO, false)
	if err != nil {
		fmt.Println("-")
		return
	}

	hostInfo := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeHINFO || answer.Header().Class != dns.ClassINET {
			continue
		}

		if hinfoRecord, ok := answer.(*dns.HINFO); ok {
			hostInfo = append(hostInfo, fmt.Sprintf("%s %s", hinfoRecord.Cpu, hinfoRecord.Os))
		}
	}

	if len(hostInfo) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(hostInfo, ", "))
	}
}

// resolveTXTRecords resolves and displays TXT records.
// Go 1.26: Type-safe TXT record extraction.
func resolveTXTRecords(server, cname string) {
	fmt.Print("TXT records   : ")

	response, err := resolveQuery(server, cname, dns.TypeTXT, false)
	if err != nil {
		fmt.Println("-")
		return
	}

	txtRecords := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if dns.RRToType(answer) != dns.TypeTXT || answer.Header().Class != dns.ClassINET {
			continue
		}

		if txtRecord, ok := answer.(*dns.TXT); ok {
			txtRecords = append(txtRecords, strings.Join(txtRecord.Txt, " "))
		}
	}

	if len(txtRecords) == 0 {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(txtRecords, ", "))
	}
}
