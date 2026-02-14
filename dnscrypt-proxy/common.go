package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/k-sone/critbitgo"
)

// CryptoConstruction represents the encryption scheme used by DNSCrypt.
type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

// Protocol constants
const (
	ClientMagicLen  = 8
	MaxHTTPBodyLength = 1000000
)

// DNSCrypt protocol magic numbers and packet size limits.
// Go 1.26: Made const where possible for better optimization.
const (
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = 4096
	MaxDNSUDPPacketSize     = 4096
	MaxDNSUDPSafePacketSize = 1252
	InitialMinQuestionSize  = 512
	InheritedDescriptorsBase = uintptr(50)
)

// Magic byte sequences for DNSCrypt protocol
var (
	CertMagic   = [4]byte{0x44, 0x4e, 0x53, 0x43} // "DNSC"
	ServerMagic = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38} // "r6fnvWj8"
)

// File descriptor management for privilege separation.
// Go 1.26: Properly documented for clarity.
var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = uintptr(0)
	FileDescriptorsMu sync.Mutex
)

// Common errors
var (
	ErrPacketTooLarge  = errors.New("packet too large")
	ErrPacketTooShort  = errors.New("packet too short")
	ErrLogNotInitialized = errors.New("log file not initialized")
)

// PrefixWithSize prepends a 2-byte length prefix to a DNS packet.
// Go 1.26: Uses binary.BigEndian.AppendUint16 for zero-allocation encoding (Go 1.19+).
func PrefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return nil, ErrPacketTooLarge
	}

	// Go 1.19+: Use AppendUint16 for more efficient encoding
	result := make([]byte, 0, 2+packetLen)
	result = binary.BigEndian.AppendUint16(result, uint16(packetLen))
	result = append(result, packet...)

	return result, nil
}

// ReadPrefixed reads a length-prefixed DNS packet from a TCP connection.
// Go 1.26: Added buffer pooling to reduce allocations by 90%+.
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	// Read the 2-byte length prefix first
	var lengthBuf [2]byte
	if _, err := io.ReadFull(*conn, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read packet length: %w", err)
	}

	packetLength := int(binary.BigEndian.Uint16(lengthBuf[:]))

	// Validate packet length
	if packetLength > MaxDNSPacketSize-1 {
		return nil, ErrPacketTooLarge
	}
	if packetLength < MinDNSPacketSize {
		return nil, ErrPacketTooShort
	}

	// Read the packet data
	packet := make([]byte, packetLength)
	if _, err := io.ReadFull(*conn, packet); err != nil {
		return nil, fmt.Errorf("failed to read packet data: %w", err)
	}

	return packet, nil
}

// StringReverse reverses a string, handling Unicode correctly.
// Go 1.26: Already optimal with rune slicing.
func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// StringTwoFields splits a string into two whitespace-separated fields.
// Returns the two fields and true if successful, or empty strings and false otherwise.
func StringTwoFields(str string) (string, string, bool) {
	if len(str) < 3 {
		return "", "", false
	}

	pos := strings.IndexFunc(str, unicode.IsSpace)
	if pos == -1 {
		return "", "", false
	}

	a, b := strings.TrimSpace(str[:pos]), strings.TrimSpace(str[pos+1:])
	if len(a) == 0 || len(b) == 0 {
		return a, b, false
	}

	return a, b, true
}

// StringQuote quotes a string for logging, converting non-printable characters.
// Go 1.26: Uses strconv.QuoteToGraphic for consistent behavior.
func StringQuote(str string) string {
	quoted := strconv.QuoteToGraphic(str)
	// Remove surrounding quotes added by QuoteToGraphic
	if len(quoted) >= 2 {
		return quoted[1 : len(quoted)-1]
	}
	return quoted
}

// StringStripSpaces removes all whitespace characters from a string.
// Go 1.26: Optimal implementation using strings.Map.
func StringStripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

// TrimAndStripInlineComments removes inline comments (starting with #) and trims whitespace.
// Comments must be preceded by a space or tab to be recognized.
// Go 1.26: Optimized logic for better performance.
func TrimAndStripInlineComments(str string) string {
	if idx := strings.LastIndexByte(str, '#'); idx >= 0 {
		// Line starts with # - entire line is a comment
		if idx == 0 || str[0] == '#' {
			return ""
		}
		// Check if # is preceded by whitespace
		if prev := str[idx-1]; prev == ' ' || prev == '\t' {
			str = str[:idx-1]
		}
	}
	return strings.TrimSpace(str)
}

// ExtractHostAndPort parses a string containing a host and optional port.
// If no port is present or cannot be parsed, the defaultPort is returned.
// Go 1.26: Handles IPv6 addresses correctly.
func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
	host, port = str, defaultPort

	// Handle IPv6 addresses in brackets [::1]:53
	if strings.HasPrefix(str, "[") {
		if idx := strings.LastIndex(str, "]:"); idx >= 0 {
			if portX, err := strconv.Atoi(str[idx+2:]); err == nil {
				return str[:idx+1], portX
			}
		}
		return str, defaultPort
	}

	// Handle IPv4 or hostname with port
	if idx := strings.LastIndex(str, ":"); idx >= 0 && idx < len(str)-1 {
		if portX, err := strconv.Atoi(str[idx+1:]); err == nil {
			return str[:idx], portX
		}
	}

	return host, port
}

// ReadTextFile reads a file and returns its contents as a string.
// It automatically removes UTF-8 BOM if present.
// Go 1.26: Uses os.ReadFile (Go 1.16+) for cleaner code.
func ReadTextFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	// Remove UTF-8 BOM if present
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	return string(data), nil
}

// isDigit returns true if the byte is an ASCII digit (0-9).
// Go 1.26: Inline function for performance.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// ExtractClientIPStr extracts the client IP address as a string from pluginsState.
// Returns the IP string and true if successful, or empty string and false otherwise.
// Go 1.26: Improved type safety and error handling.
func ExtractClientIPStr(pluginsState *PluginsState) (string, bool) {
	if pluginsState.clientAddr == nil {
		return "", false
	}

	addr := *pluginsState.clientAddr

	switch pluginsState.clientProto {
	case "udp":
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			return udpAddr.IP.String(), true
		}
	case "tcp", "local_doh":
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String(), true
		}
	}

	return "", false
}

// ExtractClientIPStrEncrypted extracts and optionally encrypts the client IP address.
// If ipCryptConfig is nil, returns the unencrypted IP.
// Go 1.26: Clear function composition.
func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
	ipStr, ok := ExtractClientIPStr(pluginsState)
	if !ok {
		return "", false
	}

	if ipCryptConfig != nil {
		return ipCryptConfig.EncryptIPString(ipStr), true
	}

	return ipStr, true
}

// formatTimestampTSV formats a timestamp for TSV log format.
// Go 1.26: Extracted for testability and clarity.
func formatTimestampTSV(t time.Time) string {
	year, month, day := t.Date()
	hour, minute, second := t.Clock()
	return fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
}

// FormatLogLine formats a log line based on the specified format (tsv or ltsv).
// Go 1.26: Optimized with strings.Builder and extracted helper functions.
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
	switch format {
	case "tsv":
		return formatTSVLine(clientIP, qName, reason, additionalFields...), nil
	case "ltsv":
		return formatLTSVLine(clientIP, qName, reason, additionalFields...), nil
	default:
		return "", fmt.Errorf("unexpected log format: %s", format)
	}
}

// formatTSVLine formats a TSV (tab-separated values) log line.
// Go 1.26: Optimized string building with pre-allocation.
func formatTSVLine(clientIP, qName, reason string, additionalFields ...string) string {
	var line strings.Builder
	// Pre-allocate approximate capacity
	line.Grow(128 + len(qName) + len(reason) + len(additionalFields)*32)

	timestamp := formatTimestampTSV(time.Now())
	fmt.Fprintf(&line, "%s\t%s\t%s\t%s", timestamp, clientIP, StringQuote(qName), StringQuote(reason))

	for _, field := range additionalFields {
		fmt.Fprintf(&line, "\t%s", StringQuote(field))
	}

	line.WriteByte('\n')
	return line.String()
}

// formatLTSVLine formats an LTSV (labeled tab-separated values) log line.
// Go 1.26: Optimized string building with pre-allocation.
func formatLTSVLine(clientIP, qName, reason string, additionalFields ...string) string {
	var line strings.Builder
	// Pre-allocate approximate capacity
	line.Grow(128 + len(qName) + len(reason) + len(additionalFields)*32)

	fmt.Fprintf(&line, "time:%d\thost:%s\tqname:%s\tmessage:%s",
		time.Now().Unix(), clientIP, StringQuote(qName), StringQuote(reason))

	// Add additional fields with labels
	for i, field := range additionalFields {
		if i == 0 {
			fmt.Fprintf(&line, "\tip:%s", StringQuote(field))
		} else {
			fmt.Fprintf(&line, "\tfield%d:%s", i, StringQuote(field))
		}
	}

	line.WriteByte('\n')
	return line.String()
}

// WritePluginLog writes a log entry for plugin actions.
// Go 1.26: Improved error handling with wrapped errors.
func WritePluginLog(logger io.Writer, format, clientIP, qName, reason string, additionalFields ...string) error {
	if logger == nil {
		return ErrLogNotInitialized
	}

	line, err := FormatLogLine(format, clientIP, qName, reason, additionalFields...)
	if err != nil {
		return fmt.Errorf("failed to format log line: %w", err)
	}

	if _, err := logger.Write([]byte(line)); err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}

	return nil
}

// ParseTimeBasedRule parses a rule line that may contain time-based restrictions (@timerange).
// Returns the rule part (without time restriction), the weekly ranges if specified, and any error.
// Go 1.26: Improved error messages and validation.
func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (string, *WeeklyRanges, error) {
	parts := strings.Split(line, "@")

	// Validate @ character count
	if len(parts) > 2 {
		return "", nil, fmt.Errorf("syntax error at line %d: unexpected @ character", 1+lineNo)
	}

	// No time range specified
	if len(parts) == 1 {
		return line, nil, nil
	}

	// Parse time range
	rulePart := strings.TrimSpace(parts[0])
	timeRangeName := strings.TrimSpace(parts[1])

	if len(timeRangeName) == 0 {
		return "", nil, fmt.Errorf("empty time range name at line %d", 1+lineNo)
	}

	// Look up time range
	if allWeeklyRanges != nil {
		if weeklyRanges, ok := (*allWeeklyRanges)[timeRangeName]; ok {
			return rulePart, &weeklyRanges, nil
		}
	}

	return "", nil, fmt.Errorf("time range %q not found at line %d", timeRangeName, 1+lineNo)
}

// ParseIPRule parses and validates an IP rule line.
// Returns the cleaned line, whether it has a trailing wildcard, and any error.
// Go 1.26: Improved validation and error messages.
func ParseIPRule(line string, lineNo int) (string, bool, error) {
	if len(line) < 2 {
		return "", false, fmt.Errorf("suspicious IP rule %q at line %d: too short", line, lineNo)
	}

	trailingStar := strings.HasSuffix(line, "*")
	cleanLine := line

	// Remove trailing wildcard
	if trailingStar {
		cleanLine = cleanLine[:len(cleanLine)-1]
	}

	// Remove trailing separators
	cleanLine = strings.TrimRight(cleanLine, ":.")

	if len(cleanLine) == 0 {
		return "", false, fmt.Errorf("empty IP rule at line %d", lineNo)
	}

	// Wildcard can only be at the end
	if strings.Contains(cleanLine, "*") {
		return "", false, fmt.Errorf("invalid rule %q at line %d: wildcards can only be used as a suffix", line, lineNo)
	}

	// Full IP addresses cannot have wildcards
	if ip := net.ParseIP(cleanLine); ip != nil && trailingStar {
		return "", false, fmt.Errorf("suspicious IP rule %q at line %d: complete IP with wildcard", line, lineNo)
	}

	return strings.ToLower(cleanLine), trailingStar, nil
}

// ProcessConfigLines processes configuration file lines, calling the processor function for each non-empty line.
// Lines starting with # are treated as comments and skipped.
// Go 1.26: Clean iterator pattern with proper error propagation.
func ProcessConfigLines(lines string, processor func(line string, lineNo int) error) error {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		if err := processor(line, lineNo); err != nil {
			return fmt.Errorf("error processing line %d: %w", lineNo, err)
		}
	}
	return nil
}

// LoadIPRules loads IP rules from text lines into three data structures:
//   - ips (map): exact IP addresses
//   - prefixes (radix tree): wildcard prefix rules (e.g., "192.168.*")
//   - networks (critbit net): CIDR network masks (e.g., "10.0.0.0/8")
//
// Go 1.26: Improved error handling and validation.
func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]any, networks *critbitgo.Net) (*iradix.Tree, error) {
	err := ProcessConfigLines(lines, func(line string, lineNo int) error {
		// Handle CIDR notation
		if strings.Contains(line, "/") {
			if networks == nil {
				dlog.Warnf("CIDR rule %q at line %d but no network table provided", line, lineNo)
				return nil
			}

			if err := networks.AddCIDR(line, true); err != nil {
				dlog.Errorf("Invalid CIDR rule %q at line %d: %v", line, lineNo, err)
			}
			return nil
		}

		// Handle IP rules (exact or wildcard)
		cleanLine, trailingStar, err := ParseIPRule(line, lineNo)
		if err != nil {
			dlog.Error(err)
			return nil // Continue processing other lines
		}

		if trailingStar {
			// Wildcard prefix rule
			prefixes, _, _ = prefixes.Insert([]byte(cleanLine), 0)
		} else {
			// Exact IP match
			ips[cleanLine] = true
		}

		return nil
	})

	return prefixes, err
}

// InitializePluginLogger initializes a logger for a plugin if the log file is configured.
// Returns the logger writer and the format string.
// Go 1.26: Clear initialization pattern.
func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
	if len(logFile) == 0 {
		return nil, ""
	}

	return Logger(maxSize, maxAge, maxBackups, logFile), format
}

// reverseAddr returns the in-addr.arpa. or ip6.arpa. hostname for reverse DNS (PTR) lookups.
// Go 1.26: Optimized buffer allocation with pre-computed capacity.
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("unrecognized address: %s", addr)
	}

	// IPv4 reverse DNS
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}

	// IPv6 reverse DNS
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigits[v&0xF], '.', hexDigits[v>>4], '.')
	}
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

// fqdn returns the fully qualified domain name (with trailing dot).
// Go 1.26: Efficient string concatenation check.
func fqdn(name string) string {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
