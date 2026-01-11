package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/hashicorp/go-immutable-radix/v2/iradix"
)

// Buffer pool for ReadPrefixed to reduce GC pressure
var prefixedReadBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 512)
	},
}

// isDigit returns true if the byte represents a digit (0-9)
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// StringReverse - OPTIMIZED: Direct byte reversal for ASCII, efficient rune handling for Unicode
func StringReverse(s string) string {
	// Fast path: Check if string is pure ASCII
	isASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			isASCII = false
			break
		}
	}

	if isASCII {
		// ASCII-only optimization: direct byte manipulation with unsafe conversion
		b := make([]byte, len(s))
		copy(b, s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return *(*string)(unsafe.Pointer(&b))
	}

	// Unicode path: Convert to runes and reverse
	r := make([]rune, 0, utf8.RuneCountInString(s))
	for _, ru := range s {
		r = append(r, ru)
	}
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// StringTwoFields - OPTIMIZED: Use built-in strings functions
func StringTwoFields(str string) (string, string, bool) {
	fields := strings.FieldsFunc(str, func(r rune) bool {
		return r == ' ' || r == '	' || r == '
' || r == ''
	})
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// StringQuote returns the string with quotes around it
func StringQuote(str string) string {
	str = strings.ReplaceAll(str, """, "\"")
	str = strings.ReplaceAll(str, "\", "\\")
	return """ + str + """
}

// TrimAndStripInlineComments - OPTIMIZED: Single pass to find bounds
func TrimAndStripInlineComments(str string) string {
	// Single pass to find bounds
	start, end := 0, len(str)

	// Find comment marker (last # preceded by whitespace)
	for i := len(str) - 1; i > 0; i-- {
		if str[i] == '#' && (str[i-1] == ' ' || str[i-1] == '	') {
			end = i - 1
			break
		}
	}

	// Trim leading whitespace
	for start < end && (str[start] == ' ' || str[start] == '	' || str[start] == '
' || str[start] == '') {
		start++
	}

	// Trim trailing whitespace
	for end > start && (str[end-1] == ' ' || str[end-1] == '	' || str[end-1] == '
' || str[end-1] == '') {
		end--
	}

	return str[start:end]
}

// StringStripSpaces removes all whitespace from a string
func StringStripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '	' || r == '' || r == '
' {
			return -1
		}
		return r
	}, str)
}

// ExtractHostAndPort splits a network address into host and port
func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		host = str
		port = defaultPort
	} else {
		port, err = strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			port = defaultPort
		}
	}
	return
}

// ExtractClientIPStr extracts the client IP address from PluginsState
func ExtractClientIPStr(pluginsState *PluginsState) (string, bool) {
	if pluginsState == nil || pluginsState.clientAddr == nil {
		return "", false
	}

	switch addr := pluginsState.clientAddr.(type) {
	case *net.UDPAddr:
		return addr.IP.String(), true
	case *net.TCPAddr:
		return addr.IP.String(), true
	default:
		return "", false
	}
}

// ReadPrefixed - OPTIMIZED: Buffer pool to reduce GC pressure
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	buf := prefixedReadBufPool.Get().([]byte)
	if cap(buf) < 512 {
		buf = make([]byte, 512)
	}
	buf = buf[:2]

	pos, err := io.ReadFull(*conn, buf)
	if err != nil {
		if cap(buf) <= 4096 {
			prefixedReadBufPool.Put(buf[:512])
		}
		return nil, err
	}

	length := int(buf[0])<<8 | int(buf[1])
	if length < 12 || length > 65535 {
		if cap(buf) <= 4096 {
			prefixedReadBufPool.Put(buf[:512])
		}
		return nil, errors.New("unexpected message length")
	}

	if cap(buf) < length {
		newBuf := make([]byte, length)
		copy(newBuf, buf[:pos])
		buf = newBuf
	} else {
		buf = buf[:length]
	}

	if _, err := io.ReadFull(*conn, buf[pos:]); err != nil {
		if cap(buf) <= 4096 {
			prefixedReadBufPool.Put(buf[:512])
		}
		return nil, err
	}

	result := make([]byte, length)
	copy(result, buf)

	if cap(buf) <= 4096 {
		prefixedReadBufPool.Put(buf[:512])
	}

	return result, nil
}

// Min returns the smaller of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the larger of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// FormatLogLine - OPTIMIZED: Use strings.Builder with time.AppendFormat
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
	if format == "tsv" {
		var buf strings.Builder
		buf.Grow(len(clientIP) + len(qName) + len(reason) + len(additionalFields)*20 + 100)

		now := time.Now()
		buf.WriteString("[")
		buf.WriteString(now.Format("2006-01-02 15:04:05"))
		buf.WriteString("]	")
		buf.WriteString(clientIP)
		buf.WriteString("	")
		buf.WriteString(StringQuote(qName))
		buf.WriteString("	")
		buf.WriteString(StringQuote(reason))

		for _, field := range additionalFields {
			buf.WriteString("	")
			buf.WriteString(StringQuote(field))
		}
		buf.WriteString("
")
		return buf.String(), nil
	} else if format == "ltsv" {
		var buf strings.Builder
		buf.Grow(len(clientIP) + len(qName) + len(reason) + len(additionalFields)*20 + 100)

		buf.WriteString("time:")
		buf.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
		buf.WriteString("	host:")
		buf.WriteString(clientIP)
		buf.WriteString("	qname:")
		buf.WriteString(StringQuote(qName))
		buf.WriteString("	message:")
		buf.WriteString(StringQuote(reason))

		// For LTSV format, additional fields are added with specific labels
		for i, field := range additionalFields {
			if i == 0 {
				buf.WriteString("	ip:")
				buf.WriteString(StringQuote(field))
			} else {
				buf.WriteString("	field")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteString(":")
				buf.WriteString(StringQuote(field))
			}
		}
		buf.WriteString("
")
		return buf.String(), nil
	}
	return "", fmt.Errorf("unexpected log format: [%s]", format)
}

// WritePluginLog writes a log entry for plugin actions
func WritePluginLog(logger io.Writer, format, clientIP, qName, reason string, additionalFields ...string) error {
	if logger == nil {
		return errors.New("Log file not initialized")
	}

	line, err := FormatLogLine(format, clientIP, qName, reason, additionalFields...)
	if err != nil {
		return err
	}

	_, err = io.WriteString(logger, line)
	return err
}

// ParseTimeBasedRule parses a rule line that may contain time-based restrictions (@timerange)
func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (rulePart string, weeklyRanges *WeeklyRanges, err error) {
	rulePart, timeRangeName, found := strings.Cut(line, "@")

	if !found {
		// No @ symbol found
		rulePart = line
	} else {
		// Found @
		rulePart = strings.TrimSpace(rulePart)
		timeRangeName = strings.TrimSpace(timeRangeName)
		if strings.Contains(timeRangeName, "@") {
			// If there's another @, that's the "Unexpected @ character" error case
			return "", nil, fmt.Errorf("syntax error at line %d -- Unexpected @ character", 1+lineNo)
		}
	}

	if len(timeRangeName) > 0 {
		if weeklyRangesX, ok := (*allWeeklyRanges)[timeRangeName]; ok {
			weeklyRanges = &weeklyRangesX
		} else {
			return "", nil, fmt.Errorf("time range [%s] not found at line %d", timeRangeName, 1+lineNo)
		}
	}

	return rulePart, weeklyRanges, nil
}

// ParseIPRule parses and validates an IP rule line
func ParseIPRule(line string, lineNo int) (cleanLine string, trailingStar bool, err error) {
	ip := net.ParseIP(line)
	trailingStar = strings.HasSuffix(line, "*")

	if len(line) < 2 || (ip != nil && trailingStar) {
		return "", false, fmt.Errorf("suspicious IP rule [%s] at line %d", line, lineNo)
	}

	cleanLine = line
	if trailingStar {
		cleanLine = cleanLine[:len(cleanLine)-1]
	}
	if strings.HasSuffix(cleanLine, ":") || strings.HasSuffix(cleanLine, ".") {
		cleanLine = cleanLine[:len(cleanLine)-1]
	}
	if len(cleanLine) == 0 {
		return "", false, fmt.Errorf("empty IP rule at line %d", lineNo)
	}
	if strings.Contains(cleanLine, "*") {
		return "", false, fmt.Errorf("invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
	}

	return strings.ToLower(cleanLine), trailingStar, nil
}

// ProcessConfigLines processes configuration file lines, calling the processor function for each non-empty line
func ProcessConfigLines(lines string, processor func(line string, lineNo int) error) error {
	for lineNo, line := range strings.Split(lines, "
") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		if err := processor(line, lineNo); err != nil {
			return err
		}
	}
	return nil
}

// LoadIPRules - OPTIMIZED: Batch insertions with sorting for better radix tree balance
func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) (*iradix.Tree, error) {
	var prefixRules []string

	err := ProcessConfigLines(lines, func(line string, lineNo int) error {
		cleanLine, trailingStar, lineErr := ParseIPRule(line, lineNo)
		if lineErr != nil {
			dlog.Error(lineErr)
			return nil // Continue processing (matching existing behavior)
		}

		if trailingStar {
			prefixRules = append(prefixRules, cleanLine)
		} else {
			ips[cleanLine] = true
		}
		return nil
	})

	// Batch insert prefixes (radix trees benefit from sorted insertion)
	sort.Strings(prefixRules)
	for _, rule := range prefixRules {
		prefixes, _, _ = prefixes.Insert([]byte(rule), 0)
	}

	return prefixes, err
}

// InitializePluginLogger initializes a logger for a plugin if the log file is configured
func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
	if len(logFile) > 0 {
		return Logger(maxSize, maxAge, maxBackups, logFile), format
	}
	return nil, ""
}

const (
	ipv4ReverseLen = 4*4 + len("in-addr.arpa.") // 29
	ipv6ReverseLen = 16*4 + len("ip6.arpa.")     // 73
)

// reverseAddr - OPTIMIZED: Direct byte conversion with exact pre-allocation
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", errors.New("unrecognized address: " + addr)
	}
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, ipv4ReverseLen)
		for i := len(v4) - 1; i >= 0; i-- {
			octet := v4[i]
			if octet >= 100 {
				buf = append(buf, byte('0'+octet/100))
				octet %= 100
				buf = append(buf, byte('0'+octet/10))
				buf = append(buf, byte('0'+octet%10))
			} else if octet >= 10 {
				buf = append(buf, byte('0'+octet/10))
				buf = append(buf, byte('0'+octet%10))
			} else {
				buf = append(buf, byte('0'+octet))
			}
			buf = append(buf, '.')
		}
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, ipv6ReverseLen)
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigits[v&0xF], '.', hexDigits[v>>4], '.')
	}
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

// fqdn returns the fully qualified domain name (with trailing dot)
func fqdn(name string) string {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
