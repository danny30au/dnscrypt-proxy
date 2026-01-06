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
	"unsafe"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
)

// ============================================
// ZERO-COPY STRING/BYTE CONVERSIONS
// ============================================

// BytesToString converts []byte to string with zero allocations
// Uses unsafe.String from Go 1.20+
// WARNING: The byte slice must not be modified after conversion
func BytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// StringToBytes converts string to []byte with zero allocations
// Uses unsafe.Slice from Go 1.20+
// WARNING: The resulting slice must not be modified (respects string immutability)
func StringToBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// ============================================
// OPTIMIZED BUFFER POOLING
// ============================================

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 512) // Start with 512 bytes - matches DNS typical size
		return &buf
	},
}

// ReadPrefixed reads a length-prefixed packet from connection with buffer pooling
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	buf := *bufPtr
	buf = buf[:cap(buf)] // Use full capacity

	packetLength, pos := -1, 0

	for {
		if pos >= len(buf) {
			if len(buf) >= 2+MaxDNSPacketSize {
				return buf, errors.New("Packet too large")
			}

			// Grow buffer - update pool reference
			newSize := min(len(buf)*2, 2+MaxDNSPacketSize)
			newBuf := make([]byte, newSize)
			copy(newBuf, buf[:pos])
			buf = newBuf
			*bufPtr = buf
		}

		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			// Copy result before returning to pool
			result := make([]byte, pos)
			copy(result, buf[:pos])
			return result, err
		}

		pos += readnb

		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("Packet too large")
			}
			if packetLength < MinDNSPacketSize {
				return buf, errors.New("Packet too short")
			}

			// Ensure buffer is large enough for expected packet
			if 2+packetLength > len(buf) {
				newBuf := make([]byte, 2+packetLength)
				copy(newBuf, buf[:pos])
				buf = newBuf
				*bufPtr = buf
			}
		}

		if packetLength >= 0 && pos >= 2+packetLength {
			// Copy result before returning to pool
			result := make([]byte, packetLength)
			copy(result, buf[2:2+packetLength])
			return result, nil
		}
	}
}

// ============================================
// OPTIMIZED STRING OPERATIONS
// ============================================

// StringReverse reverses a string with fast ASCII path
func StringReverse(s string) string {
	// Quick check for ASCII - no allocation needed
	isASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			isASCII = false
			break
		}
	}

	if isASCII {
		// Use byte slice for ASCII
		b := make([]byte, len(s))
		for i := 0; i < len(s); i++ {
			b[i] = s[len(s)-1-i]
		}
		return BytesToString(b)
	}

	// Fall back to rune handling for Unicode
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// isWhitespace checks if byte is whitespace - faster than multiple comparisons
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// StringTwoFields splits string into two fields separated by whitespace
// Optimized with single-pass scanning and inline whitespace checks
func StringTwoFields(str string) (string, string, bool) {
	if len(str) < 3 {
		return "", "", false
	}

	// Find first whitespace
	i := 0
	for i < len(str) && !isWhitespace(str[i]) {
		i++
	}

	if i == 0 || i == len(str) {
		return "", "", false
	}

	a := str[:i]

	// Skip whitespace
	j := i
	for j < len(str) && isWhitespace(str[j]) {
		j++
	}

	if j >= len(str) {
		return "", "", false
	}

	// Trim trailing whitespace
	k := len(str)
	for k > j && isWhitespace(str[k-1]) {
		k--
	}

	b := str[j:k]
	if len(b) == 0 {
		return "", "", false
	}

	return a, b, true
}

// StringStripSpaces removes all whitespace from string
func StringStripSpaces(str string) string {
	var buf strings.Builder
	buf.Grow(len(str))
	for _, r := range str {
		if !unicode.IsSpace(r) {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// TrimAndStripInlineComments removes inline comments and trims whitespace
// Optimized to use string slicing (zero allocation when possible)
func TrimAndStripInlineComments(str string) string {
	// Find last # preceded by space or tab - single pass from end
	idx := -1
	for i := len(str) - 1; i > 0; i-- {
		if str[i] == '#' && (str[i-1] == ' ' || str[i-1] == '\t') {
			idx = i - 1
			break
		}
	}

	if idx == 0 {
		return ""
	}

	if idx > 0 {
		str = str[:idx]
	}

	// Trim whitespace using slice operations (zero allocation)
	start := 0
	end := len(str)

	// Optimized: check bytes directly instead of strings.TrimSpace
	for start < end && str[start] <= ' ' {
		start++
	}

	for end > start && str[end-1] <= ' ' {
		end--
	}

	return str[start:end]
}

// ============================================
// OPTIMIZED LOGGING
// ============================================

// Pre-allocated buffer for integer conversion (thread-local would be better but not available)
var intBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 20)
		return &buf
	},
}

// writeInt writes an integer to strings.Builder with zero-padding
func writeInt(buf *strings.Builder, val int, width int) {
	if val == 0 {
		for i := 0; i < width; i++ {
			buf.WriteByte('0')
		}
		return
	}

	// Get buffer from pool
	intBufPtr := intBufPool.Get().(*[]byte)
	defer intBufPool.Put(intBufPtr)
	intBuf := *intBufPtr

	// Convert to bytes in reverse
	i := len(intBuf) - 1
	for val > 0 && i >= 0 {
		intBuf[i] = byte('0' + val%10)
		val /= 10
		i--
	}

	// Calculate number of digits written
	numDigits := len(intBuf) - 1 - i

	// Pad with zeros if needed
	for j := 0; j < width-numDigits; j++ {
		buf.WriteByte('0')
	}

	// Write actual digits
	buf.Write(intBuf[i+1 : i+1+numDigits])
}

// FormatLogLine formats a log line - optimized to eliminate fmt.Sprintf
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
	if format == "tsv" {
		var buf strings.Builder
		// Pre-allocate with accurate size estimation
		buf.Grow(len(clientIP) + len(qName) + len(reason) + len(additionalFields)*20 + 100)

		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()

		// Manually format timestamp - much faster than fmt.Sprintf
		buf.WriteByte('[')
		writeInt(&buf, year, 4)
		buf.WriteByte('-')
		writeInt(&buf, int(month), 2)
		buf.WriteByte('-')
		writeInt(&buf, day, 2)
		buf.WriteByte(' ')
		writeInt(&buf, hour, 2)
		buf.WriteByte(':')
		writeInt(&buf, minute, 2)
		buf.WriteByte(':')
		writeInt(&buf, second, 2)
		buf.WriteString("]\t")

		buf.WriteString(clientIP)
		buf.WriteByte('\t')
		buf.WriteString(StringQuote(qName))
		buf.WriteByte('\t')
		buf.WriteString(StringQuote(reason))

		for _, field := range additionalFields {
			buf.WriteByte('\t')
			buf.WriteString(StringQuote(field))
		}

		buf.WriteByte('\n')
		return buf.String(), nil

	} else if format == "ltsv" {
		var buf strings.Builder
		buf.Grow(len(clientIP) + len(qName) + len(reason) + len(additionalFields)*20 + 100)

		buf.WriteString("time:")
		buf.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
		buf.WriteString("\thost:")
		buf.WriteString(clientIP)
		buf.WriteString("\tqname:")
		buf.WriteString(StringQuote(qName))
		buf.WriteString("\tmessage:")
		buf.WriteString(StringQuote(reason))

		for i, field := range additionalFields {
			if i == 0 {
				buf.WriteString("\tip:")
				buf.WriteString(StringQuote(field))
			} else {
				buf.WriteString("\tfield")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteByte(':')
				buf.WriteString(StringQuote(field))
			}
		}

		buf.WriteByte('\n')
		return buf.String(), nil
	}

	return "", fmt.Errorf("unexpected log format: [%s]", format)
}

// ============================================
// OPTIMIZED DNS FUNCTIONS
// ============================================

// reverseAddr creates reverse DNS lookup address - optimized with pre-allocated buffers
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", errors.New("unrecognized address: " + addr)
	}

	if v4 := ip.To4(); v4 != nil {
		// Pre-allocate exact size: max 4*4 (digits) + 3 (dots) + 13 ("in-addr.arpa.")
		buf := make([]byte, 0, 28)

		for i := 3; i >= 0; i-- {
			octet := v4[i]

			// Fast path for common cases - unroll digit conversion
			if octet >= 100 {
				buf = append(buf, byte('0'+octet/100))
				octet %= 100
				buf = append(buf, byte('0'+octet/10), byte('0'+octet%10))
			} else if octet >= 10 {
				buf = append(buf, byte('0'+octet/10), byte('0'+octet%10))
			} else {
				buf = append(buf, byte('0'+octet))
			}
			buf = append(buf, '.')
		}

		buf = append(buf, "in-addr.arpa."...)
		// Zero-copy conversion
		return BytesToString(buf), nil
	}

	// IPv6: pre-allocate exact size
	buf := make([]byte, 0, 72) // 16*4 (nibbles+dots) + 9 ("ip6.arpa.")
	const hexDigits = "0123456789abcdef"

	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigits[v&0xF], '.', hexDigits[v>>4], '.')
	}

	buf = append(buf, "ip6.arpa."...)
	// Zero-copy conversion
	return BytesToString(buf), nil
}

// ============================================
// KEEP EXISTING FUNCTIONS UNCHANGED
// ============================================

// These functions are already well-optimized or don't benefit from further optimization

func PrefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return packet, errors.New("Packet too large")
	}

	newPacket := make([]byte, packetLen+2)
	binary.BigEndian.PutUint16(newPacket[0:2], uint16(packetLen))
	copy(newPacket[2:], packet)
	return newPacket, nil
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func StringQuote(str string) string {
	str = strconv.QuoteToGraphic(str)
	return str[1 : len(str)-1]
}

func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
	hostStr, portStr, err := net.SplitHostPort(str)
	if err != nil {
		if len(str) > 0 && str[0] == '[' && str[len(str)-1] == ']' {
			return str[1 : len(str)-1], defaultPort
		}
		return str, defaultPort
	}

	if p, err := strconv.Atoi(portStr); err == nil {
		return hostStr, p
	}

	return hostStr, defaultPort
}

func ReadTextFile(filename string) (string, error) {
	bin, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
	return string(bin), nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func ExtractClientIPStr(pluginsState *PluginsState) (string, bool) {
	if pluginsState.clientAddr == nil {
		return "", false
	}

	switch pluginsState.clientProto {
	case "udp":
		return (*pluginsState.clientAddr).(*net.UDPAddr).IP.String(), true
	case "tcp", "local_doh":
		return (*pluginsState.clientAddr).(*net.TCPAddr).IP.String(), true
	default:
		return "", false
	}
}

func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
	ipStr, ok := ExtractClientIPStr(pluginsState)
	if !ok || ipCryptConfig == nil {
		return ipStr, ok
	}

	return ipCryptConfig.EncryptIPString(ipStr), ok
}

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

func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (rulePart string, weeklyRanges *WeeklyRanges, err error) {
	rulePart, timeRangeName, found := strings.Cut(line, "@")
	if !found {
		rulePart = line
	} else {
		rulePart = strings.TrimSpace(rulePart)
		timeRangeName = strings.TrimSpace(timeRangeName)
		if strings.Contains(timeRangeName, "@") {
			return "", nil, fmt.Errorf("syntax error at line %d -- Unexpected @ character", 1+lineNo)
		}
		if len(timeRangeName) > 0 {
			if weeklyRangesX, ok := (*allWeeklyRanges)[timeRangeName]; ok {
				weeklyRanges = &weeklyRangesX
			} else {
				return "", nil, fmt.Errorf("time range [%s] not found at line %d", timeRangeName, 1+lineNo)
			}
		}
	}
	return rulePart, weeklyRanges, nil
}

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

func ProcessConfigLines(lines string, processor func(line string, lineNo int) error) error {
	for lineNo, line := range strings.Split(lines, "\n") {
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

func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) (*iradix.Tree, error) {
	err := ProcessConfigLines(lines, func(line string, lineNo int) error {
		cleanLine, trailingStar, lineErr := ParseIPRule(line, lineNo)
		if lineErr != nil {
			dlog.Error(lineErr)
			return nil
		}

		if trailingStar {
			prefixes, _, _ = prefixes.Insert([]byte(cleanLine), 0)
		} else {
			ips[cleanLine] = true
		}

		return nil
	})
	return prefixes, err
}

func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
	if len(logFile) > 0 {
		return Logger(maxSize, maxAge, maxBackups, logFile), format
	}

	return nil, ""
}

func fqdn(name string) string {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return name
	}

	return name + "."
}

// Stub types and functions (would need actual implementations)
type PluginsState struct {
	clientAddr  *net.Addr
	clientProto string
}

type IPCryptConfig struct{}

func (c *IPCryptConfig) EncryptIPString(s string) string {
	return s
}

type WeeklyRanges struct{}

func Logger(maxSize, maxAge, maxBackups int, logFile string) io.Writer {
	return nil
}
