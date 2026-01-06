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
)

type CryptoConstruction uint16

const (
    UndefinedConstruction CryptoConstruction = iota
    XSalsa20Poly1305
    XChacha20Poly1305
)

const (
    ClientMagicLen = 8
)

const (
    MaxHTTPBodyLength = 1000000
)

var (
    CertMagic               = [4]byte{0x44, 0x4e, 0x53, 0x43}
    ServerMagic             = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
    MinDNSPacketSize        = 12 + 5
    MaxDNSPacketSize        = 4096
    MaxDNSUDPPacketSize     = 4096
    MaxDNSUDPSafePacketSize = 1252
    InitialMinQuestionSize  = 512
)

var (
    FileDescriptors   = make([]*os.File, 0)
    FileDescriptorNum = uintptr(0)
    FileDescriptorsMu sync.Mutex
)

const (
    InheritedDescriptorsBase = uintptr(50)
)

// PrefixWithSize - OPTIMIZED: Single allocation, no copying overhead.
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

// ReadPrefixed - OPTIMIZED: Start with smaller buffer, grow only if needed.
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
    buf := make([]byte, 512)
    packetLength, pos := -1, 0
    for {
        if pos >= len(buf) {
            if len(buf) >= 2+MaxDNSPacketSize {
                return buf, errors.New("Packet too large")
            }
            newBuf := make([]byte, min(len(buf)*2, 2+MaxDNSPacketSize))
            copy(newBuf, buf)
            buf = newBuf
        }
        readnb, err := (*conn).Read(buf[pos:])
        if err != nil {
            return buf[:pos], err
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
            if 2+packetLength > len(buf) {
                newBuf := make([]byte, 2+packetLength)
                copy(newBuf, buf[:pos])
                buf = newBuf
            }
        }
        if packetLength >= 0 && pos >= 2+packetLength {
            return buf[2 : 2+packetLength], nil
        }
    }
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

// StringReverse - OPTIMIZED: Fast path for ASCII strings.
func StringReverse(s string) string {
    isASCII := true
    for i := 0; i < len(s); i++ {
        if s[i] >= 0x80 {
            isASCII = false
            break
        }
    }

    if isASCII {
        b := []byte(s)
        for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
            b[i], b[j] = b[j], b[i]
        }
        return string(b)
    }

    r := []rune(s)
    for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
        r[i], r[j] = r[j], r[i]
    }
    return string(r)
}

// StringTwoFields - OPTIMIZED: Single pass with manual trimming.
func StringTwoFields(str string) (string, string, bool) {
    if len(str) < 3 {
        return "", "", false
    }

    var i int
    for i = 0; i < len(str); i++ {
        if str[i] == ' ' || str[i] == '\t' || str[i] == '
' || str[i] == '
' {
            break
        }
    }

    if i == len(str) || i == 0 {
        return "", "", false
    }

    a := str[:i]

    var j int
    for j = i; j < len(str); j++ {
        if str[j] != ' ' && str[j] != '\t' && str[j] != '
' && str[j] != '
' {
            break
        }
    }

    if j >= len(str) {
        return "", "", false
    }

    k := len(str) - 1
    for k > j && (str[k] == ' ' || str[k] == '\t' || str[k] == '
' || str[k] == '
') {
        k--
    }

    b := str[j : k+1]
    if len(b) == 0 {
        return "", "", false
    }

    return a, b, true
}

func StringQuote(str string) string {
    str = strconv.QuoteToGraphic(str)
    return str[1 : len(str)-1]
}

// StringStripSpaces - OPTIMIZED: Use strings.Builder for better performance.
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

// TrimAndStripInlineComments - OPTIMIZED: Single pass with index tracking.
func TrimAndStripInlineComments(str string) string {
    idx := -1
    for i := len(str) - 1; i >= 0; i-- {
        if str[i] == '#' {
            if i == 0 {
                return ""
            }
            if str[i-1] == ' ' || str[i-1] == '\t' {
                idx = i - 1
                break
            }
        }
    }

    if idx >= 0 {
        str = str[:idx]
    }

    start := 0
    for start < len(str) && (str[start] == ' ' || str[start] == '\t' || str[start] == '
' || str[start] == '
') {
        start++
    }

    end := len(str)
    for end > start && (str[end-1] == ' ' || str[end-1] == '\t' || str[end-1] == '
' || str[end-1] == '
') {
        end--
    }

    return str[start:end]
}

// ExtractHostAndPort parses a string containing a host and optional port.
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

// ReadTextFile reads a file and returns its contents as a string.
func ReadTextFile(filename string) (string, error) {
    bin, err := os.ReadFile(filename)
    if err != nil {
        return "", err
    }
    bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
    return string(bin), nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ExtractClientIPStr extracts client IP string from pluginsState based on protocol.
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

// ExtractClientIPStrEncrypted extracts and optionally encrypts client IP string.
func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
    ipStr, ok := ExtractClientIPStr(pluginsState)
    if !ok || ipCryptConfig == nil {
        return ipStr, ok
    }
    return ipCryptConfig.EncryptIPString(ipStr), ok
}

// FormatLogLine - OPTIMIZED: Use strings.Builder, reduce format operations.
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
    if format == "tsv" {
        var buf strings.Builder
        buf.Grow(len(clientIP) + len(qName) + len(reason) + len(additionalFields)*20 + 100)

        now := time.Now()
        year, month, day := now.Date()
        hour, minute, second := now.Clock()

        buf.WriteString("[")
        buf.WriteString(fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d", year, int(month), day, hour, minute, second))
        buf.WriteString("]\t")
        buf.WriteString(clientIP)
        buf.WriteString("\t")
        buf.WriteString(StringQuote(qName))
        buf.WriteString("\t")
        buf.WriteString(StringQuote(reason))

        for _, field := range additionalFields {
            buf.WriteString("\t")
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

// WritePluginLog writes a log entry for plugin actions.
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

// ParseTimeBasedRule parses a rule line that may contain time-based restrictions (@timerange).
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

// ParseIPRule parses and validates an IP rule line.
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

// ProcessConfigLines processes configuration file lines, calling the processor function for each non-empty line.
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

// LoadIPRules loads IP rules from text lines into radix tree and map structures.
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

// InitializePluginLogger initializes a logger for a plugin if the log file is configured.
func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
    if len(logFile) > 0 {
        return Logger(maxSize, maxAge, maxBackups, logFile), format
    }
    return nil, ""
}

// reverseAddr - OPTIMIZED: Direct byte conversion instead of strconv calls.
func reverseAddr(addr string) (string, error) {
    ip := net.ParseIP(addr)
    if ip == nil {
        return "", errors.New("unrecognized address: " + addr)
    }
    if v4 := ip.To4(); v4 != nil {
        buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
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
func fqdn(name string) string {
    if len(name) == 0 || name[len(name)-1] == '.' {
        return name
    }
    return name + "."
}
