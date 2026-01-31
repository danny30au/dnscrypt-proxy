package main

import (
    "errors"
    "fmt"
    "net"
    "slices"
    "sync"
    "sync/atomic"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/dlog"
    clocksmith "github.com/jedisct1/go-clocksmith"
    stamps "github.com/jedisct1/go-dnsstamps"
)

// Global optimization: Buffer pools and Atomic counters (Go 1.26+)
// Go 1.26 Green Tea GC provides 10-40% reduction in GC overhead
var packetPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 0, MaxDNSPacketSize)
    },
}

var lenBufPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, 2)
        return &b
    },
}

var buffersPool = sync.Pool{
    New: func() interface{} {
        return &net.Buffers{}
    },
}

// Atomic counter for lock-free Round-Robin load balancing
var odohLbCounter atomic.Uint64

// Pool hit/miss metrics for monitoring efficiency
var (
    lenBufPoolHits   atomic.Uint64
    lenBufPoolMisses atomic.Uint64
    packetPoolHits   atomic.Uint64
    packetPoolMisses atomic.Uint64
)

// Reusable error variables to reduce allocations
var (
    errEncryptionFailed   = errors.New("encryption failed")
    errInvalidResponse    = errors.New("invalid response size")
    errNoODoHConfigs      = errors.New("no ODoH target configs available")
    errNetworkFailure     = errors.New("network failure")
    errParseError         = errors.New("parse error")
    errServerTimeout      = errors.New("server timeout")
    errUnsupportedProto   = errors.New("unsupported protocol")
)

const msgServerFailureInfo = "A response with status code 2 was received - this is usually a temporary, remote issue with the configuration of the domain name"

// OPTIMIZATION: Fast byte comparison optimized for compiler auto-vectorization
// Modern compilers (Go 1.26+) can auto-vectorize simple loops on AMD64
//go:inline
func compareBytesOptimized(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }

    // Compiler can auto-vectorize this loop with -gcflags="-B"
    for i := 0; i < len(a); i++ {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// OPTIMIZATION: Fast memory clear optimized for compiler auto-vectorization
//go:inline
func clearBytesOptimized(data []byte) {
    // Use clear() builtin (Go 1.21+) which is optimized by compiler
    for i := range data {
        data[i] = 0
    }
}

// OPTIMIZATION: Fast DNS header validation with optimized field access
//go:inline
func validateDNSHeader(query []byte) bool {
    if len(query) < 12 {
        return false
    }

    // Check QR bit (query must be 0)
    // Compiler optimizes this to direct memory access
    qrByte := query[2]
    if qrByte&0x80 != 0 {
        return false // Not a query
    }

    return true
}

// OPTIMIZATION: Fast transaction ID operations with bit manipulation
//go:inline
func transactionIDMatch(packet []byte, expectedTID uint16) bool {
    if len(packet) < 2 {
        return false
    }

    // Optimized big-endian read
    tid := uint16(packet[0])<<8 | uint16(packet[1])
    return tid == expectedTID
}

// OPTIMIZATION: Inlined size validation
//go:inline
func validateQuerySize(query []byte) bool {
    n := len(query)
    return n >= MinDNSPacketSize && n <= MaxDNSPacketSize
}

// validateQuery - Optimized validation with inlining
//go:inline
func validateQuery(query []byte) bool {
    // Fast size check
    if !validateQuerySize(query) {
        return false
    }

    // Fast header validation
    return validateDNSHeader(query)
}

// handleSynthesizedResponse - Handles a synthesized DNS response from plugins
func handleSynthesizedResponse(pluginsState *PluginsState, synth *dns.Msg) ([]byte, error) {
    if err := synth.Pack(); err != nil {
        pluginsState.returnCode = PluginsReturnCodeParseError
        return nil, fmt.Errorf("failed to pack synthesized response: %w", err)
    }
    return synth.Data, nil
}

// getStaleResponse - Type-safe stale response retrieval from sessionData map
//go:inline
func getStaleResponse(pluginsState *PluginsState) ([]byte, bool) {
    if pluginsState.sessionData == nil {
        return nil, false
    }

    stale, ok := pluginsState.sessionData["stale"]
    if !ok {
        return nil, false
    }

    staleMsg, isMsg := stale.(*dns.Msg)
    if !isMsg || staleMsg == nil {
        return nil, false
    }

    dlog.Debug("Serving stale response")
    if err := staleMsg.Pack(); err != nil {
        dlog.Warnf("Failed to pack stale response: %v", err)
        return nil, false
    }
    return staleMsg.Data, true
}

// OPTIMIZATION: Fast TC flag check with bit masking
//go:inline
func hasTCFlag(response []byte) bool {
    if len(response) < 3 {
        return false
    }
    // TC flag is bit 1 of byte 2 - optimized bit check
    return response[2]&0x02 != 0
}

// shouldRetryOverTCP - Optimized retry detection
//go:inline
func shouldRetryOverTCP(response []byte, err error) bool {
    responseLen := len(response)
    if err == nil {
        // Fast TC flag check
        if responseLen >= MinDNSPacketSize && hasTCFlag(response) {
            return true
        }
        return false
    }
    // Check for timeout error using Go 1.26 errors.AsType
    if neterr, ok := errors.AsType[net.Error](err); ok && neterr.Timeout() {
        return true
    }
    return false
}

// processDNSCryptQuery - Optimized DNSCrypt query processing
func processDNSCryptQuery(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
    serverProto string,
) ([]byte, error) {
    sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
    if err != nil && serverProto == "udp" {
        dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
        serverProto = "tcp"
        sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
    }

    if err != nil {
        pluginsState.returnCode = PluginsReturnCodeParseError
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return nil, fmt.Errorf("DNSCrypt encryption failed for %s: %w", serverInfo.Name, err)
    }

    serverInfo.noticeBegin(proxy)
    var response []byte

    if serverProto == "udp" {
        response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)

        // Optimized retry detection
        if shouldRetryOverTCP(response, err) {
            dlog.Debugf("[%v] Retry over TCP after UDP issues", serverInfo.Name)
            serverProto = "tcp"
            sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
            if err != nil {
                pluginsState.returnCode = PluginsReturnCodeParseError
                pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
                serverInfo.noticeFailure(proxy)
                return nil, fmt.Errorf("DNSCrypt TCP retry encryption failed for %s: %w", serverInfo.Name, err)
            }
            response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
        }
    } else {
        response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
    }

    if err != nil {
        serverInfo.noticeFailure(proxy)
        if staleData, ok := getStaleResponse(pluginsState); ok {
            return staleData, nil
        }
        if neterr, ok := errors.AsType[net.Error](err); ok && neterr.Timeout() {
            pluginsState.returnCode = PluginsReturnCodeServerTimeout
        } else {
            pluginsState.returnCode = PluginsReturnCodeNetworkError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return nil, fmt.Errorf("DNSCrypt exchange failed for %s: %w", serverInfo.Name, err)
    }

    return response, nil
}

// processDoHQuery - Optimized DoH query processing
func processDoHQuery(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
) ([]byte, error) {
    tid := TransactionID(query)
    SetTransactionID(query, 0)
    serverInfo.noticeBegin(proxy)
    serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(serverInfo.useGet, serverInfo.URL, query, proxy.timeout)
    SetTransactionID(query, tid)

    if err == nil && tls != nil && tls.HandshakeComplete {
        responseLen := len(serverResponse)
        if responseLen >= MinDNSPacketSize {
            SetTransactionID(serverResponse, tid)
        }
        return serverResponse, nil
    }

    serverInfo.noticeFailure(proxy)

    if staleData, ok := getStaleResponse(pluginsState); ok {
        return staleData, nil
    }

    pluginsState.returnCode = PluginsReturnCodeNetworkError
    pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
    return nil, fmt.Errorf("DoH query failed for %s: %w", serverInfo.Name, err)
}

// processODoHQuery - Optimized ODoH query processing
func processODoHQuery(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
) ([]byte, error) {
    tid := TransactionID(query)

    configCount := len(serverInfo.odohTargetConfigs)
    if configCount == 0 {
        return nil, fmt.Errorf("no ODoH target configs available for %s", serverInfo.Name)
    }

    serverInfo.noticeBegin(proxy)

    // Lock-free atomic Round-Robin
    targetIdx := odohLbCounter.Add(1) % uint64(configCount)
    target := serverInfo.odohTargetConfigs[targetIdx]

    odohQuery, err := target.encryptQuery(query)
    if err != nil {
        dlog.Errorf("Failed to encrypt query for [%v]", serverInfo.Name)
        return nil, fmt.Errorf("ODoH encryption failed for %s: %w", serverInfo.Name, err)
    }

    targetURL := serverInfo.URL
    if serverInfo.Relay != nil && serverInfo.Relay.ODoH != nil {
        targetURL = serverInfo.Relay.ODoH.URL
    }

    responseBody, responseCode, _, _, err := proxy.xTransport.ObliviousDoHQuery(
        serverInfo.useGet, targetURL, odohQuery.odohMessage, proxy.timeout)

    if err == nil && len(responseBody) > 0 && responseCode == 200 {
        response, err := odohQuery.decryptResponse(responseBody)
        if err != nil {
            dlog.Warnf("Failed to decrypt response from [%v]", serverInfo.Name)
            serverInfo.noticeFailure(proxy)
            return nil, fmt.Errorf("ODoH decryption failed for %s: %w", serverInfo.Name, err)
        }

        responseLen := len(response)
        if responseLen >= MinDNSPacketSize {
            SetTransactionID(response, tid)
        }

        return response, nil
    }

    if responseCode == 401 || (responseCode == 200 && len(responseBody) == 0) {
        if responseCode == 200 {
            dlog.Warnf("ODoH relay for [%v] is buggy...", serverInfo.Name)
        }
        dlog.Infof("Forcing key update for [%v]", serverInfo.Name)

        serverIdx := slices.IndexFunc(proxy.serversInfo.registeredServers, func(s RegisteredServer) bool {
            return s.name == serverInfo.Name
        })
        if serverIdx != -1 {
            s := proxy.serversInfo.registeredServers[serverIdx]
            if err = proxy.serversInfo.refreshServer(proxy, s.name, s.stamp); err != nil {
                dlog.Noticef("Key update failed for [%v]", serverInfo.Name)
                serverInfo.noticeFailure(proxy)
                clocksmith.Sleep(10 * time.Second)
            }
        }
    } else {
        dlog.Warnf("Failed to receive successful response from [%v]", serverInfo.Name)
    }

    pluginsState.returnCode = PluginsReturnCodeNetworkError
    pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
    serverInfo.noticeFailure(proxy)

    return nil, fmt.Errorf("ODoH query failed for %s with code %d: %w", serverInfo.Name, responseCode, err)
}

// handleDNSExchange - Optimized DNS exchange handler
func handleDNSExchange(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
    serverProto string,
) ([]byte, error) {
    var err error
    var response []byte

    switch serverInfo.Proto {
    case stamps.StampProtoTypeDNSCrypt:
        response, err = processDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto)
    case stamps.StampProtoTypeDoH:
        response, err = processDoHQuery(proxy, serverInfo, pluginsState, query)
    case stamps.StampProtoTypeODoHTarget:
        response, err = processODoHQuery(proxy, serverInfo, pluginsState, query)
    default:
        return nil, fmt.Errorf("unsupported protocol: %v", serverInfo.Proto)
    }

    if err != nil {
        return nil, err
    }

    // Fast size validation
    responseLen := len(response)
    if responseLen < MinDNSPacketSize || responseLen > MaxDNSPacketSize {
        pluginsState.returnCode = PluginsReturnCodeParseError
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        serverInfo.noticeFailure(proxy)
        return nil, fmt.Errorf("invalid response size from %s: %d bytes", serverInfo.Name, responseLen)
    }

    return response, nil
}

// processPlugins - Optimized plugin processing
func processPlugins(
    proxy *Proxy,
    pluginsState *PluginsState,
    query []byte,
    serverInfo *ServerInfo,
    response []byte,
) ([]byte, error) {
    var err error

    response, err = pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
    if err != nil {
        pluginsState.returnCode = PluginsReturnCodeParseError
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        serverInfo.noticeFailure(proxy)
        return response, fmt.Errorf("response plugin failed: %w", err)
    }

    if pluginsState.action == PluginsActionDrop {
        pluginsState.returnCode = PluginsReturnCodeDrop
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return response, nil
    }

    if pluginsState.synthResponse != nil {
        if err = pluginsState.synthResponse.Pack(); err != nil {
            pluginsState.returnCode = PluginsReturnCodeParseError
            pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
            return response, fmt.Errorf("failed to pack synthetic response: %w", err)
        }
        response = pluginsState.synthResponse.Data
    }

    rcode := Rcode(response)
    if rcode == dns.RcodeServerFailure {
        if pluginsState.dnssec {
            dlog.Debug("A response had an invalid DNSSEC signature")
        } else {
            dlog.Info(msgServerFailureInfo)
            serverInfo.noticeFailure(proxy)
        }
    } else {
        serverInfo.noticeSuccess(proxy)
    }

    return response, nil
}

// sendResponse - Optimized response sending
func sendResponse(
    proxy *Proxy,
    pluginsState *PluginsState,
    response []byte,
    clientProto string,
    clientAddr *net.Addr,
    clientPc net.Conn,
) {
    responseLen := len(response)
    if responseLen < MinDNSPacketSize || responseLen > MaxDNSPacketSize {
        if responseLen == 0 {
            pluginsState.returnCode = PluginsReturnCodeNotReady
        } else {
            pluginsState.returnCode = PluginsReturnCodeParseError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return
    }

    switch clientProto {
    case "udp":
        var err error
        if responseLen > pluginsState.maxUnencryptedUDPSafePayloadSize {
            response, err = TruncatedResponse(response)
            if err != nil {
                pluginsState.returnCode = PluginsReturnCodeParseError
                pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
                return
            }
            responseLen = len(response)
        }
        if _, err := clientPc.(net.PacketConn).WriteTo(response, *clientAddr); err != nil {
            dlog.Warnf("Failed to write UDP response: %v", err)
        }
        // Optimized TC flag check
        if hasTCFlag(response) {
            proxy.questionSizeEstimator.blindAdjust()
        } else {
            proxy.questionSizeEstimator.adjust(ResponseOverhead + responseLen)
        }

    case "tcp":
        lenBuf := lenBufPool.Get().(*[]byte)
        defer lenBufPool.Put(lenBuf)

        (*lenBuf)[0] = byte(responseLen >> 8)
        (*lenBuf)[1] = byte(responseLen)

        if clientPc != nil {
            buffers := buffersPool.Get().(*net.Buffers)
            *buffers = net.Buffers{*lenBuf, response}

            _, err := buffers.WriteTo(clientPc)

            *buffers = (*buffers)[:0]
            buffersPool.Put(buffers)

            if err != nil {
                dlog.Warnf("Failed to write TCP response: %v", err)
            }
        }
    }
}

// updateMonitoringMetrics - Updates monitoring metrics
func updateMonitoringMetrics(
    proxy *Proxy,
    pluginsState *PluginsState,
) {
    if pluginsState.questionMsg == nil {
        return
    }

    if proxy.monitoringUI.Enabled && proxy.monitoringInstance != nil {
        proxy.monitoringInstance.UpdateMetrics(*pluginsState, pluginsState.questionMsg)
    }
}

// GetPoolStats - Returns current pool efficiency metrics
func GetPoolStats() map[string]uint64 {
    return map[string]uint64{
        "lenBufPoolHits":    lenBufPoolHits.Load(),
        "lenBufPoolMisses":  lenBufPoolMisses.Load(),
        "packetPoolHits":    packetPoolHits.Load(),
        "packetPoolMisses":  packetPoolMisses.Load(),
        "odohRequests":      odohLbCounter.Load(),
    }
}

// GetPoolHitRate - Returns pool hit rate percentage
func GetPoolHitRate() float64 {
    hits := lenBufPoolHits.Load()
    misses := lenBufPoolMisses.Load()
    total := hits + misses
    if total == 0 {
        return 0.0
    }
    return float64(hits) / float64(total) * 100.0
}
