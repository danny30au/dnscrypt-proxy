package main

import (
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
var packetPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, MaxDNSPacketSize)
        return &b
    },
}

var lenBufPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, 2)
        return &b
    },
}

// Atomic counter for lock-free Round-Robin load balancing
var odohLbCounter atomic.Uint64

// validateQuery - Performs basic validation on the incoming query
func validateQuery(query []byte) bool {
    if len(query) < MinDNSPacketSize {
        return false
    }
    if len(query) > MaxDNSPacketSize {
        return false
    }
    return true
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

// processDNSCryptQuery - Processes a query using the DNSCrypt protocol with improved error handling
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
        retryOverTCP := false
        if err == nil && len(response) >= MinDNSPacketSize && response[2]&0x02 == 0x02 {
            retryOverTCP = true
        } else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
            dlog.Debugf("[%v] Retry over TCP after UDP timeouts", serverInfo.Name)
            retryOverTCP = true
        }
        if retryOverTCP {
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
        if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
            pluginsState.returnCode = PluginsReturnCodeServerTimeout
        } else {
            pluginsState.returnCode = PluginsReturnCodeNetworkError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return nil, fmt.Errorf("DNSCrypt exchange failed for %s: %w", serverInfo.Name, err)
    }

    return response, nil
}

// processDoHQuery - Processes a query using the DoH protocol with improved error handling
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
        response := serverResponse
        if len(response) >= MinDNSPacketSize {
            SetTransactionID(response, tid)
        }
        return response, nil
    }

    serverInfo.noticeFailure(proxy)

    if staleData, ok := getStaleResponse(pluginsState); ok {
        return staleData, nil
    }

    pluginsState.returnCode = PluginsReturnCodeNetworkError
    pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
    return nil, fmt.Errorf("DoH query failed for %s: %w", serverInfo.Name, err)
}

// processODoHQuery - Processes a query using the ODoH protocol with enhanced error context
func processODoHQuery(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
) ([]byte, error) {
    tid := TransactionID(query)

    if len(serverInfo.odohTargetConfigs) == 0 {
        return nil, fmt.Errorf("no ODoH target configs available for %s", serverInfo.Name)
    }

    serverInfo.noticeBegin(proxy)

    // Optimization: Lock-free atomic Round-Robin (Go 1.19+)
    idx := odohLbCounter.Add(1) % uint64(len(serverInfo.odohTargetConfigs))
    target := serverInfo.odohTargetConfigs[idx]

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

        if len(response) >= MinDNSPacketSize {
            SetTransactionID(response, tid)
        }

        return response, nil
    }

    if responseCode == 401 || (responseCode == 200 && len(responseBody) == 0) {
        if responseCode == 200 {
            dlog.Warnf("ODoH relay for [%v] is buggy...", serverInfo.Name)
        }
        dlog.Infof("Forcing key update for [%v]", serverInfo.Name)

        // Optimization: Use slices.IndexFunc (Go 1.21+) for cleaner lookup
        idx := slices.IndexFunc(proxy.serversInfo.registeredServers, func(s RegisteredServer) bool {
            return s.name == serverInfo.Name
        })
        if idx != -1 {
            s := proxy.serversInfo.registeredServers[idx]
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

// handleDNSExchange - Handles the DNS exchange with a server using enhanced validation
func handleDNSExchange(
    proxy *Proxy,
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
    serverProto string,
) ([]byte, error) {
    var err error
    var response []byte

    if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
        response, err = processDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto)
    } else if serverInfo.Proto == stamps.StampProtoTypeDoH {
        response, err = processDoHQuery(proxy, serverInfo, pluginsState, query)
    } else if serverInfo.Proto == stamps.StampProtoTypeODoHTarget {
        response, err = processODoHQuery(proxy, serverInfo, pluginsState, query)
    } else {
        dlog.Fatal("Unsupported protocol")
    }

    if err != nil {
        return nil, err
    }

    if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
        pluginsState.returnCode = PluginsReturnCodeParseError
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        serverInfo.noticeFailure(proxy)
        return nil, fmt.Errorf("invalid response size from %s: %d bytes", serverInfo.Name, len(response))
    }

    return response, nil
}

// processPlugins - Processes plugins for both query and response with enhanced error context
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

    if rcode := Rcode(response); rcode == dns.RcodeServerFailure {
        if pluginsState.dnssec {
            dlog.Debug("A response had an invalid DNSSEC signature")
        } else {
            dlog.Infof("A response with status code 2 was received - this is usually a temporary, remote issue with the configuration of the domain name")
            serverInfo.noticeFailure(proxy)
        }
    } else {
        serverInfo.noticeSuccess(proxy)
    }

    return response, nil
}

// sendResponse - Sends the response back to the client with improved error handling
func sendResponse(
    proxy *Proxy,
    pluginsState *PluginsState,
    response []byte,
    clientProto string,
    clientAddr *net.Addr,
    clientPc net.Conn,
) {
    if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
        if len(response) == 0 {
            pluginsState.returnCode = PluginsReturnCodeNotReady
        } else {
            pluginsState.returnCode = PluginsReturnCodeParseError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return
    }

    var err error
    if clientProto == "udp" {
        if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
            response, err = TruncatedResponse(response)
            if err != nil {
                pluginsState.returnCode = PluginsReturnCodeParseError
                pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
                return
            }
        }
        if _, err := clientPc.(net.PacketConn).WriteTo(response, *clientAddr); err != nil {
            dlog.Warnf("Failed to write UDP response: %v", err)
        }
        if HasTCFlag(response) {
            proxy.questionSizeEstimator.blindAdjust()
        } else {
            proxy.questionSizeEstimator.adjustResponseOverhead(len(response))
        }
    } else if clientProto == "tcp" {
        // Optimization: Use net.Buffers for zero-copy vectored I/O
        lenBufPtr := lenBufPool.Get().(*[]byte)
        lenBuf := *lenBufPtr
        defer lenBufPool.Put(lenBufPtr)

        lenBuf[0] = byte(len(response) >> 8)
        lenBuf[1] = byte(len(response))

        if clientPc != nil {
            v := net.Buffers{lenBuf, response}
            if _, err := v.WriteTo(clientPc); err != nil {
                dlog.Warnf("Failed to write TCP response: %v", err)
            }
        }
    }
}

// updateMonitoringMetrics - Updates monitoring metrics if enabled with cleaner logic
func updateMonitoringMetrics(
    proxy *Proxy,
    pluginsState *PluginsState,
) {
    if proxy.monitoringUI.Enabled && proxy.monitoringInstance != nil && pluginsState.questionMsg != nil {
        proxy.monitoringInstance.UpdateMetrics(*pluginsState, pluginsState.questionMsg)
    } else if pluginsState.questionMsg == nil {
        dlog.Debugf("Question message is nil")
    }
}
