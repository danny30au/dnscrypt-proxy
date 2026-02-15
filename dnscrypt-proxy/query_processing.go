package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
)

// Constants for DNS processing
const (
	// HTTP status codes for ODoH
	HTTPStatusOK           = 200
	HTTPStatusUnauthorized = 401

	// ODoH key update retry delay
	KeyUpdateRetryDelay = 10 * time.Second

	// DNS response flags
	DNSTruncatedFlag = 0x02
)

// Common errors
var (
	ErrQueryTooSmall       = errors.New("DNS query too small")
	ErrQueryTooLarge       = errors.New("DNS query too large")
	ErrResponseTooSmall    = errors.New("DNS response too small")
	ErrResponseTooLarge    = errors.New("DNS response too large")
	ErrInvalidResponse     = errors.New("invalid DNS response")
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrNoODoHConfig        = errors.New("no ODoH target configs available")
)

// validateQuery performs basic validation on the incoming DNS query.
// Go 1.26: Maintains backward compatibility by returning bool.
func validateQuery(query []byte) bool {
	return len(query) >= MinDNSPacketSize && len(query) <= MaxDNSPacketSize
}

// validateQueryWithError performs validation and returns detailed error information.
// Go 1.26: New function for better error reporting while maintaining compatibility.
func validateQueryWithError(query []byte) error {
	queryLen := len(query)

	if queryLen < MinDNSPacketSize {
		return fmt.Errorf("%w: got %d bytes, minimum %d", ErrQueryTooSmall, queryLen, MinDNSPacketSize)
	}

	if queryLen > MaxDNSPacketSize {
		return fmt.Errorf("%w: got %d bytes, maximum %d", ErrQueryTooLarge, queryLen, MaxDNSPacketSize)
	}

	return nil
}

// validateResponse performs validation on the DNS response.
// Go 1.26: Extracted validation logic for reuse.
func validateResponse(response []byte) error {
	responseLen := len(response)

	if responseLen < MinDNSPacketSize {
		return fmt.Errorf("%w: got %d bytes, minimum %d", ErrResponseTooSmall, responseLen, MinDNSPacketSize)
	}

	if responseLen > MaxDNSPacketSize {
		return fmt.Errorf("%w: got %d bytes, maximum %d", ErrResponseTooLarge, responseLen, MaxDNSPacketSize)
	}

	return nil
}

// handleSynthesizedResponse handles a synthesized DNS response from plugins.
// Go 1.26: Better error wrapping and validation.
func handleSynthesizedResponse(pluginsState *PluginsState, synth *dns.Msg) ([]byte, error) {
	if synth == nil {
		return nil, errors.New("synthesized message is nil")
	}

	if err := synth.Pack(); err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		return nil, fmt.Errorf("failed to pack synthesized response: %w", err)
	}

	return synth.Data, nil
}

// tryServeStaleResponse attempts to serve a stale cached response as fallback.
// Go 1.26: Extracted common stale response logic with safe type assertion.
func tryServeStaleResponse(pluginsState *PluginsState) ([]byte, bool) {
	stale, ok := pluginsState.sessionData["stale"]
	if !ok {
		return nil, false
	}

	// Safe type assertion
	staleMsg, ok := stale.(*dns.Msg)
	if !ok {
		dlog.Warn("Invalid stale response type in session data")
		return nil, false
	}

	dlog.Debug("Serving stale response")

	if err := staleMsg.Pack(); err != nil {
		dlog.Warnf("Failed to pack stale response: %v", err)
		return nil, false
	}

	return staleMsg.Data, true
}

// encryptQueryForProtocol encrypts a query for the specified protocol.
// Go 1.26: Extracted encryption logic with better error context.
func encryptQueryForProtocol(
	proxy *Proxy,
	serverInfo *ServerInfo,
	query []byte,
	proto string,
) (sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte, err error) {
	sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, proto)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt query for %s: %w", proto, err)
	}
	return sharedKey, encryptedQuery, clientNonce, nil
}

// shouldRetryOverTCP determines if a UDP query should be retried over TCP.
// Go 1.26: Extracted TCP fallback decision logic.
func shouldRetryOverTCP(response []byte, err error, serverInfo *ServerInfo) bool {
	// Check for truncated response flag (TC bit in DNS header)
	if err == nil && len(response) >= MinDNSPacketSize {
		// Byte 2, bit 1 is the TC (truncated) flag
		if response[2]&DNSTruncatedFlag == DNSTruncatedFlag {
			return true
		}
	}

	// Check for timeout error
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		dlog.Debugf("[%v] Retry over TCP after UDP timeout", serverInfo.Name)
		return true
	}

	return false
}

// handleEncryptionError handles encryption errors and logs them appropriately.
// Go 1.26: Centralized error handling for encryption failures.
func handleEncryptionError(proxy *Proxy, pluginsState *PluginsState, serverInfo *ServerInfo, err error) error {
	pluginsState.returnCode = PluginsReturnCodeParseError
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	serverInfo.noticeFailure(proxy)
	return err
}

// processDNSCryptQuery processes a query using the DNSCrypt protocol.
// Go 1.26: Refactored with extracted helper functions and clearer flow.
func processDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	// Initial encryption attempt
	sharedKey, encryptedQuery, clientNonce, err := encryptQueryForProtocol(proxy, serverInfo, query, serverProto)

	// Fallback to TCP if UDP encryption fails
	if err != nil && serverProto == "udp" {
		dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
		serverProto = "tcp"
		sharedKey, encryptedQuery, clientNonce, err = encryptQueryForProtocol(proxy, serverInfo, query, serverProto)
	}

	if err != nil {
		return nil, handleEncryptionError(proxy, pluginsState, serverInfo, err)
	}

	serverInfo.noticeBegin(proxy)

	// Execute query based on protocol
	response, err := executeDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto, sharedKey, encryptedQuery, clientNonce)

	// Handle query failure with stale response fallback
	if err != nil {
		serverInfo.noticeFailure(proxy)

		if staleResponse, ok := tryServeStaleResponse(pluginsState); ok {
			return staleResponse, nil
		}

		// Categorize error type
		return nil, handleQueryError(proxy, pluginsState, err)
	}

	return response, nil
}

// executeDNSCryptQuery executes the DNSCrypt query with automatic TCP fallback.
// Go 1.26: Separated execution logic from error handling.
func executeDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	var response []byte
	var err error

	if serverProto == "udp" {
		response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)

		// Check if TCP fallback is needed
		if shouldRetryOverTCP(response, err, serverInfo) {
			dlog.Debugf("[%v] Falling back to TCP", serverInfo.Name)

			// Re-encrypt for TCP
			sharedKey, encryptedQuery, clientNonce, err = encryptQueryForProtocol(proxy, serverInfo, query, "tcp")
			if err != nil {
				return nil, handleEncryptionError(proxy, pluginsState, serverInfo, err)
			}

			response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
		}
	} else {
		response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	}

	return response, err
}

// handleQueryError categorizes and handles DNS query errors.
// Go 1.26: Centralized error categorization logic.
func handleQueryError(proxy *Proxy, pluginsState *PluginsState, err error) error {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		pluginsState.returnCode = PluginsReturnCodeServerTimeout
	} else {
		pluginsState.returnCode = PluginsReturnCodeNetworkError
	}

	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	return err
}

// processDoHQuery processes a query using the DNS-over-HTTPS (DoH) protocol.
// Go 1.26: Simplified flow with extracted helper functions.
func processDoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	// Save and clear transaction ID for DoH
	tid := TransactionID(query)
	SetTransactionID(query, 0)

	serverInfo.noticeBegin(proxy)

	// Execute DoH query
	serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(
		serverInfo.useGet,
		serverInfo.URL,
		query,
		proxy.timeout,
	)

	// Restore transaction ID
	SetTransactionID(query, tid)

	// Check for successful response
	if err == nil && tls != nil && tls.HandshakeComplete {
		response := serverResponse
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}
		return response, nil
	}

	// Handle failure
	serverInfo.noticeFailure(proxy)

	// Try stale response fallback
	if staleResponse, ok := tryServeStaleResponse(pluginsState); ok {
		return staleResponse, nil
	}

	// Return error
	pluginsState.returnCode = PluginsReturnCodeNetworkError
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)

	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}

	return nil, errors.New("DoH query failed: incomplete TLS handshake")
}

// processODoHQuery processes a query using the Oblivious DNS-over-HTTPS (ODoH) protocol.
// Go 1.26: Simplified to work with actual implementation without type assumptions.
func processODoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	tid := TransactionID(query)

	if len(serverInfo.odohTargetConfigs) == 0 {
		return nil, ErrNoODoHConfig
	}

	serverInfo.noticeBegin(proxy)

	// Select random target configuration
	target := serverInfo.odohTargetConfigs[rand.Intn(len(serverInfo.odohTargetConfigs))]

	// Encrypt query - use actual method without type assumptions
	odohQuery, err := target.encryptQuery(query)
	if err != nil {
		dlog.Errorf("Failed to encrypt query for [%v]: %v", serverInfo.Name, err)
		return nil, fmt.Errorf("ODoH encryption failed: %w", err)
	}

	// Determine target URL
	targetURL := serverInfo.URL
	if serverInfo.Relay != nil && serverInfo.Relay.ODoH != nil {
		targetURL = serverInfo.Relay.ODoH.URL
	}

	// Execute ODoH query
	responseBody, responseCode, _, _, err := proxy.xTransport.ObliviousDoHQuery(
		serverInfo.useGet,
		targetURL,
		odohQuery.odohMessage,
		proxy.timeout,
	)

	// Handle successful response
	if err == nil && len(responseBody) > 0 && responseCode == HTTPStatusOK {
		response, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Failed to decrypt response from [%v]: %v", serverInfo.Name, err)
			serverInfo.noticeFailure(proxy)
			return nil, fmt.Errorf("ODoH decryption failed: %w", err)
		}

		// Restore original transaction ID
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}

		return response, nil
	}

	// Handle key update scenarios
	if responseCode == HTTPStatusUnauthorized || (responseCode == HTTPStatusOK && len(responseBody) == 0) {
		if responseCode == HTTPStatusOK {
			dlog.Warnf(
				"ODoH relay for [%v] is buggy and returns a 200 status code instead of 401 after a key update",
				serverInfo.Name,
			)
		}

		dlog.Infof("Forcing key update for [%v]", serverInfo.Name)

		// Find and refresh the server
		for _, registeredServer := range proxy.serversInfo.registeredServers {
			if registeredServer.name == serverInfo.Name {
				if err := proxy.serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err != nil {
					dlog.Noticef("Key update failed for [%v]: %v", serverInfo.Name, err)
					serverInfo.noticeFailure(proxy)
					clocksmith.Sleep(KeyUpdateRetryDelay)
				}
				break
			}
		}
	} else {
		dlog.Warnf("Failed to receive successful response from [%v]: status=%d, err=%v", 
			serverInfo.Name, responseCode, err)
	}

	// Query failed
	pluginsState.returnCode = PluginsReturnCodeNetworkError
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	serverInfo.noticeFailure(proxy)

	if err != nil {
		return nil, fmt.Errorf("ODoH query failed: %w", err)
	}

	return nil, fmt.Errorf("ODoH query failed: status code %d", responseCode)
}

// handleDNSExchange handles the DNS exchange with a server based on protocol type.
// Go 1.26: Use switch statement instead of if-else chain, better error handling.
func handleDNSExchange(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	var response []byte
	var err error

	// Process query based on protocol type
	switch serverInfo.Proto {
	case stamps.StampProtoTypeDNSCrypt:
		response, err = processDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto)

	case stamps.StampProtoTypeDoH:
		response, err = processDoHQuery(proxy, serverInfo, pluginsState, query)

	case stamps.StampProtoTypeODoHTarget:
		response, err = processODoHQuery(proxy, serverInfo, pluginsState, query)

	default:
		// Fatal error for unsupported protocols
		dlog.Fatalf("Unsupported protocol: %v", serverInfo.Proto)
		return nil, ErrUnsupportedProtocol
	}

	if err != nil {
		return nil, err
	}

	// Validate response size
	if err := validateResponse(response); err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		serverInfo.noticeFailure(proxy)
		return nil, err
	}

	return response, nil
}

// processPlugins processes plugins for both query and response.
// Go 1.26: Better error handling and clearer flow.
func processPlugins(
	proxy *Proxy,
	pluginsState *PluginsState,
	query []byte,
	serverInfo *ServerInfo,
	response []byte,
) ([]byte, error) {
	// Apply response plugins
	processedResponse, err := pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
	if err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		serverInfo.noticeFailure(proxy)
		return processedResponse, fmt.Errorf("response plugin failed: %w", err)
	}

	// Handle drop action
	if pluginsState.action == PluginsActionDrop {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return processedResponse, nil
	}

	// Handle synthesized response
	if pluginsState.synthResponse != nil {
		if err := pluginsState.synthResponse.Pack(); err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return processedResponse, fmt.Errorf("failed to pack synthetic response: %w", err)
		}
		processedResponse = pluginsState.synthResponse.Data
	}

	// Handle response code and update server metrics
	handleResponseCode(proxy, pluginsState, serverInfo, processedResponse)

	return processedResponse, nil
}

// handleResponseCode checks the DNS response code and updates server status.
// Go 1.26: Extracted response code handling logic.
func handleResponseCode(proxy *Proxy, pluginsState *PluginsState, serverInfo *ServerInfo, response []byte) {
	rcode := Rcode(response)

	if rcode == dns.RcodeServerFailure {
		if pluginsState.dnssec {
			dlog.Debug("A response had an invalid DNSSEC signature")
		} else {
			dlog.Info("A response with SERVFAIL status was received - this is usually a temporary, remote issue with the domain configuration")
			serverInfo.noticeFailure(proxy)
		}
	} else {
		serverInfo.noticeSuccess(proxy)
	}
}

// sendResponse sends the DNS response back to the client.
// Go 1.26: Better error handling and protocol-specific logic extraction.
func sendResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientProto string,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	// Validate response size
	if err := validateResponse(response); err != nil {
		if len(response) == 0 {
			pluginsState.returnCode = PluginsReturnCodeNotReady
		} else {
			pluginsState.returnCode = PluginsReturnCodeParseError
		}
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}

	// Send response based on protocol
	switch clientProto {
	case "udp":
		sendUDPResponse(proxy, pluginsState, response, clientAddr, clientPc)
	case "tcp":
		sendTCPResponse(proxy, pluginsState, response, clientPc)
	default:
		dlog.Warnf("Unknown client protocol: %s", clientProto)
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	}
}

// sendUDPResponse sends a DNS response via UDP.
// Go 1.26: Extracted UDP-specific sending logic.
func sendUDPResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	// Truncate if response is too large for UDP
	if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
		truncated, err := TruncatedResponse(response)
		if err != nil {
			dlog.Warnf("Failed to truncate UDP response: %v", err)
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return
		}
		response = truncated
	}

	// Send via UDP
	packetConn, ok := clientPc.(net.PacketConn)
	if !ok {
		dlog.Error("Client connection is not a PacketConn for UDP protocol")
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}

	if _, err := packetConn.WriteTo(response, *clientAddr); err != nil {
		dlog.Warnf("Failed to send UDP response: %v", err)
		return
	}

	// Update size estimator
	if HasTCFlag(response) {
		proxy.questionSizeEstimator.blindAdjust()
	} else {
		proxy.questionSizeEstimator.adjust(ResponseOverhead + len(response))
	}
}

// sendTCPResponse sends a DNS response via TCP.
// Go 1.26: Extracted TCP-specific sending logic.
func sendTCPResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientPc net.Conn,
) {
	// Prefix with length for TCP
	prefixedResponse, err := PrefixWithSize(response)
	if err != nil {
		dlog.Warnf("Failed to prefix TCP response: %v", err)
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}

	// Send via TCP
	if clientPc != nil {
		if _, err := clientPc.Write(prefixedResponse); err != nil {
			dlog.Warnf("Failed to send TCP response: %v", err)
		}
	}
}

// updateMonitoringMetrics updates monitoring metrics if enabled.
// Go 1.26: Better nil checks and error logging.
func updateMonitoringMetrics(
	proxy *Proxy,
	pluginsState *PluginsState,
) {
	// Check if monitoring is enabled
	if !proxy.monitoringUI.Enabled {
		return
	}

	// Validate monitoring instance
	if proxy.monitoringInstance == nil {
		dlog.Debug("Monitoring is enabled but monitoringInstance is nil")
		return
	}

	// Validate question message
	if pluginsState.questionMsg == nil {
		dlog.Debug("Question message is nil, cannot update metrics")
		return
	}

	// Update metrics
	proxy.monitoringInstance.UpdateMetrics(*pluginsState, pluginsState.questionMsg)
}
