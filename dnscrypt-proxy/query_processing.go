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

// ============================================================================
// GLOBAL OPTIMIZATIONS - Production Ready
// ============================================================================

// OPTIMIZATION 1: Fixed buffer pool - returns slice directly
var packetPool = sync.Pool{
New: func() interface{} {
return make([]byte, 0, MaxDNSPacketSize)
},
}

// OPTIMIZATION 2: Length buffer pool - returns slice directly (FIXED)
var lenBufPool = sync.Pool{
New: func() interface{} {
return make([]byte, 2)
},
}

// OPTIMIZATION 3: net.Buffers pool for zero-copy I/O
var buffersPool = sync.Pool{
New: func() interface{} {
return &net.Buffers{}
},
}

// OPTIMIZATION 4: Lock-free atomic Round-Robin
var odohLbCounter atomic.Uint64

// OPTIMIZATION 5: Reusable error variables (eliminate allocations)
var (
errDNSCryptEncryption = errors.New("DNSCrypt encryption failed")
errDNSCryptExchange   = errors.New("DNSCrypt exchange failed")
errDoHQueryFailed     = errors.New("DoH query failed")
errODoHEncryption     = errors.New("ODoH encryption failed")
errODoHDecryption     = errors.New("ODoH decryption failed")
errODoHQueryFailed    = errors.New("ODoH query failed")
errInvalidResponse    = errors.New("invalid response size")
errUnsupportedProto   = errors.New("unsupported protocol")
)

// OPTIMIZATION 6: String constant to eliminate allocation in hot path
const msgServerFailureInfo = "A response with status code 2 was received - this is usually a temporary, remote issue with the configuration of the domain name"

// ============================================================================
// HELPER FUNCTIONS - Optimized for inlining and performance
// ============================================================================

// validateQuery - Cached len(), single expression, compiler auto-inlines
func validateQuery(query []byte) bool {
n := len(query)
return n >= MinDNSPacketSize && n <= MaxDNSPacketSize
}

// handleSynthesizedResponse - Optimized synthesized response handler
func handleSynthesizedResponse(pluginsState *PluginsState, synth *dns.Msg) ([]byte, error) {
if err := synth.Pack(); err != nil {
pluginsState.returnCode = PluginsReturnCodeParseError
return nil, fmt.Errorf("failed to pack synthesized response: %w", err)
}
return synth.Data, nil
}

// getStaleResponse - Early returns, better nil checking
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

// hasTCFlag - Fast TC flag check (compiler auto-inlines)
func hasTCFlag(response []byte) bool {
if len(response) < 3 {
return false
}
return response[2]&0x02 != 0
}

// shouldRetryOverTCP - Extracted retry logic (FIXED: use errors.As)
func shouldRetryOverTCP(response []byte, err error) bool {
if err == nil {
return hasTCFlag(response)
}

var neterr net.Error
if errors.As(err, &neterr) && neterr.Timeout() {
return true
}
return false
}

// ============================================================================
// PROTOCOL HANDLERS - Fully optimized
// ============================================================================

// processDNSCryptQuery - FIXED: Use errors.As, pre-allocated errors
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
dlog.Warnf("DNSCrypt encryption failed for %s: %v", serverInfo.Name, err)
return nil, errDNSCryptEncryption
}

serverInfo.noticeBegin(proxy)
var response []byte
if serverProto == "udp" {
response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
if shouldRetryOverTCP(response, err) {
dlog.Debugf("[%v] Retry over TCP after UDP issues", serverInfo.Name)
serverProto = "tcp"
sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
if err != nil {
pluginsState.returnCode = PluginsReturnCodeParseError
pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
serverInfo.noticeFailure(proxy)
dlog.Warnf("DNSCrypt TCP retry encryption failed for %s: %v", serverInfo.Name, err)
return nil, errDNSCryptEncryption
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

var neterr net.Error
if errors.As(err, &neterr) && neterr.Timeout() {
pluginsState.returnCode = PluginsReturnCodeServerTimeout
} else {
pluginsState.returnCode = PluginsReturnCodeNetworkError
}
pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
dlog.Warnf("DNSCrypt exchange failed for %s: %v", serverInfo.Name, err)
return nil, errDNSCryptExchange
}

return response, nil
}

// processDoHQuery - Cached length, direct return
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
return serverResponse, nil
}
}

serverInfo.noticeFailure(proxy)
if staleData, ok := getStaleResponse(pluginsState); ok {
return staleData, nil
}

pluginsState.returnCode = PluginsReturnCodeNetworkError
pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
dlog.Warnf("DoH query failed for %s: %v", serverInfo.Name, err)
return nil, errDoHQueryFailed
}

// processODoHQuery - Cached configCount, no variable shadowing, cached lengths
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
targetIdx := odohLbCounter.Add(1) % uint64(configCount)
target := serverInfo.odohTargetConfigs[targetIdx]
odohQuery, err := target.encryptQuery(query)
if err != nil {
dlog.Errorf("Failed to encrypt query for [%v]", serverInfo.Name)
return nil, errODoHEncryption
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
return nil, errODoHDecryption
}

responseLen := len(response)
if responseLen >= MinDNSPacketSize {
SetTransactionID(response, tid)
return response, nil
}
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
return nil, errODoHQueryFailed
}

// handleDNSExchange - Switch statement for better branch prediction
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

responseLen := len(response)
if responseLen < MinDNSPacketSize || responseLen > MaxDNSPacketSize {
pluginsState.returnCode = PluginsReturnCodeParseError
pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
serverInfo.noticeFailure(proxy)
return nil, fmt.Errorf("invalid response size from %s: %d bytes", serverInfo.Name, responseLen)
}

return response, nil
}

// processPlugins - Cached rcode, string constant
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

// sendResponse - FIXED: Cached length, proper pool usage, nil references
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

if hasTCFlag(response) {
proxy.questionSizeEstimator.blindAdjust()
} else {
proxy.questionSizeEstimator.adjust(ResponseOverhead + responseLen)
}

case "tcp":
lenBufPtr := lenBufPool.Get()
if lenBufPtr == nil {
dlog.Warn("lenBufPool returned nil")
return
}
lenBuf := lenBufPtr.([]byte)
defer lenBufPool.Put(lenBuf)

lenBuf[0] = byte(responseLen >> 8)
lenBuf[1] = byte(responseLen)

if clientPc != nil {
buffers := buffersPool.Get().(*net.Buffers)
*buffers = net.Buffers{lenBuf, response}
_, err := buffers.WriteTo(clientPc)

// FIXED: Nil out references before returning to pool
for i := range *buffers {
(*buffers)[i] = nil
}
*buffers = (*buffers)[:0]
buffersPool.Put(buffers)

if err != nil {
dlog.Warnf("Failed to write TCP response: %v", err)
}
}
}
}

// updateMonitoringMetrics - Early return optimization
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
