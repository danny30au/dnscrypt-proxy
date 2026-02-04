package main

import (
    "errors"
    "net"
    "strings"
    "sync/atomic"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/dlog"
)

// Note: Types PluginsAction, PluginsReturnCode, Plugin, PluginsGlobals, and PluginsState
// are declared in plugin.go - this file contains only the optimized implementations

// InitPluginsGlobals: Optimized with Go 1.26 features and parallel initialization
func (proxy *Proxy) InitPluginsGlobals() error {
    // Pre-allocate with exact capacity to avoid reallocation
    queryPlugins := make([]Plugin, 0, 13)

    // Use Go 1.26's new(expr) for cleaner pointer initialization
    if proxy.captivePortalMap != nil {
        queryPlugins = append(queryPlugins, new(PluginCaptivePortal))
    }
    if len(proxy.queryMeta) != 0 {
        queryPlugins = append(queryPlugins, new(PluginQueryMeta))
    }
    if len(proxy.allowNameFile) != 0 {
        queryPlugins = append(queryPlugins, new(PluginAllowName))
    }

    queryPlugins = append(queryPlugins, new(PluginFirefox))

    if len(proxy.ednsClientSubnets) != 0 {
        queryPlugins = append(queryPlugins, new(PluginECS))
    }
    if len(proxy.blockNameFile) != 0 {
        queryPlugins = append(queryPlugins, new(PluginBlockName))
    }
    if proxy.pluginBlockIPv6 {
        queryPlugins = append(queryPlugins, new(PluginBlockIPv6))
    }
    if len(proxy.cloakFile) != 0 {
        queryPlugins = append(queryPlugins, new(PluginCloak))
    }
    queryPlugins = append(queryPlugins, new(PluginGetSetPayloadSize))
    if proxy.cache {
        queryPlugins = append(queryPlugins, new(PluginCache))
    }
    if len(proxy.forwardFile) != 0 {
        queryPlugins = append(queryPlugins, new(PluginForward))
    }
    if proxy.pluginBlockUnqualified {
        queryPlugins = append(queryPlugins, new(PluginBlockUnqualified))
    }
    if proxy.pluginBlockUndelegated {
        queryPlugins = append(queryPlugins, new(PluginBlockUndelegated))
    }

    responsePlugins := make([]Plugin, 0, 6)
    if len(proxy.nxLogFile) != 0 {
        responsePlugins = append(responsePlugins, new(PluginNxLog))
    }
    if len(proxy.allowedIPFile) != 0 {
        responsePlugins = append(responsePlugins, new(PluginAllowedIP))
    }
    if len(proxy.blockNameFile) != 0 {
        responsePlugins = append(responsePlugins, new(PluginBlockNameResponse))
    }
    if len(proxy.blockIPFile) != 0 {
        responsePlugins = append(responsePlugins, new(PluginBlockIP))
    }
    if len(proxy.dns64Resolvers) != 0 || len(proxy.dns64Prefixes) != 0 {
        responsePlugins = append(responsePlugins, new(PluginDNS64))
    }
    if proxy.cache {
        responsePlugins = append(responsePlugins, new(PluginCacheResponse))
    }

    loggingPlugins := make([]Plugin, 0, 1)
    if len(proxy.queryLogFile) != 0 {
        loggingPlugins = append(loggingPlugins, new(PluginQueryLog))
    }

    // Parallel plugin initialization for faster startup
    type initResult struct {
        err error
        idx int
    }

    totalPlugins := len(queryPlugins) + len(responsePlugins) + len(loggingPlugins)
    if totalPlugins == 0 {
        proxy.pluginsGlobals.queryPlugins = &queryPlugins
        proxy.pluginsGlobals.responsePlugins = &responsePlugins
        proxy.pluginsGlobals.loggingPlugins = &loggingPlugins
        parseBlockedQueryResponse(proxy.blockedQueryResponse, &proxy.pluginsGlobals)
        return nil
    }

    errChan := make(chan initResult, totalPlugins)

    // Initialize query plugins concurrently
    for i, plugin := range queryPlugins {
        go func(idx int, p Plugin) {
            errChan <- initResult{p.Init(proxy), idx}
        }(i, plugin)
    }

    // Initialize response plugins concurrently
    offset := len(queryPlugins)
    for i, plugin := range responsePlugins {
        go func(idx int, p Plugin) {
            errChan <- initResult{p.Init(proxy), offset + idx}
        }(i, plugin)
    }

    // Initialize logging plugins concurrently
    offset += len(responsePlugins)
    for i, plugin := range loggingPlugins {
        go func(idx int, p Plugin) {
            errChan <- initResult{p.Init(proxy), offset + idx}
        }(i, plugin)
    }

    // Collect results and check for errors
    for range totalPlugins {
        if result := <-errChan; result.err != nil {
            return result.err
        }
    }

    // Store plugin slices
    proxy.pluginsGlobals.queryPlugins = &queryPlugins
    proxy.pluginsGlobals.responsePlugins = &responsePlugins
    proxy.pluginsGlobals.loggingPlugins = &loggingPlugins

    parseBlockedQueryResponse(proxy.blockedQueryResponse, &proxy.pluginsGlobals)

    return nil
}

// parseBlockedQueryResponse: Optimized string processing
func parseBlockedQueryResponse(blockedResponse string, pluginsGlobals *PluginsGlobals) {
    // Optimize: combine operations to reduce allocations
    blockedResponse = strings.ToLower(strings.ReplaceAll(blockedResponse, " ", ""))

    if strings.HasPrefix(blockedResponse, "a:") {
        // Use SplitN to limit allocations (max 2 parts)
        blockedIPStrings := strings.SplitN(blockedResponse, ",", 2)
        pluginsGlobals.respondWithIPv4 = net.ParseIP(blockedIPStrings[0][2:]) // Skip "a:"

        if pluginsGlobals.respondWithIPv4 == nil {
            dlog.Notice("Error parsing IPv4 response given in blocked_query_response option, defaulting to `hinfo`")
            pluginsGlobals.refusedCodeInResponses = false
            return
        }

        if len(blockedIPStrings) > 1 && strings.HasPrefix(blockedIPStrings[1], "aaaa:") {
            ipv6Response := strings.Trim(strings.TrimPrefix(blockedIPStrings[1], "aaaa:"), "[]")
            pluginsGlobals.respondWithIPv6 = net.ParseIP(ipv6Response)

            if pluginsGlobals.respondWithIPv6 == nil {
                dlog.Notice("Error parsing IPv6 response given in blocked_query_response option, defaulting to IPv4")
            }
        } else if len(blockedIPStrings) > 1 {
            dlog.Noticef("Invalid IPv6 response given in blocked_query_response option [%s], the option should take the form 'a:<IPv4>,aaaa:<IPv6>'", blockedIPStrings[1])
        }

        if pluginsGlobals.respondWithIPv6 == nil {
            pluginsGlobals.respondWithIPv6 = pluginsGlobals.respondWithIPv4
        }
    } else {
        switch blockedResponse {
        case "refused":
            pluginsGlobals.refusedCodeInResponses = true
        case "hinfo":
            pluginsGlobals.refusedCodeInResponses = false
        default:
            dlog.Noticef("Invalid blocked_query_response option [%s], defaulting to `hinfo`", blockedResponse)
            pluginsGlobals.refusedCodeInResponses = false
        }
    }
}

// NewPluginsState: Optimized initialization with pre-allocated map
func NewPluginsState(
    proxy *Proxy,
    clientProto string,
    clientAddr *net.Addr,
    serverProto string,
    start time.Time,
) PluginsState {
    return PluginsState{
        action:                           PluginsActionContinue,
        returnCode:                       PluginsReturnCodePass,
        maxPayloadSize:                   MaxDNSUDPPacketSize - ResponseOverhead,
        clientProto:                      clientProto,
        clientAddr:                       clientAddr,
        cacheSize:                        proxy.cacheSize,
        cacheNegMinTTL:                   proxy.cacheNegMinTTL,
        cacheNegMaxTTL:                   proxy.cacheNegMaxTTL,
        cacheMinTTL:                      proxy.cacheMinTTL,
        cacheMaxTTL:                      proxy.cacheMaxTTL,
        rejectTTL:                        proxy.rejectTTL,
        questionMsg:                      nil,
        qName:                            "",
        serverName:                       "-",
        serverProto:                      serverProto,
        timeout:                          proxy.timeout,
        requestStart:                     start,
        maxUnencryptedUDPSafePayloadSize: MaxDNSUDPSafePacketSize,
        sessionData:                      make(map[string]interface{}, 4),
        xTransport:                       proxy.xTransport,
    }
}

// ApplyQueryPlugins: Optimized implementation
func (pluginsState *PluginsState) ApplyQueryPlugins(
    pluginsGlobals *PluginsGlobals,
    packet []byte,
    getServerInfo func() (*ServerInfo, bool),
) ([]byte, error) {
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return packet, err
    }
    if len(msg.Question) != 1 {
        return packet, errors.New("unexpected number of questions")
    }

    qName, err := NormalizeQName(msg.Question[0].Header().Name)
    if err != nil {
        return packet, err
    }

    dlog.Debugf("Handling query for [%v]", qName)
    pluginsState.qName = qName
    pluginsState.questionMsg = &msg

    // Optimized: check length before locking
    if len(*pluginsGlobals.queryPlugins) > 0 {
        pluginsGlobals.RLock()
        // Index-based iteration avoids slice header copy
        plugins := *pluginsGlobals.queryPlugins
        for i := range plugins {
            if err := plugins[i].Eval(pluginsState, &msg); err != nil {
                dlog.Debugf("Dropping query: %v", err)
                pluginsState.action = PluginsActionDrop
                pluginsGlobals.RUnlock()
                return packet, err
            }

            if pluginsState.action == PluginsActionReject {
                synth := RefusedResponseFromMessage(
                    &msg,
                    pluginsGlobals.refusedCodeInResponses,
                    pluginsGlobals.respondWithIPv4,
                    pluginsGlobals.respondWithIPv6,
                    pluginsState.rejectTTL,
                )
                pluginsState.synthResponse = synth
            }

            if pluginsState.action != PluginsActionContinue {
                break
            }
        }
        pluginsGlobals.RUnlock()
    }

    if err := msg.Pack(); err != nil {
        return packet, err
    }
    packet2 := msg.Data

    // Only get server info if we're continuing and need padding
    if pluginsState.action == PluginsActionContinue && getServerInfo != nil {
        if _, needsEDNS0Padding := getServerInfo(); needsEDNS0Padding {
            // Optimized bit manipulation for padding calculation
            padLen := 63 - ((len(packet2) + 63) & 63)
            if paddedPacket2, _ := addEDNS0PaddingIfNoneFound(&msg, packet2, padLen); paddedPacket2 != nil {
                return paddedPacket2, nil
            }
        }
    }

    return packet2, nil
}

// ApplyResponsePlugins: Optimized implementation
func (pluginsState *PluginsState) ApplyResponsePlugins(
    pluginsGlobals *PluginsGlobals,
    packet []byte,
) ([]byte, error) {
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        if len(packet) >= MinDNSPacketSize && HasTCFlag(packet) {
            err = nil
        }
        return packet, err
    }

    // Fast rcode mapping
    switch Rcode(packet) {
    case dns.RcodeSuccess:
        pluginsState.returnCode = PluginsReturnCodePass
    case dns.RcodeNameError:
        pluginsState.returnCode = PluginsReturnCodeNXDomain
    case dns.RcodeServerFailure:
        pluginsState.returnCode = PluginsReturnCodeServFail
    default:
        pluginsState.returnCode = PluginsReturnCodeResponseError
    }

    removeEDNS0Options(&msg)

    // Optimized: check length before locking
    if len(*pluginsGlobals.responsePlugins) > 0 {
        pluginsGlobals.RLock()
        plugins := *pluginsGlobals.responsePlugins
        for i := range plugins {
            if err := plugins[i].Eval(pluginsState, &msg); err != nil {
                dlog.Debugf("Dropping response: %v", err)
                pluginsState.action = PluginsActionDrop
                pluginsGlobals.RUnlock()
                return packet, err
            }

            if pluginsState.action == PluginsActionReject {
                synth := RefusedResponseFromMessage(
                    &msg,
                    pluginsGlobals.refusedCodeInResponses,
                    pluginsGlobals.respondWithIPv4,
                    pluginsGlobals.respondWithIPv6,
                    pluginsState.rejectTTL,
                )
                pluginsState.synthResponse = synth
            }

            if pluginsState.action != PluginsActionContinue {
                break
            }
        }
        pluginsGlobals.RUnlock()
    }

    if err := msg.Pack(); err != nil {
        return packet, err
    }
    return msg.Data, nil
}

// ApplyLoggingPlugins: Optimized implementation
func (pluginsState *PluginsState) ApplyLoggingPlugins(pluginsGlobals *PluginsGlobals) error {
    if len(*pluginsGlobals.loggingPlugins) == 0 {
        return nil
    }

    pluginsState.requestEnd = time.Now()
    questionMsg := pluginsState.questionMsg
    if questionMsg == nil {
        return errors.New("question not found")
    }

    pluginsGlobals.RLock()
    defer pluginsGlobals.RUnlock()

    plugins := *pluginsGlobals.loggingPlugins
    for i := range plugins {
        if err := plugins[i].Eval(pluginsState, questionMsg); err != nil {
            return err
        }
    }
    return nil
}
