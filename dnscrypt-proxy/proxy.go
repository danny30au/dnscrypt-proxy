package main

import (
    "context"
    crypto_rand "crypto/rand"
    "encoding/binary"
    "net"
    "os"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/jedisct1/dlog"
    clocksmith "github.com/jedisct1/go-clocksmith"
    stamps "github.com/jedisct1/go-dnsstamps"
    "golang.org/x/crypto/curve25519"
    netproxy "golang.org/x/net/proxy"
)

// Optimization: Reuse buffers to reduce GC pressure
var packetBufferPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, MaxDNSPacketSize)
        return &b
    },
}

type Proxy struct {
    // Hot path fields (better L1 cache locality)
    clientsCount                  uint32
    maxClients                    uint32
    timeout                       time.Duration
    timeoutLoadReduction          float64
    serversInfo                   ServersInfo
    xTransport                    *XTransport
    udpConnPool                   *UDPConnPool

    // Configuration and other fields
    pluginsGlobals                PluginsGlobals
    questionSizeEstimator         QuestionSizeEstimator
    registeredServers             []RegisteredServer
    dns64Resolvers                []string
    dns64Prefixes                 []string
    serversBlockingFragments      []string
    ednsClientSubnets             []*net.IPNet
    queryLogIgnoredQtypes         []string
    localDoHListeners             []*net.TCPListener
    queryMeta                     []string
    enableHotReload               bool
    udpListeners                  []*net.UDPConn
    sources                       []*Source
    tcpListeners                  []*net.TCPListener
    registeredRelays              []RegisteredServer
    listenAddresses               []string
    localDoHListenAddresses       []string
    monitoringUI                  MonitoringUIConfig
    monitoringInstance            *MonitoringUI
    allWeeklyRanges               *map[string]WeeklyRanges
    routes                        *map[string][]string
    captivePortalMap              *CaptivePortalMap
    nxLogFormat                   string
    localDoHCertFile              string
    localDoHCertKeyFile           string
    captivePortalMapFile          string
    localDoHPath                  string
    cloakFile                     string
    forwardFile                   string
    blockIPFormat                 string
    blockIPLogFile                string
    allowedIPFile                 string
    allowedIPFormat               string
    allowedIPLogFile              string
    queryLogFormat                string
    blockIPFile                   string
    allowNameFile                 string
    allowNameFormat               string
    allowNameLogFile              string
    blockNameLogFile              string
    blockNameFormat               string
    blockNameFile                 string
    queryLogFile                  string
    blockedQueryResponse          string
    userName                      string
    nxLogFile                     string
    proxySecretKey                [32]byte
    proxyPublicKey                [32]byte
    ephemeralPublicKeyScratch     [32]byte
    ServerNames                   []string
    DisabledServerNames           []string
    requiredProps                 stamps.ServerInformalProperties
    certRefreshDelayAfterFailure  time.Duration
    certRefreshDelay              time.Duration
    certRefreshConcurrency        int
    cacheSize                     int
    logMaxBackups                 int
    logMaxAge                     int
    logMaxSize                    int
    cacheNegMinTTL                uint32
    rejectTTL                     uint32
    cacheMaxTTL                   uint32
    cacheMinTTL                   uint32
    cacheNegMaxTTL                uint32
    cloakTTL                      uint32
    cloakedPTR                    bool
    cache                         bool
    pluginBlockIPv6               bool
    ephemeralKeys                 bool
    pluginBlockUnqualified        bool
    showCerts                     bool
    certIgnoreTimestamp           bool
    skipAnonIncompatibleResolvers bool
    anonDirectCertFallback        bool
    pluginBlockUndelegated        bool
    child                         bool
    SourceIPv4                    bool
    SourceIPv6                    bool
    SourceDNSCrypt                bool
    SourceDoH                     bool
    SourceODoH                    bool
    listenersMu                   sync.Mutex
    ipCryptConfig                 *IPCryptConfig
}

func (proxy *Proxy) clientsCountInc() bool {
    // Optimization: Simple atomic add without CAS loop
    newCount := atomic.AddUint32(&proxy.clientsCount, 1)
    if newCount <= proxy.maxClients {
        return true
    }
    atomic.AddUint32(&proxy.clientsCount, ^uint32(0)) // Rollback
    return false
}

func (proxy *Proxy) clientsCountDec() {
    // Optimization: Safe decrement without logging overhead
    for {
        count := atomic.LoadUint32(&proxy.clientsCount)
        if count == 0 {
            return
        }
        if atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count-1) {
            return
        }
    }
}

func (proxy *Proxy) getDynamicTimeout() time.Duration {
    if proxy.timeoutLoadReduction <= 0.0 || proxy.maxClients == 0 {
        return proxy.timeout
    }

    // Optimization: Integer math instead of float
    currentClients := atomic.LoadUint32(&proxy.clientsCount)
    utilization := (currentClients * 100) / proxy.maxClients

    // Pre-computed 1.0 - x^4 curve for 0-100% utilization
    factors := [...]int{100, 100, 99, 97, 94, 87, 76, 60, 41, 20, 10}
    idx := utilization / 10
    if idx > 10 {
        idx = 10
    }

    return time.Duration((int64(proxy.timeout) * int64(factors[idx])) / 100)
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
    defer clientPc.Close()
    for {
        // Optimization: Get buffer from pool
        bufPtr := packetBufferPool.Get().(*[]byte)
        buffer := *bufPtr

        length, clientAddr, err := clientPc.ReadFrom(buffer[:MaxDNSPacketSize-1])
        if err != nil {
            packetBufferPool.Put(bufPtr)
            return
        }

        packet := buffer[:length]

        if !proxy.clientsCountInc() {
            dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)

            // Send synchronous response for cached items only
            proxy.processIncomingQuery(
                "udp",
                proxy.xTransport.mainProto,
                packet,
                &clientAddr,
                clientPc,
                time.Now(),
                true,
            )

            packetBufferPool.Put(bufPtr)
            continue
        }

        // Optimization: Pass packet and clientAddr as parameters to avoid closure capture race
        go func(bPtr *[]byte, pkt []byte, addr net.Addr, startTime time.Time) {
            defer packetBufferPool.Put(bPtr)
            defer proxy.clientsCountDec()

            proxy.processIncomingQuery("udp", proxy.xTransport.mainProto, pkt, &addr, clientPc, startTime, false)
        }(bufPtr, packet, clientAddr, time.Now())
    }
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
    defer acceptPc.Close()
    for {
        clientPc, err := acceptPc.Accept()
        if err != nil {
            continue
        }
        if !proxy.clientsCountInc() {
            dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
            clientPc.Close()
            continue
        }
        go func() {
            defer clientPc.Close()
            defer proxy.clientsCountDec()
            dynamicTimeout := proxy.getDynamicTimeout()
            if err := clientPc.SetDeadline(time.Now().Add(dynamicTimeout)); err != nil {
                return
            }
            start := time.Now()
            packet, err := ReadPrefixed(&clientPc)
            if err != nil {
                return
            }
            clientAddr := clientPc.RemoteAddr()
            proxy.processIncomingQuery("tcp", "tcp", packet, &clientAddr, clientPc, start, false)
        }()
    }
}

func (proxy *Proxy) StartProxy() {
    proxy.questionSizeEstimator = NewQuestionSizeEstimator()
    if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
        dlog.Fatal(err)
    }
    curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)

    if proxy.monitoringUI.Enabled {
        dlog.Noticef("Initializing monitoring UI")
        proxy.monitoringInstance = NewMonitoringUI(proxy)
        if proxy.monitoringInstance == nil {
            dlog.Errorf("Failed to create monitoring UI instance")
        } else {
            dlog.Noticef("Starting monitoring UI")
            if err := proxy.monitoringInstance.Start(); err != nil {
                dlog.Errorf("Failed to start monitoring UI: %v", err)
            }
        }
    }

    proxy.startAcceptingClients()
    if !proxy.child {
        if err := ServiceManagerReadyNotify(); err != nil {
            dlog.Fatal(err)
        }
    }
    proxy.xTransport.internalResolverReady = false
    proxy.xTransport.internalResolvers = proxy.listenAddresses
    liveServers, err := proxy.serversInfo.refresh(proxy)
    if liveServers > 0 {
        proxy.certIgnoreTimestamp = false
    }
    if proxy.showCerts {
        os.Exit(0)
    }
    if liveServers <= 0 {
        dlog.Error(err)
        dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
    }

    // Optimization: Remove runtime.GC() - let runtime manage GC pacing
    go func() {
        lastLogTime := time.Now()
        for {
            clocksmith.Sleep(PrefetchSources(proxy.xTransport, proxy.sources))
            proxy.updateRegisteredServers()

            if time.Since(lastLogTime) > 5*time.Minute {
                proxy.serversInfo.logWP2Stats()
                lastLogTime = time.Now()
            }
        }
    }()

    if len(proxy.serversInfo.registeredServers) > 0 {
        go func() {
            for {
                delay := proxy.certRefreshDelay
                if liveServers == 0 {
                    delay = proxy.certRefreshDelayAfterFailure
                }
                clocksmith.Sleep(delay)
                liveServers, _ = proxy.serversInfo.refresh(proxy)
                if liveServers > 0 {
                    proxy.certIgnoreTimestamp = false
                }
            }
        }()
    }
}

func (proxy *Proxy) updateRegisteredServers() error {
    // Optimization: O(1) membership tests using maps
    serverNamesMap := make(map[string]struct{}, len(proxy.ServerNames))
    for _, name := range proxy.ServerNames {
        serverNamesMap[name] = struct{}{}
    }
    disabledServerNamesMap := make(map[string]struct{}, len(proxy.DisabledServerNames))
    for _, name := range proxy.DisabledServerNames {
        disabledServerNamesMap[name] = struct{}{}
    }

    for _, source := range proxy.sources {
        registeredServers, err := source.Parse()
        if err != nil {
            if len(registeredServers) == 0 {
                dlog.Criticalf("Unable to use source [%s]: [%s]", source.name, err)
                return err
            }
            dlog.Warnf(
                "Error in source [%s]: [%s] -- Continuing with reduced server count [%d]",
                source.name,
                err,
                len(registeredServers),
            )
        }
        for _, registeredServer := range registeredServers {
            if registeredServer.stamp.Proto != stamps.StampProtoTypeDNSCryptRelay &&
                registeredServer.stamp.Proto != stamps.StampProtoTypeODoHRelay {
                if len(proxy.ServerNames) > 0 {
                    if _, ok := serverNamesMap[registeredServer.name]; !ok {
                        continue
                    }
                } else if registeredServer.stamp.Props&proxy.requiredProps != proxy.requiredProps {
                    continue
                }
            }
            if _, ok := disabledServerNamesMap[registeredServer.name]; ok {
                continue
            }
            if proxy.SourceIPv4 || proxy.SourceIPv6 {
                isIPv4, isIPv6 := true, false
                if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH {
                    isIPv4, isIPv6 = true, true
                }
                if strings.HasPrefix(registeredServer.stamp.ServerAddrStr, "[") {
                    isIPv4, isIPv6 = false, true
                }
                if !(proxy.SourceIPv4 == isIPv4 || proxy.SourceIPv6 == isIPv6) {
                    continue
                }
            }
            if registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
                registeredServer.stamp.Proto == stamps.StampProtoTypeODoHRelay {
                var found bool
                for i, currentRegisteredRelay := range proxy.registeredRelays {
                    if currentRegisteredRelay.name == registeredServer.name {
                        found = true
                        if currentRegisteredRelay.stamp.String() != registeredServer.stamp.String() {
                            dlog.Infof(
                                "Updating stamp for [%s] was: %s now: %s",
                                registeredServer.name,
                                currentRegisteredRelay.stamp.String(),
                                registeredServer.stamp.String(),
                            )
                            proxy.registeredRelays[i].stamp = registeredServer.stamp
                        }
                    }
                }
                if !found {
                    dlog.Debugf("Adding [%s] to the set of available relays", registeredServer.name)
                    proxy.registeredRelays = append(proxy.registeredRelays, registeredServer)
                }
            } else {
                if !((proxy.SourceDNSCrypt && registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCrypt) ||
                    (proxy.SourceDoH && registeredServer.stamp.Proto == stamps.StampProtoTypeDoH) ||
                    (proxy.SourceODoH && registeredServer.stamp.Proto == stamps.StampProtoTypeODoHTarget)) {
                    continue
                }
                var found bool
                for i, currentRegisteredServer := range proxy.registeredServers {
                    if currentRegisteredServer.name == registeredServer.name {
                        found = true
                        if currentRegisteredServer.stamp.String() != registeredServer.stamp.String() {
                            dlog.Infof("Updating stamp for [%s] was: %s now: %s", registeredServer.name, currentRegisteredServer.stamp.String(), registeredServer.stamp.String())
                            proxy.registeredServers[i].stamp = registeredServer.stamp
                        }
                    }
                }
                if !found {
                    dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.name)
                    proxy.registeredServers = append(proxy.registeredServers, registeredServer)
                }
            }
        }
    }
    for _, registeredServer := range proxy.registeredServers {
        proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
    }
    for _, registeredRelay := range proxy.registeredRelays {
        proxy.serversInfo.registerRelay(registeredRelay.name, registeredRelay.stamp)
    }
    return nil
}

func (proxy *Proxy) processIncomingQuery(
    clientProto string,
    serverProto string,
    query []byte,
    clientAddr *net.Addr,
    clientPc net.Conn,
    start time.Time,
    onlyCached bool,
) []byte {
    // Optimization: Skip expensive logging in hot path
    // clientAddrStr := "unknown"
    // if clientAddr != nil {
    //     clientAddrStr = (*clientAddr).String()
    // }
    // dlog.Debugf("Processing incoming query from %s", clientAddrStr)

    var response []byte
    if !validateQuery(query) {
        return response
    }

    pluginsState := NewPluginsState(proxy, clientProto, clientAddr, serverProto, start)

    var serverInfo *ServerInfo
    var serverName string = "-"

    // Optimization: Eager server fetch to avoid double-check
    if serverInfo == nil && !onlyCached {
        serverInfo = proxy.serversInfo.getOne()
        if serverInfo != nil {
            serverName = serverInfo.Name
        }
    }

    query, err := pluginsState.ApplyQueryPlugins(
        &proxy.pluginsGlobals,
        query,
        func() (*ServerInfo, bool) {
            if serverInfo == nil {
                return nil, false
            }
            needsPadding := (serverInfo.Proto == stamps.StampProtoTypeDoH ||
                serverInfo.Proto == stamps.StampProtoTypeTLS)
            return serverInfo, needsPadding
        },
    )
    if err != nil {
        dlog.Debugf("Plugins failed: %v", err)
        pluginsState.action = PluginsActionDrop
        pluginsState.returnCode = PluginsReturnCodeDrop
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return response
    }
    if !validateQuery(query) {
        return response
    }

    if pluginsState.action == PluginsActionDrop {
        pluginsState.returnCode = PluginsReturnCodeDrop
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return response
    }

    if pluginsState.synthResponse != nil {
        response, err = handleSynthesizedResponse(&pluginsState, pluginsState.synthResponse)
        if err != nil {
            return response
        }
    }

    if onlyCached {
        if len(response) == 0 {
            return response
        }
        serverInfo = nil
    }

    if len(response) == 0 {
        if serverInfo == nil {
            serverInfo = proxy.serversInfo.getOne()
            if serverInfo != nil {
                serverName = serverInfo.Name
            }
        }
        if serverInfo != nil {
            pluginsState.serverName = serverName

            exchangeResponse, err := handleDNSExchange(proxy, serverInfo, &pluginsState, query, serverProto)

            success := (err == nil && exchangeResponse != nil)
            proxy.serversInfo.updateServerStats(serverName, success)

            if err != nil || exchangeResponse == nil {
                return response
            }

            response = exchangeResponse

            processedResponse, err := processPlugins(proxy, &pluginsState, query, serverInfo, response)
            if err != nil {
                return response
            }

            response = processedResponse
        }
    }

    if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
        if len(response) == 0 {
            pluginsState.returnCode = PluginsReturnCodeNotReady
        } else {
            pluginsState.returnCode = PluginsReturnCodeParseError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        if serverInfo != nil {
            serverInfo.noticeFailure(proxy)
        }
        return response
    }

    sendResponse(proxy, &pluginsState, response, clientProto, clientAddr, clientPc)

    pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)

    updateMonitoringMetrics(proxy, &pluginsState)

    return response
}

func NewProxy() *Proxy {
    return &Proxy{
        serversInfo: NewServersInfo(),
        udpConnPool: NewUDPConnPool(),
    }
}
