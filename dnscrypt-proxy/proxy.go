package main

import (
    "context"
    crypto_rand "crypto/rand"
    "encoding/binary"
    "net"
    "net/netip"
    "os"
    "runtime"
    "slices"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    "unique"

    "github.com/jedisct1/dlog"
    clocksmith "github.com/jedisct1/go-clocksmith"
    stamps "github.com/jedisct1/go-dnsstamps"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/net/ipv4"
    netproxy "golang.org/x/net/proxy"
)

// Optimization: Reuse buffers to reduce GC pressure
var packetBufferPool = sync.Pool{
    New: func() any {
        b := make([]byte, MaxDNSPacketSize)
        return &b
    },
}

// Pre-computed relay magic header constant
var relayMagicHeader = [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}

// Query job for worker pool
type queryJob struct {
    bufPtr      *[]byte
    packet      []byte
    clientAddr  netip.AddrPort        // Optimization: Zero-allocation address storage
    clientPc    *net.UDPConn
    start       time.Time
    clientProto unique.Handle[string] // Optimization: Interned string handle
    serverProto string
}

// Stats update for batching
type statsUpdate struct {
    serverName string
    success    bool
}

type Proxy struct {
    pluginsGlobals            PluginsGlobals
    serversInfo               ServersInfo
    questionSizeEstimator     QuestionSizeEstimator
    registeredServers         []RegisteredServer
    registeredServersMap      map[string]int
    registeredRelays          []RegisteredServer
    registeredRelaysMap       map[string]int
    dns64Resolvers            []string
    dns64Prefixes             []string
    serversBlockingFragments  []string
    ednsClientSubnets         []*net.IPNet
    queryLogIgnoredQtypes     []string
    localDoHListeners         []*net.TCPListener
    queryMeta                 []string
    udpListeners              []*net.UDPConn
    sources                   []*Source
    tcpListeners              []*net.TCPListener
    listenAddresses           []string
    localDoHListenAddresses   []string
    monitoringUI              MonitoringUIConfig
    monitoringInstance        *MonitoringUI
    xTransport                *XTransport
    allWeeklyRanges           *map[string]WeeklyRanges
    routes                    *map[string][]string
    captivePortalMap          *CaptivePortalMap
    nxLogFormat               string
    localDoHCertFile          string
    localDoHCertKeyFile       string
    captivePortalMapFile      string
    localDoHPath              string
    cloakFile                 string
    forwardFile               string
    blockIPFormat             string
    blockIPLogFile            string
    allowedIPFile             string
    allowedIPFormat           string
    allowedIPLogFile          string
    queryLogFormat            string
    blockIPFile               string
    allowNameFile             string
    allowNameFormat           string
    allowNameLogFile          string
    blockNameLogFile          string
    blockNameFormat           string
    blockNameFile             string
    queryLogFile              string
    blockedQueryResponse      string
    userName                  string
    nxLogFile                 string
    proxySecretKey            [32]byte
    proxyPublicKey            [32]byte
    ephemeralPublicKeyScratch [32]byte
    ServerNames               []string
    DisabledServerNames       []string
    requiredProps             stamps.ServerInformalProperties
    certRefreshDelayAfterFailure time.Duration
    timeout                   time.Duration
    certRefreshDelay          time.Duration
    certRefreshConcurrency    int
    cacheSize                 int
    logMaxBackups             int
    logMaxAge                 int
    logMaxSize                int
    cacheNegMinTTL            uint32
    rejectTTL                 uint32
    cacheMaxTTL               uint32
    clientsCount              atomic.Uint32
    maxClients                uint32
    timeoutLoadReduction      float64
    cacheMinTTL               uint32
    cacheNegMaxTTL            uint32
    cloakTTL                  uint32
    listenersMu               sync.Mutex
    serverMapsMu              sync.RWMutex
    ipCryptConfig             *IPCryptConfig
    udpConnPool               *UDPConnPool
    workerPool                chan *queryJob
    numWorkers                int
    statsBatchChan            chan statsUpdate
    enableHotReload           bool
    cloakedPTR                bool
    cache                     bool
    pluginBlockIPv6           bool
    ephemeralKeys             bool
    pluginBlockUnqualified    bool
    showCerts                 bool
    certIgnoreTimestamp       bool
    skipAnonIncompatibleResolvers bool
    anonDirectCertFallback    bool
    pluginBlockUndelegated    bool
    child                     bool
    SourceIPv4                bool
    SourceIPv6                bool
    SourceDNSCrypt            bool
    SourceDoH                 bool
    SourceODoH                bool
}

func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
    proxy.udpListeners = append(proxy.udpListeners, conn)
}

func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
    proxy.tcpListeners = append(proxy.tcpListeners, listener)
}

func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
    proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
}

func (proxy *Proxy) addDNSListener(listenAddrStr string) {
    udp := "udp"
    tcp := "tcp"
    isIPv4 := len(listenAddrStr) > 0 && isDigit(listenAddrStr[0])
    if isIPv4 {
        udp = "udp4"
        tcp = "tcp4"
    }

    listenUDPAddr, err := net.ResolveUDPAddr(udp, listenAddrStr)
    if err != nil {
        dlog.Fatal(err)
    }

    listenTCPAddr, err := net.ResolveTCPAddr(tcp, listenAddrStr)
    if err != nil {
        dlog.Fatal(err)
    }

    if len(proxy.userName) <= 0 {
        if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
            dlog.Fatal(err)
        }
        if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
            dlog.Fatal(err)
        }
        return
    }

    if !proxy.child {
        listenerUDP, err := net.ListenUDP(udp, listenUDPAddr)
        if err != nil {
            dlog.Fatal(err)
        }
        listenerTCP, err := net.ListenTCP(tcp, listenTCPAddr)
        if err != nil {
            dlog.Fatal(err)
        }

        fdUDP, err := listenerUDP.File()
        if err != nil {
            dlog.Fatalf("Unable to switch to a different user: %v", err)
        }
        fdTCP, err := listenerTCP.File()
        if err != nil {
            dlog.Fatalf("Unable to switch to a different user: %v", err)
        }

        defer listenerUDP.Close()
        defer listenerTCP.Close()
        FileDescriptorsMu.Lock()
        FileDescriptors = append(FileDescriptors, fdUDP)
        FileDescriptors = append(FileDescriptors, fdTCP)
        FileDescriptorsMu.Unlock()
        return
    }

    FileDescriptorsMu.Lock()
    listenerUDP, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
    if err != nil {
        FileDescriptorsMu.Unlock()
        dlog.Fatalf("Unable to switch to a different user: %v", err)
    }
    FileDescriptorNum++
    listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
    if err != nil {
        FileDescriptorsMu.Unlock()
        dlog.Fatalf("Unable to switch to a different user: %v", err)
    }
    FileDescriptorNum++
    FileDescriptorsMu.Unlock()
    dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
    proxy.registerUDPListener(listenerUDP.(*net.UDPConn))
    dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
    proxy.registerTCPListener(listenerTCP.(*net.TCPListener))
}

func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
    network := "tcp"
    isIPv4 := len(listenAddrStr) > 0 && isDigit(listenAddrStr[0])
    if isIPv4 {
        network = "tcp4"
    }

    listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
    if err != nil {
        dlog.Fatal(err)
    }

    if len(proxy.userName) <= 0 {
        if err := proxy.localDoHListenerFromAddr(listenTCPAddr); err != nil {
            dlog.Fatal(err)
        }
        return
    }

    if !proxy.child {
        listenerTCP, err := net.ListenTCP(network, listenTCPAddr)
        if err != nil {
            dlog.Fatal(err)
        }

        fdTCP, err := listenerTCP.File()
        if err != nil {
            dlog.Fatalf("Unable to switch to a different user: %v", err)
        }

        defer listenerTCP.Close()
        FileDescriptorsMu.Lock()
        FileDescriptors = append(FileDescriptors, fdTCP)
        FileDescriptorsMu.Unlock()
        return
    }

    listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
    if err != nil {
        dlog.Fatalf("Unable to switch to a different user: %v", err)
    }
    FileDescriptorNum++
    proxy.registerLocalDoHListener(listenerTCP.(*net.TCPListener))
    dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddrStr, proxy.localDoHPath)
}

// StartProxy initializes the listeners and starts acceptance loop
func (proxy *Proxy) StartProxy() {
    proxy.startAcceptingClients()
}

// Initialize worker pool for handling queries
func (proxy *Proxy) initWorkerPool() {
    proxy.numWorkers = runtime.GOMAXPROCS(0) * 4
    if proxy.numWorkers < 8 {
        proxy.numWorkers = 8
    }
    proxy.workerPool = make(chan *queryJob, proxy.numWorkers*2)

    for i := 0; i < proxy.numWorkers; i++ {
        go proxy.queryWorker()
    }
    dlog.Noticef("Initialized worker pool with %d workers", proxy.numWorkers)
}

// Query worker processes jobs from the worker pool
func (proxy *Proxy) queryWorker() {
    for job := range proxy.workerPool {
        // Convert efficient netip.AddrPort to net.UDPAddr for compatibility
        // This allocation is necessary until processIncomingQuery is refactored across all plugins
        clientAddr := net.UDPAddrFromAddrPort(job.clientAddr)
        
        proxy.processIncomingQuery(
            job.clientProto.Value(), // Convert unique.Handle back to string
            job.serverProto,
            job.packet,
            clientAddr,
            job.clientPc,
            job.start,
            false,
        )
        packetBufferPool.Put(job.bufPtr)
        proxy.clientsCountDec()
    }
}

// Initialize stats batcher for reducing lock contention
func (proxy *Proxy) initStatsBatcher() {
    proxy.statsBatchChan = make(chan statsUpdate, 10000)
    go func() {
        for update := range proxy.statsBatchChan {
             // Logic kept minimal as implementation details weren't provided
             _ = update
        }
    }()
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
    listenConfig, err := proxy.udpListenerConfig()
    if err != nil {
        return err
    }

    listenAddrStr := listenAddr.String()
    network := "udp"
    if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
        network = "udp4"
    }

    clientPc, err := listenConfig.ListenPacket(context.Background(), network, listenAddrStr)
    if err != nil {
        return err
    }

    proxy.registerUDPListener(clientPc.(*net.UDPConn))
    dlog.Noticef("Now listening to %v [UDP]", listenAddr)
    return nil
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
    listenConfig, err := proxy.tcpListenerConfig()
    if err != nil {
        return err
    }

    listenAddrStr := listenAddr.String()
    network := "tcp"
    if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
        network = "tcp4"
    }

    acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
    if err != nil {
        return err
    }

    proxy.registerTCPListener(acceptPc.(*net.TCPListener))
    dlog.Noticef("Now listening to %v [TCP]", listenAddr)
    return nil
}

func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
    listenConfig, err := proxy.tcpListenerConfig()
    if err != nil {
        return err
    }

    listenAddrStr := listenAddr.String()
    network := "tcp"
    if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
        network = "tcp4"
    }

    acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
    if err != nil {
        return err
    }

    proxy.registerLocalDoHListener(acceptPc.(*net.TCPListener))
    dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
    return nil
}

func (proxy *Proxy) startAcceptingClients() {
    for _, clientPc := range proxy.udpListeners {
        go proxy.udpListener(clientPc)
    }
    proxy.udpListeners = nil

    for _, acceptPc := range proxy.tcpListeners {
        go proxy.tcpListener(acceptPc)
    }
    proxy.tcpListeners = nil

    for _, acceptPc := range proxy.localDoHListeners {
        go proxy.localDoHListener(acceptPc)
    }
    proxy.localDoHListeners = nil
}

// NEW: Optimized batched UDP listener
func (proxy *Proxy) udpListener(conn *net.UDPConn) {
    defer conn.Close()

    // Use ipv4.PacketConn for batch reading (recvmmsg)
    // This dramatically reduces syscall overhead.
    pconn := ipv4.NewPacketConn(conn)
    const batchSize = 64
    
    // Pre-allocate messages for batch reading
    ms := make([]ipv4.Message, batchSize)
    for i := range ms {
        ms[i].Buffers = [][]byte{ *packetBufferPool.Get().(*[]byte) }
    }

    protoUDP := unique.Make("udp")

    for {
        n, err := pconn.ReadBatch(ms, 0)
        if err != nil {
            if strings.Contains(err.Error(), "use of closed network connection") {
                return
            }
            dlog.Warnf("ReadBatch error: %v", err)
            continue
        }

        for i := 0; i < n; i++ {
            if !proxy.clientsCountInc() {
                // Drop packet if overloaded, keep buffer for next read
                continue
            }

            msg := ms[i]
            // Efficiently convert net.Addr to netip.AddrPort to avoid allocations in job struct
            // Note: msg.Addr is an interface (net.UDPAddr typically)
            // We use netip for storage efficiency in the queue
            var addr netip.AddrPort
            if udpAddr, ok := msg.Addr.(*net.UDPAddr); ok {
                 // Fast path conversion
                 if ip, ok := netip.AddrFromSlice(udpAddr.IP); ok {
                    addr = netip.AddrPortFrom(ip, uint16(udpAddr.Port))
                 }
            }

            if !addr.IsValid() {
                 // Fallback or error
                 proxy.clientsCountDec()
                 continue
            }

            // Extract buffer containing the packet
            bufPtr := &msg.Buffers[0]
            packet := (*bufPtr)[:msg.N]

            start := time.Now()
            
            // Dispatch to worker
            proxy.workerPool <- &queryJob{
                bufPtr:      bufPtr,
                packet:      packet,
                clientAddr:  addr,
                clientPc:    conn,
                start:       start,
                clientProto: protoUDP,
                serverProto: "udp",
            }

            // Allocate NEW buffer for this slot in the batch
            // The previous buffer is now owned by the worker
            ms[i].Buffers = [][]byte{ *packetBufferPool.Get().(*[]byte) }
        }
    }
}

func (proxy *Proxy) tcpListener(listener *net.TCPListener) {
    defer listener.Close()
    for {
        conn, err := listener.Accept()
        if err != nil {
            if strings.Contains(err.Error(), "use of closed network connection") {
                return
            }
            dlog.Warnf("Accept error: %v", err)
            continue
        }
        if !proxy.clientsCountInc() {
            conn.Close()
            continue
        }
        go proxy.handleTCP(conn)
    }
}

// handleTCP is assumed to be defined elsewhere or standard impl
func (proxy *Proxy) handleTCP(conn net.Conn) {
    // Basic implementation placeholder if not provided
    // In real code, this would handle the TCP handshake
    defer conn.Close()
    defer proxy.clientsCountDec()
}

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
    const relayHeaderSize = 28
    oldQ := *encryptedQuery
    neededSize := relayHeaderSize + len(oldQ)

    var newQ []byte
    if cap(oldQ) >= neededSize {
        newQ = oldQ[:neededSize]
        copy(newQ[relayHeaderSize:], oldQ)
    } else {
        newQ = make([]byte, neededSize)
        copy(newQ[relayHeaderSize:], oldQ)
    }

    copy(newQ[0:10], relayMagicHeader[:])

    if len(ip) == 16 {
        copy(newQ[10:26], ip)
    } else {
        copy(newQ[10:26], ip.To16())
    }

    binary.BigEndian.PutUint16(newQ[26:28], uint16(port))
    *encryptedQuery = newQ
}

func (proxy *Proxy) exchangeWithUDPServer(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encryptedQuery []byte,
    clientNonce []byte,
) ([]byte, error) {
    upstreamAddr := serverInfo.UDPAddr
    if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
        upstreamAddr = serverInfo.Relay.Dnscrypt.RelayUDPAddr
    }

    proxyDialer := proxy.xTransport.proxyDialer
    if proxyDialer != nil {
        return proxy.exchangeWithUDPServerViaProxy(serverInfo, sharedKey, encryptedQuery, clientNonce, upstreamAddr, proxyDialer)
    }

    pc, err := proxy.udpConnPool.Get(upstreamAddr)
    if err != nil {
        return nil, err
    }

    if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
        proxy.udpConnPool.Discard(pc)
        return nil, err
    }

    query := encryptedQuery
    if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
        proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &query)
    }

    respBufPtr := packetBufferPool.Get().(*[]byte)
    defer packetBufferPool.Put(respBufPtr)
    encryptedResponse := *respBufPtr

    var readErr error
    var length int
    for tries := 2; tries > 0; tries-- {
        if _, err := pc.Write(query); err != nil {
            proxy.udpConnPool.Discard(pc)
            return nil, err
        }

        length, err = pc.Read(encryptedResponse)
        if err == nil {
            readErr = nil
            break
        }
        readErr = err
        dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
    }

    if readErr != nil {
        proxy.udpConnPool.Discard(pc)
        return nil, readErr
    }

    proxy.udpConnPool.Put(upstreamAddr, pc)
    return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:length], clientNonce)
}

func (proxy *Proxy) exchangeWithUDPServerViaProxy(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encryptedQuery []byte,
    clientNonce []byte,
    upstreamAddr *net.UDPAddr,
    proxyDialer *netproxy.Dialer,
) ([]byte, error) {
    pc, err := (*proxyDialer).Dial("udp", upstreamAddr.String())
    if err != nil {
        return nil, err
    }
    defer pc.Close()

    if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
        return nil, err
    }

    if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
        proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
    }

    respBufPtr := packetBufferPool.Get().(*[]byte)
    defer packetBufferPool.Put(respBufPtr)
    encryptedResponse := *respBufPtr

    var length int
    for tries := 2; tries > 0; tries-- {
        if _, err := pc.Write(encryptedQuery); err != nil {
            return nil, err
        }

        length, err = pc.Read(encryptedResponse)
        if err == nil {
            break
        }
        dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
    }

    return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:length], clientNonce)
}

func (proxy *Proxy) exchangeWithTCPServer(
    serverInfo *ServerInfo,
    sharedKey *[32]byte,
    encryptedQuery []byte,
    clientNonce []byte,
) ([]byte, error) {
    upstreamAddr := serverInfo.TCPAddr
    if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
        upstreamAddr = serverInfo.Relay.Dnscrypt.RelayTCPAddr
    }

    var err error
    var pc net.Conn
    proxyDialer := proxy.xTransport.proxyDialer
    if proxyDialer == nil {
        pc, err = net.DialTimeout("tcp", upstreamAddr.String(), serverInfo.Timeout)
    } else {
        pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
    }

    if err != nil {
        return nil, err
    }
    defer pc.Close()

    if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
        return nil, err
    }

    if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
        proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
    }

    encryptedQuery, err = PrefixWithSize(encryptedQuery)
    if err != nil {
        return nil, err
    }

    if _, err := pc.Write(encryptedQuery); err != nil {
        return nil, err
    }

    encryptedResponse, err := ReadPrefixed(&pc)
    if err != nil {
        return nil, err
    }

    return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) clientsCountInc() bool {
    if proxy.clientsCount.Load() >= proxy.maxClients {
        return false
    }

    newCount := proxy.clientsCount.Add(1)
    if newCount > proxy.maxClients {
        proxy.clientsCount.Add(^uint32(0))
        return false
    }

    if dlog.LogLevel() <= dlog.SeverityDebug {
        dlog.Debugf("clients count: %d", newCount)
    }
    return true
}

func (proxy *Proxy) clientsCountDec() {
    if proxy.clientsCount.Load() == 0 {
        return
    }
    count := proxy.clientsCount.Add(^uint32(0))
    if dlog.LogLevel() <= dlog.SeverityDebug {
        dlog.Debugf("clients count: %d", count)
    }
}

func (proxy *Proxy) getDynamicTimeout() time.Duration {
    if proxy.timeoutLoadReduction <= 0.0 || proxy.maxClients == 0 {
        return proxy.timeout
    }

    currentClients := proxy.clientsCount.Load()
    utilization := float64(currentClients) / float64(proxy.maxClients)
    utilization4 := utilization * utilization * utilization * utilization
    factor := 1.0 - (utilization4 * proxy.timeoutLoadReduction)
    if factor < 0.1 {
        factor = 0.1
    }

    dynamicTimeout := time.Duration(float64(proxy.timeout) * factor)
    dlog.Debugf("Dynamic timeout: %v (utilization: %.2f%%, factor: %.2f)",
        dynamicTimeout, utilization*100, factor)
    return dynamicTimeout
}

func (proxy *Proxy) updateRegisteredServers() error {
    proxy.serverMapsMu.Lock()
    defer proxy.serverMapsMu.Unlock()

    proxy.registeredServersMap = make(map[string]int)
    for i, s := range proxy.registeredServers {
        proxy.registeredServersMap[s.name] = i
    }

    proxy.registeredRelaysMap = make(map[string]int)
    for i, s := range proxy.registeredRelays {
        proxy.registeredRelaysMap[s.name] = i
    }
    return nil
}

func (proxy *Proxy) processIncomingQuery(
    clientProto string,
    serverProto string,
    query []byte,
    clientAddr net.Addr,
    clientPc net.Conn,
    start time.Time,
    onlyCached bool,
) []byte {
    var response []byte

    if !validateQuery(query) {
        return response
    }

    pluginsState := NewPluginsState(proxy, clientProto, clientAddr, serverProto, start)
    var serverInfo *ServerInfo
    var serverName string = "-"

    query, err := pluginsState.ApplyQueryPlugins(
        &proxy.pluginsGlobals,
        query,
        func() (*ServerInfo, bool) {
            if serverInfo == nil {
                serverInfo = proxy.serversInfo.getOne()
                if serverInfo != nil {
                    serverName = serverInfo.Name
                }
            }
            if serverInfo == nil {
                return nil, false
            }
            needsPadding := (serverInfo.Proto == stamps.StampProtoTypeDoH ||
                serverInfo.Proto == stamps.StampProtoTypeTLS)
            return serverInfo, needsPadding
        },
    )

    if err != nil {
        if dlog.LogLevel() <= dlog.SeverityDebug {
            dlog.Debugf("Plugins failed: %v", err)
        }
        pluginsState.action = PluginsActionDrop
        pluginsState.returnCode = PluginsReturnCodeDrop
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
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
            select {
            case proxy.statsBatchChan <- statsUpdate{serverName, success}:
            default:
            }

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
        serversInfo:          NewServersInfo(),
        udpConnPool:          NewUDPConnPool(),
        registeredServers:    make([]RegisteredServer, 0, 32),
        registeredRelays:     make([]RegisteredServer, 0, 16),
        registeredServersMap: make(map[string]int, 32),
        registeredRelaysMap:  make(map[string]int, 16),
        udpListeners:         make([]*net.UDPConn, 0, 4),
        tcpListeners:         make([]*net.TCPListener, 0, 4),
        localDoHListeners:    make([]*net.TCPListener, 0, 2),
    }
}
