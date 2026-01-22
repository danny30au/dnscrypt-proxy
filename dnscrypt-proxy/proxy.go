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

// Optimized buffer pools with modern Go features
var packetBufferPool = sync.Pool{
New: func() any {
b := make([]byte, MaxDNSPacketSize)
return &b
},
}

var smallBufferPool = sync.Pool{
New: func() any {
b := make([]byte, 512)
return &b
},
}

type Proxy struct {
pluginsGlobals                PluginsGlobals
serversInfo                   ServersInfo
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
xTransport                    *XTransport
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
timeout                       time.Duration
certRefreshDelay              time.Duration
certRefreshConcurrency        int
cacheSize                     int
logMaxBackups                 int
logMaxAge                     int
logMaxSize                    int
cacheNegMinTTL                uint32
rejectTTL                     uint32
cacheMaxTTL                   uint32
clientsCount                  uint32
maxClients                    uint32
timeoutLoadReduction          float64
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
udpConnPool                   *UDPConnPool
}

func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
proxy.listenersMu.Lock()
proxy.udpListeners = append(proxy.udpListeners, conn)
proxy.listenersMu.Unlock()
}

func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
proxy.listenersMu.Lock()
proxy.tcpListeners = append(proxy.tcpListeners, listener)
proxy.listenersMu.Unlock()
}

func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
proxy.listenersMu.Lock()
proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
proxy.listenersMu.Unlock()
}

func getNetworkType(listenAddrStr string) (udp, tcp string) {
if len(listenAddrStr) > 0 && listenAddrStr[0] >= '0' && listenAddrStr[0] <= '9' {
return "udp4", "tcp4"
}
return "udp", "tcp"
}

func (proxy *Proxy) addDNSListener(listenAddrStr string) {
udp, tcp := getNetworkType(listenAddrStr)
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
} else {
dlog.Noticef("Monitoring UI started successfully")
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

go func() {
lastLogTime := time.Now()
for {
clocksmith.Sleep(PrefetchSources(proxy.xTransport, proxy.sources))
proxy.updateRegisteredServers()

if time.Since(lastLogTime) > 5*time.Minute {
proxy.serversInfo.logWP2Stats()
lastLogTime = time.Now()
}

runtime.GC()
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
runtime.GC()
}
}()
}
}

func (proxy *Proxy) updateRegisteredServers() error {
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
if !includesName(proxy.ServerNames, registeredServer.name) {
continue
}
} else if registeredServer.stamp.Props&proxy.requiredProps != proxy.requiredProps {
continue
}
}
if includesName(proxy.DisabledServerNames, registeredServer.name) {
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
dlog.Debugf("Total count of registered relays %v", len(proxy.registeredRelays))
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
dlog.Debugf("Total count of registered servers %v", len(proxy.registeredServers))
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

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
defer clientPc.Close()

var clientAddr net.UDPAddr

for {
bufPtr := packetBufferPool.Get().(*[]byte)
buffer := *bufPtr

length, addr, err := clientPc.ReadFromUDP(buffer[:MaxDNSPacketSize-1])
if err != nil {
packetBufferPool.Put(bufPtr)
return
}

clientAddr = *addr
packet := buffer[:length]

if !proxy.clientsCountInc() {
dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())

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

go func(bPtr *[]byte, addr net.Addr) {
defer packetBufferPool.Put(bPtr)
defer proxy.clientsCountDec()

proxy.processIncomingQuery("udp", proxy.xTransport.mainProto, packet, &addr, clientPc, time.Now(), false)
}(bufPtr, &clientAddr)
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
dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())
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

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
const relayHeaderSize = 28
oldQ := *encryptedQuery
neededSize := relayHeaderSize + len(oldQ)

if cap(oldQ) >= neededSize {
newQ := oldQ[:neededSize]
copy(newQ[relayHeaderSize:], oldQ)

binary.LittleEndian.PutUint64(newQ[0:8], 0xFFFFFFFFFFFFFFFF)
binary.BigEndian.PutUint16(newQ[8:10], 0x0000)
copy(newQ[10:26], ip.To16())
binary.BigEndian.PutUint16(newQ[26:28], uint16(port))

*encryptedQuery = newQ
return
}

newQ := make([]byte, neededSize)
binary.LittleEndian.PutUint64(newQ[0:8], 0xFFFFFFFFFFFFFFFF)
binary.BigEndian.PutUint16(newQ[8:10], 0x0000)
copy(newQ[10:26], ip.To16())
binary.BigEndian.PutUint16(newQ[26:28], uint16(port))
copy(newQ[relayHeaderSize:], oldQ)

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
newCount := atomic.AddUint32(&proxy.clientsCount, 1)
if newCount > proxy.maxClients {
atomic.AddUint32(&proxy.clientsCount, ^uint32(0))
return false
}
dlog.Debugf("clients count: %d", newCount)
return true
}

func (proxy *Proxy) clientsCountDec() {
newCount := atomic.AddUint32(&proxy.clientsCount, ^uint32(0))
dlog.Debugf("clients count: %d", newCount)
}

func (proxy *Proxy) getDynamicTimeout() time.Duration {
if proxy.timeoutLoadReduction <= 0.0 || proxy.maxClients == 0 {
return proxy.timeout
}

currentClients := atomic.LoadUint32(&proxy.clientsCount)
utilization := float64(currentClients) / float64(proxy.maxClients)

utilization4 := utilization * utilization * utilization * utilization
factor := 1.0 - (utilization4 * proxy.timeoutLoadReduction)
if factor < 0.1 {
factor = 0.1
}

dynamicTimeout := time.Duration(float64(proxy.timeout) * factor)
dlog.Debugf("Dynamic timeout: %v (utilization: %.2f%%, factor: %.2f)", dynamicTimeout, utilization*100, factor)

return dynamicTimeout
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
clientAddrStr := "unknown"
if clientAddr != nil {
clientAddrStr = (*clientAddr).String()
}
dlog.Debugf("Processing incoming query from %s", clientAddrStr)

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
