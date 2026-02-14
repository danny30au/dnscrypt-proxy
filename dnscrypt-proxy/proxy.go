package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

// Proxy represents the main DNSCrypt proxy server with optimized memory layout for Go 1.26.
// Fields are ordered for optimal cache alignment and minimal padding.
type Proxy struct {
	// Hot path pointers (8 bytes each) - cache line 1
	xTransport         *XTransport
	udpConnPool        *UDPConnPool
	ipCryptConfig      *IPCryptConfig
	monitoringInstance *MonitoringUI

	// Large structs
	pluginsGlobals        PluginsGlobals
	serversInfo           ServersInfo
	questionSizeEstimator QuestionSizeEstimator
	monitoringUI          MonitoringUIConfig
	requiredProps         stamps.ServerInformalProperties

	// Pointers to maps (8 bytes each)
	allWeeklyRanges  *map[string]WeeklyRanges
	routes           *map[string][]string
	captivePortalMap *CaptivePortalMap

	// Atomic counter (8-byte aligned) - Go 1.19+ atomic types
	clientsCount atomic.Uint32

	// Slices (24 bytes each on 64-bit)
	registeredServers        []RegisteredServer
	registeredRelays         []RegisteredServer
	sources                  []*Source
	listenAddresses          []string
	localDoHListenAddresses  []string
	ServerNames              []string
	DisabledServerNames      []string
	dns64Resolvers           []string
	dns64Prefixes            []string
	serversBlockingFragments []string
	ednsClientSubnets        []*net.IPNet
	queryLogIgnoredQtypes    []string
	queryMeta                []string
	udpListeners             []*net.UDPConn
	tcpListeners             []*net.TCPListener
	localDoHListeners        []*net.TCPListener

	// Strings (16 bytes each on 64-bit)
	nxLogFormat          string
	localDoHCertFile     string
	localDoHCertKeyFile  string
	captivePortalMapFile string
	localDoHPath         string
	cloakFile            string
	forwardFile          string
	blockIPFormat        string
	blockIPLogFile       string
	allowedIPFile        string
	allowedIPFormat      string
	allowedIPLogFile     string
	queryLogFormat       string
	blockIPFile          string
	allowNameFile        string
	allowNameFormat      string
	allowNameLogFile     string
	blockNameLogFile     string
	blockNameFormat      string
	blockNameFile        string
	queryLogFile         string
	blockedQueryResponse string
	userName             string
	nxLogFile            string

	// Fixed arrays (32 bytes each)
	proxySecretKey [32]byte
	proxyPublicKey [32]byte

	// time.Duration (8 bytes each)
	certRefreshDelayAfterFailure time.Duration
	timeout                      time.Duration
	certRefreshDelay             time.Duration

	// Integers (4 bytes each)
	certRefreshConcurrency int
	cacheSize              int
	logMaxBackups          int
	logMaxAge              int
	logMaxSize             int
	maxClients             uint32
	cacheNegMinTTL         uint32
	rejectTTL              uint32
	cacheMaxTTL            uint32
	cacheMinTTL            uint32
	cacheNegMaxTTL         uint32
	cloakTTL               uint32

	// float64 (8 bytes)
	timeoutLoadReduction float64

	// Mutex (platform-dependent)
	listenersMu sync.Mutex

	// Bools (1 byte each) - packed at end to minimize padding
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
	enableHotReload               bool
}

// registerUDPListener safely registers a UDP listener.
func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.listenersMu.Lock()
	proxy.udpListeners = append(proxy.udpListeners, conn)
	proxy.listenersMu.Unlock()
}

// registerTCPListener safely registers a TCP listener.
func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.tcpListeners = append(proxy.tcpListeners, listener)
	proxy.listenersMu.Unlock()
}

// registerLocalDoHListener safely registers a local DoH listener.
func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
	proxy.listenersMu.Unlock()
}

// addDNSListener adds DNS listeners (UDP and TCP) for the given address.
// Go 1.26: Improved error handling with fmt.Errorf wrapping.
func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	udp, tcp := "udp", "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		udp, tcp = "udp4", "tcp4"
	}

	listenUDPAddr, err := net.ResolveUDPAddr(udp, listenAddrStr)
	if err != nil {
		dlog.Fatalf("Failed to resolve UDP address %s: %v", listenAddrStr, err)
	}

	listenTCPAddr, err := net.ResolveTCPAddr(tcp, listenAddrStr)
	if err != nil {
		dlog.Fatalf("Failed to resolve TCP address %s: %v", listenAddrStr, err)
	}

	// Handle privilege separation if userName is set
	if len(proxy.userName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatalf("Failed to create UDP listener: %v", err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatalf("Failed to create TCP listener: %v", err)
		}
		return
	}

	// Parent process - create listeners and pass file descriptors
	if !proxy.child {
		proxy.setupParentListeners(udp, tcp, listenUDPAddr, listenTCPAddr)
		return
	}

	// Child process - inherit file descriptors
	proxy.setupChildListeners(listenUDPAddr, listenAddrStr)
}

// setupParentListeners creates listeners in parent process for privilege separation.
func (proxy *Proxy) setupParentListeners(udp, tcp string, listenUDPAddr *net.UDPAddr, listenTCPAddr *net.TCPAddr) {
	listenerUDP, err := net.ListenUDP(udp, listenUDPAddr)
	if err != nil {
		dlog.Fatalf("Failed to listen UDP: %v", err)
	}
	listenerTCP, err := net.ListenTCP(tcp, listenTCPAddr)
	if err != nil {
		dlog.Fatalf("Failed to listen TCP: %v", err)
	}

	// Get file descriptors (not implemented on Windows)
	fdUDP, err := listenerUDP.File()
	if err != nil {
		dlog.Fatalf("Unable to get UDP file descriptor for privilege separation: %v", err)
	}
	fdTCP, err := listenerTCP.File()
	if err != nil {
		dlog.Fatalf("Unable to get TCP file descriptor for privilege separation: %v", err)
	}

	defer listenerUDP.Close()
	defer listenerTCP.Close()

	FileDescriptorsMu.Lock()
	FileDescriptors = append(FileDescriptors, fdUDP, fdTCP)
	FileDescriptorsMu.Unlock()
}

// setupChildListeners inherits listeners from parent process.
func (proxy *Proxy) setupChildListeners(listenUDPAddr *net.UDPAddr, listenAddrStr string) {
	FileDescriptorsMu.Lock()
	listenerUDP, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to inherit UDP file descriptor: %v", err)
	}
	FileDescriptorNum++

	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to inherit TCP file descriptor: %v", err)
	}
	FileDescriptorNum++
	FileDescriptorsMu.Unlock()

	dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
	proxy.registerUDPListener(listenerUDP.(*net.UDPConn))

	dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
	proxy.registerTCPListener(listenerTCP.(*net.TCPListener))
}

// addLocalDoHListener adds a local DoH (DNS-over-HTTPS) listener.
func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
	network := "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		network = "tcp4"
	}

	listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
	if err != nil {
		dlog.Fatalf("Failed to resolve DoH address %s: %v", listenAddrStr, err)
	}

	// Handle privilege separation
	if len(proxy.userName) <= 0 {
		if err := proxy.localDoHListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatalf("Failed to create DoH listener: %v", err)
		}
		return
	}

	// Parent process
	if !proxy.child {
		listenerTCP, err := net.ListenTCP(network, listenTCPAddr)
		if err != nil {
			dlog.Fatalf("Failed to listen DoH TCP: %v", err)
		}

		fdTCP, err := listenerTCP.File()
		if err != nil {
			dlog.Fatalf("Unable to get DoH TCP file descriptor for privilege separation: %v", err)
		}
		defer listenerTCP.Close()

		FileDescriptorsMu.Lock()
		FileDescriptors = append(FileDescriptors, fdTCP)
		FileDescriptorsMu.Unlock()
		return
	}

	// Child process
	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to inherit DoH TCP file descriptor: %v", err)
	}
	FileDescriptorNum++

	proxy.registerLocalDoHListener(listenerTCP.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddrStr, proxy.localDoHPath)
}

// StartProxy initializes and starts the proxy server.
// Go 1.26: Returns context for graceful shutdown support.
func (proxy *Proxy) StartProxy() (context.Context, context.CancelFunc) {
	// Initialize question size estimator
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()

	// Generate ephemeral keypair
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatalf("Failed to generate secret key: %v", err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)

	// Setup listeners
	for _, listenAddr := range proxy.listenAddresses {
		proxy.addDNSListener(listenAddr)
	}
	for _, listenAddr := range proxy.localDoHListenAddresses {
		proxy.addLocalDoHListener(listenAddr)
	}

	// Initialize monitoring UI
	if proxy.monitoringUI.Enabled {
		proxy.initMonitoringUI()
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Start accepting clients with context
	proxy.startAcceptingClients(ctx)

	// Notify service manager (systemd, etc.)
	if !proxy.child {
		if err := ServiceManagerReadyNotify(); err != nil {
			dlog.Fatalf("Failed to notify service manager: %v", err)
		}
	}

	// Initialize internal resolvers
	proxy.xTransport.internalResolverReady = false
	proxy.xTransport.internalResolvers = proxy.listenAddresses

	// Initial server refresh
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

	// Start background maintenance loops
	go proxy.sourcePrefetchLoop(ctx)
	go proxy.certRefreshLoop(ctx, liveServers)

	return ctx, cancel
}

// initMonitoringUI initializes and starts the monitoring UI.
func (proxy *Proxy) initMonitoringUI() {
	dlog.Noticef("Initializing monitoring UI")
	proxy.monitoringInstance = NewMonitoringUI(proxy)
	if proxy.monitoringInstance == nil {
		dlog.Errorf("Failed to create monitoring UI instance")
		return
	}

	dlog.Noticef("Starting monitoring UI")
	if err := proxy.monitoringInstance.Start(); err != nil {
		dlog.Errorf("Failed to start monitoring UI: %v", err)
		return
	}

	dlog.Noticef("Monitoring UI started successfully")
}

// sourcePrefetchLoop periodically prefetches source lists and updates servers.
// Go 1.26: Context-aware for graceful shutdown.
func (proxy *Proxy) sourcePrefetchLoop(ctx context.Context) {
	lastLogTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			dlog.Notice("Source prefetch loop shutting down")
			return
		default:
		}

		delay := PrefetchSources(proxy.xTransport, proxy.sources)

		select {
		case <-ctx.Done():
			return
		case <-clocksmith.After(delay):
		}

		if err := proxy.updateRegisteredServers(); err != nil {
			dlog.Warnf("Error updating registered servers: %v", err)
		}

		// Log WP2 statistics every 5 minutes
		if time.Since(lastLogTime) > 5*time.Minute {
			proxy.serversInfo.logWP2Stats()
			lastLogTime = time.Now()
		}

		runtime.GC()
	}
}

// certRefreshLoop periodically refreshes server certificates.
// Go 1.26: Context-aware for graceful shutdown.
func (proxy *Proxy) certRefreshLoop(ctx context.Context, liveServers int) {
	if len(proxy.serversInfo.registeredServers) == 0 {
		dlog.Debug("No servers registered, cert refresh loop not started")
		return
	}

	for {
		delay := proxy.certRefreshDelay
		if liveServers == 0 {
			delay = proxy.certRefreshDelayAfterFailure
		}

		select {
		case <-ctx.Done():
			dlog.Notice("Cert refresh loop shutting down")
			return
		case <-clocksmith.After(delay):
		}

		newLiveServers, _ := proxy.serversInfo.refresh(proxy)
		liveServers = newLiveServers

		if liveServers > 0 {
			proxy.certIgnoreTimestamp = false
		}

		runtime.GC()
	}
}

// updateRegisteredServers updates the list of registered servers and relays from sources.
// Go 1.26: Extracted helper functions for better testability and readability.
func (proxy *Proxy) updateRegisteredServers() error {
	var updateErrors []error

	for _, source := range proxy.sources {
		registeredServers, err := source.Parse()
		if err != nil {
			if len(registeredServers) == 0 {
				dlog.Criticalf("Unable to use source [%s]: [%s]", source.name, err)
				updateErrors = append(updateErrors, fmt.Errorf("source %s: %w", source.name, err))
				continue
			}
			dlog.Warnf(
				"Error in source [%s]: [%s] -- Continuing with reduced server count [%d]",
				source.name, err, len(registeredServers),
			)
		}

		for _, registeredServer := range registeredServers {
			if proxy.processRegisteredServer(&registeredServer) {
				// Server/relay was processed successfully
			}
		}
	}

	// Commit all changes to serversInfo
	proxy.commitServerUpdates()

	if len(updateErrors) > 0 {
		return fmt.Errorf("encountered %d errors during server update", len(updateErrors))
	}

	return nil
}

// processRegisteredServer processes a single registered server or relay.
// Go 1.26: Extracted for testability.
func (proxy *Proxy) processRegisteredServer(server *RegisteredServer) bool {
	isRelay := server.stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
		server.stamp.Proto == stamps.StampProtoTypeODoHRelay

	if isRelay {
		return proxy.updateOrAddRelay(server)
	}

	// Apply filters for servers (not relays)
	if !proxy.shouldUseServer(server) {
		return false
	}

	return proxy.updateOrAddServer(server)
}

// shouldUseServer determines if a server should be used based on configured filters.
// Go 1.26: Extracted for testability and clarity.
func (proxy *Proxy) shouldUseServer(server *RegisteredServer) bool {
	// Apply ServerNames whitelist
	if len(proxy.ServerNames) > 0 {
		if !includesName(proxy.ServerNames, server.name) {
			return false
		}
	} else {
		// Check required properties
		if server.stamp.Props&proxy.requiredProps != proxy.requiredProps {
			return false
		}
	}

	// Apply DisabledServerNames blacklist
	if includesName(proxy.DisabledServerNames, server.name) {
		return false
	}

	// Apply IP version filters
	if proxy.SourceIPv4 || proxy.SourceIPv6 {
		isIPv4, isIPv6 := determineIPVersion(server)
		if !(proxy.SourceIPv4 && isIPv4) && !(proxy.SourceIPv6 && isIPv6) {
			return false
		}
	}

	// Apply protocol filters
	return proxy.isProtocolSupported(server.stamp.Proto)
}

// determineIPVersion determines if a server uses IPv4, IPv6, or both.
// Go 1.26: Extracted for testability.
func determineIPVersion(server *RegisteredServer) (isIPv4, isIPv6 bool) {
	// DoH supports both IPv4 and IPv6
	if server.stamp.Proto == stamps.StampProtoTypeDoH {
		return true, true
	}

	// Check if address starts with [ (IPv6)
	if strings.HasPrefix(server.stamp.ServerAddrStr, "[") {
		return false, true
	}

	return true, false
}

// isProtocolSupported checks if the protocol is enabled.
// Go 1.26: Extracted for testability.
func (proxy *Proxy) isProtocolSupported(proto stamps.StampProtoType) bool {
	switch proto {
	case stamps.StampProtoTypeDNSCrypt:
		return proxy.SourceDNSCrypt
	case stamps.StampProtoTypeDoH:
		return proxy.SourceDoH
	case stamps.StampProtoTypeODoHTarget:
		return proxy.SourceODoH
	default:
		return false
	}
}

// updateOrAddRelay updates an existing relay or adds a new one.
// Returns true if relay was added (new).
func (proxy *Proxy) updateOrAddRelay(relay *RegisteredServer) bool {
	for i, current := range proxy.registeredRelays {
		if current.name == relay.name {
			// Update existing relay if stamp changed
			if current.stamp.String() != relay.stamp.String() {
				dlog.Infof(
					"Updating stamp for relay [%s] was: %s now: %s",
					relay.name, current.stamp.String(), relay.stamp.String(),
				)
				proxy.registeredRelays[i].stamp = relay.stamp
			}
			return false
		}
	}

	// Add new relay
	dlog.Debugf("Adding [%s] to the set of available relays", relay.name)
	proxy.registeredRelays = append(proxy.registeredRelays, *relay)
	return true
}

// updateOrAddServer updates an existing server or adds a new one.
// Returns true if server was added (new).
func (proxy *Proxy) updateOrAddServer(server *RegisteredServer) bool {
	for i, current := range proxy.registeredServers {
		if current.name == server.name {
			// Update existing server if stamp changed
			if current.stamp.String() != server.stamp.String() {
				dlog.Infof(
					"Updating stamp for server [%s] was: %s now: %s",
					server.name, current.stamp.String(), server.stamp.String(),
				)
				proxy.registeredServers[i].stamp = server.stamp
			}
			return false
		}
	}

	// Add new server
	dlog.Debugf("Adding [%s] to the set of wanted resolvers", server.name)
	proxy.registeredServers = append(proxy.registeredServers, *server)
	return true
}

// commitServerUpdates commits pending server/relay changes to serversInfo.
func (proxy *Proxy) commitServerUpdates() {
	for _, server := range proxy.registeredServers {
		proxy.serversInfo.registerServer(server.name, server.stamp)
	}
	for _, relay := range proxy.registeredRelays {
		proxy.serversInfo.registerRelay(relay.name, relay.stamp)
	}
}

// udpListener processes incoming UDP DNS queries with zero-allocation buffer pooling.
// Go 1.26: Context-aware shutdown, buffer pooling for performance.
func (proxy *Proxy) udpListener(ctx context.Context, clientPc *net.UDPConn) {
	defer clientPc.Close()

	// Buffer pool for zero-allocation packet processing
	bufferPool := &sync.Pool{
		New: func() any {
			buf := make([]byte, MaxDNSPacketSize-1)
			return &buf
		},
	}

	for {
		// Check for shutdown signal
		select {
		case <-ctx.Done():
			dlog.Debug("UDP listener shutting down gracefully")
			return
		default:
		}

		// Set read deadline for periodic context checks
		if err := clientPc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			dlog.Debugf("Failed to set read deadline: %v", err)
			return
		}

		// Get buffer from pool (zero allocation!)
		bufPtr := bufferPool.Get().(*[]byte)
		buffer := *bufPtr

		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			bufferPool.Put(bufPtr)

			// Check if timeout (normal for periodic context checks)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			// Check if connection closed
			if errors.Is(err, net.ErrClosed) {
				dlog.Debug("UDP listener closed")
				return
			}

			dlog.Warnf("UDP read error: %v", err)
			continue
		}

		// Create packet copy for async processing
		packet := make([]byte, length)
		copy(packet, buffer[:length])

		// Return buffer to pool immediately
		bufferPool.Put(bufPtr)

		// Check client limit
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())

			// Process synchronously for cached responses only
			proxy.processIncomingQuery(
				"udp",
				proxy.xTransport.mainProto,
				packet,
				&clientAddr,
				clientPc,
				time.Now(),
				true, // onlyCached
			)
			continue
		}

		// Process asynchronously
		go func(pkt []byte, addr net.Addr) {
			defer proxy.clientsCountDec()
			proxy.processIncomingQuery(
				"udp",
				proxy.xTransport.mainProto,
				pkt,
				&addr,
				clientPc,
				time.Now(),
				false,
			)
		}(packet, clientAddr)
	}
}

// tcpListener accepts and processes TCP DNS queries.
// Go 1.26: Context-aware shutdown and improved error handling.
func (proxy *Proxy) tcpListener(ctx context.Context, acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	for {
		// Check for shutdown signal
		select {
		case <-ctx.Done():
			dlog.Debug("TCP listener shutting down gracefully")
			return
		default:
		}

		// Set accept deadline for periodic context checks
		if err := acceptPc.SetDeadline(time.Now().Add(time.Second)); err != nil {
			dlog.Debugf("Failed to set accept deadline: %v", err)
			return
		}

		clientPc, err := acceptPc.Accept()
		if err != nil {
			// Check if timeout (normal for periodic context checks)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			// Check if listener closed
			if errors.Is(err, net.ErrClosed) {
				dlog.Debug("TCP listener closed")
				return
			}

			dlog.Warnf("TCP accept error: %v", err)
			continue
		}

		// Check client limit
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())
			clientPc.Close()
			continue
		}

		// Process connection in goroutine
		go proxy.handleTCPConnection(clientPc)
	}
}

// handleTCPConnection processes a single TCP DNS connection.
// Go 1.26: Extracted for clarity and better error handling.
func (proxy *Proxy) handleTCPConnection(clientPc net.Conn) {
	defer clientPc.Close()
	defer proxy.clientsCountDec()

	// Set dynamic timeout based on server load
	dynamicTimeout := proxy.getDynamicTimeout()
	if err := clientPc.SetDeadline(time.Now().Add(dynamicTimeout)); err != nil {
		dlog.Debugf("Failed to set connection deadline: %v", err)
		return
	}

	start := time.Now()

	// Read DNS query with length prefix
	packet, err := ReadPrefixed(&clientPc)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			dlog.Debugf("Failed to read TCP query: %v", err)
		}
		return
	}

	clientAddr := clientPc.RemoteAddr()
	proxy.processIncomingQuery("tcp", "tcp", packet, &clientAddr, clientPc, start, false)
}

// udpListenerFromAddr creates a UDP listener from an address.
func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	listenConfig, err := proxy.udpListenerConfig()
	if err != nil {
		return fmt.Errorf("failed to create UDP config: %w", err)
	}

	listenAddrStr := listenAddr.String()
	network := "udp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		network = "udp4"
	}

	clientPc, err := listenConfig.ListenPacket(context.Background(), network, listenAddrStr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	proxy.registerUDPListener(clientPc.(*net.UDPConn))
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	return nil
}

// tcpListenerFromAddr creates a TCP listener from an address.
func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return fmt.Errorf("failed to create TCP config: %w", err)
	}

	listenAddrStr := listenAddr.String()
	network := "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		network = "tcp4"
	}

	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return fmt.Errorf("failed to listen TCP: %w", err)
	}

	proxy.registerTCPListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	return nil
}

// localDoHListenerFromAddr creates a local DoH listener from an address.
func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return fmt.Errorf("failed to create DoH TCP config: %w", err)
	}

	listenAddrStr := listenAddr.String()
	network := "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		network = "tcp4"
	}

	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return fmt.Errorf("failed to listen DoH TCP: %w", err)
	}

	proxy.registerLocalDoHListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
	return nil
}

// startAcceptingClients starts all listener goroutines.
// Go 1.26: Context-aware for graceful shutdown.
func (proxy *Proxy) startAcceptingClients(ctx context.Context) {
	for _, clientPc := range proxy.udpListeners {
		go proxy.udpListener(ctx, clientPc)
	}
	proxy.udpListeners = nil

	for _, acceptPc := range proxy.tcpListeners {
		go proxy.tcpListener(ctx, acceptPc)
	}
	proxy.tcpListeners = nil

	for _, acceptPc := range proxy.localDoHListeners {
		go proxy.localDoHListener(ctx, acceptPc)
	}
	proxy.localDoHListeners = nil
}

// prepareForRelay prepares a query for relaying through an anonymization relay.
func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)

	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)

	*encryptedQuery = relayedQuery
}

// exchangeWithUDPServer exchanges a query with a DNS server over UDP.
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
		return proxy.exchangeWithUDPServerViaProxy(
			serverInfo, sharedKey, encryptedQuery, clientNonce,
			upstreamAddr, proxyDialer,
		)
	}

	pc, err := proxy.udpConnPool.Get(upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get UDP connection: %w", err)
	}

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		proxy.udpConnPool.Discard(pc)
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	query := encryptedQuery
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &query)
	}

	encryptedResponse := make([]byte, MaxDNSPacketSize)
	var readErr error

	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(query); err != nil {
			proxy.udpConnPool.Discard(pc)
			return nil, fmt.Errorf("failed to write query: %w", err)
		}

		length, err := pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			readErr = nil
			break
		}

		readErr = err
		dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
	}

	if readErr != nil {
		proxy.udpConnPool.Discard(pc)
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}

	proxy.udpConnPool.Put(upstreamAddr, pc)

	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

// exchangeWithUDPServerViaProxy exchanges a query via a SOCKS proxy.
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
		return nil, fmt.Errorf("failed to dial via proxy: %w", err)
	}
	defer pc.Close()

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}

	encryptedResponse := make([]byte, MaxDNSPacketSize)

	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(encryptedQuery); err != nil {
			return nil, fmt.Errorf("failed to write query: %w", err)
		}

		length, err := pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			break
		}

		dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
	}

	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

// exchangeWithTCPServer exchanges a query with a DNS server over TCP.
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

	var pc net.Conn
	var err error

	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTimeout("tcp", upstreamAddr.String(), serverInfo.Timeout)
	} else {
		pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}
	defer pc.Close()

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}

	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to prefix query: %w", err)
	}

	if _, err := pc.Write(encryptedQuery); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

// clientsCountInc atomically increments the client counter.
// Returns false if max clients limit is reached.
// Go 1.26: Uses atomic.Uint32 type-safe methods.
func (proxy *Proxy) clientsCountInc() bool {
	for {
		current := proxy.clientsCount.Load()
		if current >= proxy.maxClients {
			return false
		}
		if proxy.clientsCount.CompareAndSwap(current, current+1) {
			dlog.Debugf("clients count: %d", current+1)
			return true
		}
		// CAS failed, retry
	}
}

// clientsCountDec atomically decrements the client counter.
// Go 1.26: Uses atomic.Uint32 type-safe methods.
func (proxy *Proxy) clientsCountDec() {
	for {
		current := proxy.clientsCount.Load()
		if current == 0 {
			return
		}
		if proxy.clientsCount.CompareAndSwap(current, current-1) {
			dlog.Debugf("clients count: %d", current-1)
			return
		}
		// CAS failed, retry
	}
}

// getDynamicTimeout calculates timeout based on current server load.
// Go 1.26: Uses max() built-in for cleaner code.
func (proxy *Proxy) getDynamicTimeout() time.Duration {
	if proxy.timeoutLoadReduction <= 0.0 || proxy.maxClients == 0 {
		return proxy.timeout
	}

	currentClients := proxy.clientsCount.Load()
	utilization := float64(currentClients) / float64(proxy.maxClients)

	// Use quartic (power 4) curve for smooth degradation
	utilization4 := utilization * utilization * utilization * utilization
	factor := 1.0 - (utilization4 * proxy.timeoutLoadReduction)
	factor = max(factor, 0.1) // Go 1.21+ max built-in

	dynamicTimeout := time.Duration(float64(proxy.timeout) * factor)
	dlog.Debugf("Dynamic timeout: %v (utilization: %.2f%%, factor: %.2f)",
		dynamicTimeout, utilization*100, factor)

	return dynamicTimeout
}

// processIncomingQuery processes a DNS query from a client.
// This is the main query processing pipeline.
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

	// Apply query plugins with lazy server selection
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
			if serverInfo.Relay != nil {
				pluginsState.relayName = serverInfo.Relay.Name
			}

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

// Shutdown gracefully shuts down the proxy.
// Go 1.26: New method for graceful shutdown support.
func (proxy *Proxy) Shutdown(ctx context.Context) error {
	dlog.Notice("Shutting down proxy...")

	var errs []error

	// Close all listeners
	proxy.listenersMu.Lock()

	for _, conn := range proxy.udpListeners {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("UDP listener: %w", err))
		}
	}
	proxy.udpListeners = nil

	for _, listener := range proxy.tcpListeners {
		if err := listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TCP listener: %w", err))
		}
	}
	proxy.tcpListeners = nil

	for _, listener := range proxy.localDoHListeners {
		if err := listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("DoH listener: %w", err))
		}
	}
	proxy.localDoHListeners = nil

	proxy.listenersMu.Unlock()

	// Wait for all clients to finish (with timeout)
	shutdownTimeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if proxy.clientsCount.Load() == 0 {
			dlog.Notice("All clients finished")
			break
		}

		select {
		case <-shutdownTimeout:
			remaining := proxy.clientsCount.Load()
			dlog.Warnf("Shutdown timeout reached with %d clients remaining", remaining)
			errs = append(errs, fmt.Errorf("shutdown timeout: %d clients remaining", remaining))
			goto cleanup
		case <-ticker.C:
			// Continue waiting
		case <-ctx.Done():
			dlog.Warn("Shutdown context cancelled")
			return ctx.Err()
		}
	}

cleanup:
	// Shutdown monitoring UI
	if proxy.monitoringInstance != nil {
		if err := proxy.monitoringInstance.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("monitoring UI: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	dlog.Notice("Proxy shutdown complete")
	return nil
}

// NewProxy creates a new Proxy instance with default configuration.
func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
		udpConnPool: NewUDPConnPool(),
	}
}
