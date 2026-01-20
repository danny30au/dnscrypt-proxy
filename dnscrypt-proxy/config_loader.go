package main

import (
"errors"
"fmt"
"net"
"net/http"
"net/url"
"os"
"strconv"
"strings"
"time"

"github.com/jedisct1/dlog"
stamps "github.com/jedisct1/go-dnsstamps"
netproxy "golang.org/x/net/proxy"
)

// configureLogging - Configure logging based on the configuration
func configureLogging(proxy *Proxy, flags *ConfigFlags, config *Config) {
if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
dlog.SetLogLevel(dlog.Severity(config.LogLevel))
}
if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
dlog.SetLogLevel(dlog.SeverityInfo)
}
dlog.TruncateLogFile(config.LogFileLatest)

// Go 1.26: Simplified boolean checks - check command mode conditions directly
isCommandMode := (flags.Check != nil && *flags.Check) ||
proxy.showCerts ||
(flags.List != nil && *flags.List) ||
(flags.ListAll != nil && *flags.ListAll)

if isCommandMode {
// Don't configure additional logging for command mode
return
}

if config.UseSyslog {
dlog.UseSyslog(true)
} else if config.LogFile != nil {
dlog.UseLogFile(*config.LogFile)
if !*flags.Child {
FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
} else {
dlog.SetFileDescriptor(os.NewFile(uintptr(InheritedDescriptorsBase+FileDescriptorNum), "logFile"))
FileDescriptorNum++
}
}

if !*flags.Child {
dlog.Noticef("dnscrypt-proxy %s", AppVersion)
}
}

// configureXTransport - Configures the XTransport
func configureXTransport(proxy *Proxy, config *Config) error {
proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
proxy.xTransport.tlsPreferRSA = config.TLSPreferRSA
proxy.xTransport.http3 = config.HTTP3
proxy.xTransport.http3Probe = config.HTTP3Probe

// Configure bootstrap resolvers - optimized string check
if len(config.BootstrapResolvers) == 0 && len(config.BootstrapResolversLegacy) > 0 {
dlog.Warnf("fallback_resolvers was renamed to bootstrap_resolvers - Please update your configuration")
config.BootstrapResolvers = config.BootstrapResolversLegacy
}
if len(config.BootstrapResolvers) > 0 {
// Pre-allocate for better memory efficiency (Go 1.26 benefits from optimized small allocations)
for _, resolver := range config.BootstrapResolvers {
if err := isIPAndPort(resolver); err != nil {
// Go 1.26: Use fmt.Errorf with %w for optimized error wrapping
return fmt.Errorf("Bootstrap resolver [%v]: %w", resolver, err)
}
}
proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
}
proxy.xTransport.bootstrapResolvers = config.BootstrapResolvers
proxy.xTransport.useIPv4 = config.SourceIPv4
proxy.xTransport.useIPv6 = config.SourceIPv6
proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second

// Configure HTTP proxy URL if specified
if len(config.HTTPProxyURL) > 0 {
httpProxyURL, err := url.Parse(config.HTTPProxyURL)
if err != nil {
return fmt.Errorf("Unable to parse the HTTP proxy URL [%v]: %w", config.HTTPProxyURL, err)
}

// Pre-resolve proxy hostname using bootstrap resolvers if it's a domain
hostname := httpProxyURL.Hostname()
if hostname != "" && ParseIP(hostname) == nil {
ips, ttl, err := proxy.xTransport.resolve(hostname, proxy.xTransport.useIPv4, proxy.xTransport.useIPv6)
if err != nil {
dlog.Warnf("Unable to resolve HTTP proxy hostname [%s] using bootstrap resolvers: %v", hostname, err)
} else if len(ips) > 0 {
proxy.xTransport.saveCachedIPs(hostname, ips, ttl)
dlog.Infof("Resolved HTTP proxy hostname [%s] to [%s] using bootstrap resolvers", hostname, ips[0])
}
}

proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
}

// Configure proxy dialer if specified
if len(config.Proxy) > 0 {
proxyDialerURL, err := url.Parse(config.Proxy)
if err != nil {
return fmt.Errorf("Unable to parse the proxy URL [%v]: %w", config.Proxy, err)
}
proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
if err != nil {
return fmt.Errorf("Unable to use the proxy: %w", err)
}
proxy.xTransport.proxyDialer = &proxyDialer
proxy.xTransport.mainProto = "tcp"
}

proxy.xTransport.rebuildTransport()

// Configure TLS key log if specified
if len(config.TLSKeyLogFile) > 0 {
f, err := os.OpenFile(config.TLSKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
if err != nil {
return fmt.Errorf("Unable to create key log file [%s]: %w", config.TLSKeyLogFile, err)
}
dlog.Warnf("TLS key log file [%s] enabled", config.TLSKeyLogFile)
proxy.xTransport.keyLogWriter = f
proxy.xTransport.rebuildTransport()
}

return nil
}

// configureDoHClientAuth - Configures DoH client authentication
func configureDoHClientAuth(proxy *Proxy, config *Config) error {
if config.DoHClientX509AuthLegacy.Creds != nil {
return errors.New("[tls_client_auth] has been renamed to [doh_client_x509_auth] - Update your config file")
}

dohClientCreds := config.DoHClientX509Auth.Creds
if len(dohClientCreds) > 0 {
dlog.Noticef("Enabling TLS authentication")
if len(dohClientCreds) > 1 {
dlog.Fatal("Only one tls_client_auth entry is currently supported")
}
configClientCred := dohClientCreds[0]
proxy.xTransport.tlsClientCreds = DOHClientCreds{
clientCert: configClientCred.ClientCert,
clientKey:  configClientCred.ClientKey,
rootCA:     configClientCred.RootCA,
}
proxy.xTransport.rebuildTransport()
}

return nil
}

// configureServerParams - Configures server parameters
func configureServerParams(proxy *Proxy, config *Config) {
proxy.blockedQueryResponse = config.BlockedQueryResponse
proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
proxy.maxClients = config.MaxClients
proxy.timeoutLoadReduction = config.TimeoutLoadReduction

// Simplified range check
if proxy.timeoutLoadReduction < 0.0 || proxy.timeoutLoadReduction > 1.0 {
dlog.Warnf("timeout_load_reduction must be between 0.0 and 1.0, using default 0.75")
proxy.timeoutLoadReduction = 0.75
}

// Set protocol based on config
if config.ForceTCP {
proxy.xTransport.mainProto = "tcp"
} else {
proxy.xTransport.mainProto = "udp"
}

// Configure certificate refresh parameters - use built-in max function
proxy.certRefreshConcurrency = max(1, config.CertRefreshConcurrency)
proxy.certRefreshDelay = time.Duration(max(60, config.CertRefreshDelay)) * time.Minute
proxy.certRefreshDelayAfterFailure = 10 * time.Second
proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
proxy.ephemeralKeys = config.EphemeralKeys
proxy.monitoringUI = config.MonitoringUI
}

// configureLoadBalancing - Configures load balancing strategy
func configureLoadBalancing(proxy *Proxy, config *Config) {
lbStrategy := LBStrategy(DefaultLBStrategy)
lbStrategyStr := strings.ToLower(config.LBStrategy)

switch lbStrategyStr {
case "":
// default - WP2 is now the default strategy
dlog.Noticef("Using default Weighted Power of Two (WP2) load balancing strategy")
case "p2":
lbStrategy = LBStrategyP2{}
case "ph":
lbStrategy = LBStrategyPH{}
case "fastest", "first": // Combined cases for clarity
lbStrategy = LBStrategyFirst{}
case "random":
lbStrategy = LBStrategyRandom{}
case "wp2":
lbStrategy = LBStrategyWP2{}
default:
if strings.HasPrefix(lbStrategyStr, "p") {
// Direct slice indexing instead of TrimPrefix for better performance
n, err := strconv.ParseInt(lbStrategyStr[1:], 10, 32)
if err == nil && n > 0 {
lbStrategy = LBStrategyPN{n: int(n)}
} else {
dlog.Warnf("Invalid load balancing strategy: [%s]", config.LBStrategy)
}
} else {
dlog.Warnf("Unknown load balancing strategy: [%s]", config.LBStrategy)
}
}

proxy.serversInfo.lbStrategy = lbStrategy
proxy.serversInfo.lbEstimator = config.LBEstimator
}

// configurePlugins - Configures DNS plugins
func configurePlugins(proxy *Proxy, config *Config) {
// Configure listen addresses and paths
proxy.listenAddresses = config.ListenAddresses
proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses

if len(config.LocalDoH.Path) > 0 && config.LocalDoH.Path[0] != '/' {
dlog.Fatalf("local DoH: [%s] cannot be a valid URL path. Read the documentation", config.LocalDoH.Path)
}
proxy.localDoHPath = config.LocalDoH.Path
proxy.localDoHCertFile = config.LocalDoH.CertFile
proxy.localDoHCertKeyFile = config.LocalDoH.CertKeyFile

// Configure plugins
proxy.pluginBlockIPv6 = config.BlockIPv6
proxy.pluginBlockUnqualified = config.BlockUnqualified
proxy.pluginBlockUndelegated = config.BlockUndelegated

// Configure cache
proxy.cache = config.Cache
proxy.cacheSize = config.CacheSize

// Simplified TTL configuration
if config.CacheNegTTL > 0 {
proxy.cacheNegMinTTL = config.CacheNegTTL
proxy.cacheNegMaxTTL = config.CacheNegTTL
} else {
proxy.cacheNegMinTTL = config.CacheNegMinTTL
proxy.cacheNegMaxTTL = config.CacheNegMaxTTL
}

proxy.cacheMinTTL = config.CacheMinTTL
proxy.cacheMaxTTL = config.CacheMaxTTL
proxy.rejectTTL = config.RejectTTL
proxy.cloakTTL = config.CloakTTL
proxy.cloakedPTR = config.CloakedPTR

// Configure query meta
proxy.queryMeta = config.QueryMeta
}

// configureEDNSClientSubnet - Configures EDNS client subnet
func configureEDNSClientSubnet(proxy *Proxy, config *Config) error {
if len(config.EDNSClientSubnet) != 0 {
// Pre-allocate slice with exact capacity (Go 1.26 optimized small allocations)
proxy.ednsClientSubnets = make([]*net.IPNet, 0, len(config.EDNSClientSubnet))
for _, cidr := range config.EDNSClientSubnet {
_, ipnet, err := net.ParseCIDR(cidr)
if err != nil {
return fmt.Errorf("Invalid EDNS-client-subnet CIDR: [%v]: %w", cidr, err)
}
proxy.ednsClientSubnets = append(proxy.ednsClientSubnets, ipnet)
}
}
return nil
}

// validateLogConfig - Helper to validate and normalize log configuration (DRY principle)
func validateLogConfig(format *string, formatName string) error {
if len(*format) == 0 {
*format = "tsv"
} else {
*format = strings.ToLower(*format)
}
if *format != "tsv" && *format != "ltsv" {
return fmt.Errorf("Unsupported %s log format", formatName)
}
return nil
}

// configureQueryLog - Configures query logging
func configureQueryLog(proxy *Proxy, config *Config) error {
if err := validateLogConfig(&config.QueryLog.Format, "query"); err != nil {
return err
}
proxy.queryLogFile = config.QueryLog.File
proxy.queryLogFormat = config.QueryLog.Format
proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

return nil
}

// configureNXLog - Configures NX domain logging
func configureNXLog(proxy *Proxy, config *Config) error {
if err := validateLogConfig(&config.NxLog.Format, "NX"); err != nil {
return err
}
proxy.nxLogFile = config.NxLog.File
proxy.nxLogFormat = config.NxLog.Format

return nil
}

// configureBlockedNames - Configures blocked names
func configureBlockedNames(proxy *Proxy, config *Config) error {
if len(config.BlockName.File) > 0 && len(config.BlockNameLegacy.File) > 0 {
return errors.New("Don't specify both [blocked_names] and [blacklist] sections - Update your config file")
}
if len(config.BlockNameLegacy.File) > 0 {
dlog.Notice("Use of [blacklist] is deprecated - Update your config file")
config.BlockName.File = config.BlockNameLegacy.File
config.BlockName.Format = config.BlockNameLegacy.Format
config.BlockName.LogFile = config.BlockNameLegacy.LogFile
}
if err := validateLogConfig(&config.BlockName.Format, "block"); err != nil {
return err
}
proxy.blockNameFile = config.BlockName.File
proxy.blockNameFormat = config.BlockName.Format
proxy.blockNameLogFile = config.BlockName.LogFile

return nil
}

// configureAllowedNames - Configures allowed names
func configureAllowedNames(proxy *Proxy, config *Config) error {
if len(config.AllowedName.File) > 0 && len(config.WhitelistNameLegacy.File) > 0 {
return errors.New("Don't specify both [whitelist] and [allowed_names] sections - Update your config file")
}
if len(config.WhitelistNameLegacy.File) > 0 {
dlog.Notice("Use of [whitelist] is deprecated - Update your config file")
config.AllowedName.File = config.WhitelistNameLegacy.File
config.AllowedName.Format = config.WhitelistNameLegacy.Format
config.AllowedName.LogFile = config.WhitelistNameLegacy.LogFile
}
if err := validateLogConfig(&config.AllowedName.Format, "allowed_names"); err != nil {
return err
}
proxy.allowNameFile = config.AllowedName.File
proxy.allowNameFormat = config.AllowedName.Format
proxy.allowNameLogFile = config.AllowedName.LogFile

return nil
}

// configureBlockedIPs - Configures blocked IPs
func configureBlockedIPs(proxy *Proxy, config *Config) error {
if len(config.BlockIP.File) > 0 && len(config.BlockIPLegacy.File) > 0 {
return errors.New("Don't specify both [blocked_ips] and [ip_blacklist] sections - Update your config file")
}
if len(config.BlockIPLegacy.File) > 0 {
dlog.Notice("Use of [ip_blacklist] is deprecated - Update your config file")
config.BlockIP.File = config.BlockIPLegacy.File
config.BlockIP.Format = config.BlockIPLegacy.Format
config.BlockIP.LogFile = config.BlockIPLegacy.LogFile
}
if err := validateLogConfig(&config.BlockIP.Format, "IP block"); err != nil {
return err
}
proxy.blockIPFile = config.BlockIP.File
proxy.blockIPFormat = config.BlockIP.Format
proxy.blockIPLogFile = config.BlockIP.LogFile

return nil
}

// configureAllowedIPs - Configures allowed IPs
func configureAllowedIPs(proxy *Proxy, config *Config) error {
if err := validateLogConfig(&config.AllowIP.Format, "allowed_ips"); err != nil {
return err
}
proxy.allowedIPFile = config.AllowIP.File
proxy.allowedIPFormat = config.AllowIP.Format
proxy.allowedIPLogFile = config.AllowIP.LogFile

return nil
}

// configureAdditionalFiles - Configures forwarding, cloaking, and captive portal files
func configureAdditionalFiles(proxy *Proxy, config *Config) {
proxy.forwardFile = config.ForwardFile
proxy.cloakFile = config.CloakFile
proxy.captivePortalMapFile = config.CaptivePortals.MapFile
}

// configureWeeklyRanges - Parses and configures weekly ranges
func configureWeeklyRanges(proxy *Proxy, config *Config) error {
allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
if err != nil {
return fmt.Errorf("failed to parse weekly ranges: %w", err)
}
proxy.allWeeklyRanges = allWeeklyRanges
return nil
}

// configureAnonymizedDNS - Configures anonymized DNS
func configureAnonymizedDNS(proxy *Proxy, config *Config) {
if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
// Pre-allocate map with capacity (Go 1.26 optimized allocation)
routes := make(map[string][]string, len(configRoutes))
for _, configRoute := range configRoutes {
routes[configRoute.ServerName] = configRoute.RelayNames
}
proxy.routes = &routes
}

proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
}

// configureSourceRestrictions - Configures server source restrictions
func configureSourceRestrictions(proxy *Proxy, flags *ConfigFlags, config *Config) {
if *flags.ListAll {
config.ServerNames = nil
config.DisabledServerNames = nil
config.SourceRequireDNSSEC = false
config.SourceRequireNoFilter = false
config.SourceRequireNoLog = false
config.SourceIPv4 = true
config.SourceIPv6 = true
config.SourceDNSCrypt = true
config.SourceDoH = true
config.SourceODoH = true
}

var requiredProps stamps.ServerInformalProperties
if config.SourceRequireDNSSEC {
requiredProps |= stamps.ServerInformalPropertyDNSSEC
}
if config.SourceRequireNoLog {
requiredProps |= stamps.ServerInformalPropertyNoLog
}
if config.SourceRequireNoFilter {
requiredProps |= stamps.ServerInformalPropertyNoFilter
}

proxy.requiredProps = requiredProps
proxy.ServerNames = config.ServerNames
proxy.DisabledServerNames = config.DisabledServerNames
proxy.SourceIPv4 = config.SourceIPv4
proxy.SourceIPv6 = config.SourceIPv6
proxy.SourceDNSCrypt = config.SourceDNSCrypt
proxy.SourceDoH = config.SourceDoH
proxy.SourceODoH = config.SourceODoH
}

// determineNetprobeAddress - Determines the address to use for network probing
func determineNetprobeAddress(flags *ConfigFlags, config *Config) (string, int) {
netprobeTimeout := config.NetprobeTimeout
if flags.NetprobeTimeoutOverride != nil {
netprobeTimeout = *flags.NetprobeTimeoutOverride
}

netprobeAddress := DefaultNetprobeAddress
if len(config.NetprobeAddress) > 0 {
netprobeAddress = config.NetprobeAddress
} else if len(config.BootstrapResolvers) > 0 {
netprobeAddress = config.BootstrapResolvers[0]
}

return netprobeAddress, netprobeTimeout
}

// initializeNetworking - Initializes networking
func initializeNetworking(proxy *Proxy, flags *ConfigFlags, config *Config) error {
// Simplified command mode check
isCommandMode := *flags.Check || proxy.showCerts || *flags.List || *flags.ListAll
if isCommandMode {
return nil
}

netprobeAddress, netprobeTimeout := determineNetprobeAddress(flags, config)
if err := NetProbe(proxy, netprobeAddress, netprobeTimeout); err != nil {
return fmt.Errorf("network probe failed: %w", err)
}

for _, listenAddrStr := range proxy.listenAddresses {
proxy.addDNSListener(listenAddrStr)
}
for _, listenAddrStr := range proxy.localDoHListenAddresses {
proxy.addLocalDoHListener(listenAddrStr)
}

return proxy.addSystemDListeners()
}
