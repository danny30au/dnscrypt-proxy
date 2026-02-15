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

// flagEnabled returns true if a *bool flag is non-nil and set to true.
func flagEnabled(b *bool) bool {
	return b != nil && *b
}

// isCommandMode reports whether we are running in a command/one-shot mode.
// In this mode we avoid configuring long-lived logging and we skip networking init.
func isCommandMode(proxy *Proxy, flags *ConfigFlags) bool {
	if proxy != nil && proxy.showCerts {
		return true
	}
	if flags == nil {
		return false
	}
	return flagEnabled(flags.Check) || flagEnabled(flags.List) || flagEnabled(flags.ListAll)
}

// normalizeFormat lowercases a format and applies a default when empty.
func normalizeFormat(format string, def string) string {
	if len(format) == 0 {
		return def
	}
	return strings.ToLower(format)
}

// validateFormat ensures format is one of the allowed ones.
func validateFormat(format string, allowed ...string) error {
	for _, a := range allowed {
		if format == a {
			return nil
		}
	}
	return fmt.Errorf("unsupported log format: %q", format)
}

// configureLogging configures logging based on the configuration.
// Behavior is preserved, but flag handling has been hardened to avoid nil dereferences.
func configureLogging(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if proxy == nil || config == nil {
		return
	}

	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}
	dlog.TruncateLogFile(config.LogFileLatest)

	if isCommandMode(proxy, flags) {
		// Don't configure additional logging for command mode.
		return
	}

	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if flags == nil || !flagEnabled(flags.Child) {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			dlog.SetFileDescriptor(os.NewFile(uintptr(InheritedDescriptorsBase+FileDescriptorNum), "logFile"))
			FileDescriptorNum++
		}
	}

	if flags == nil || !flagEnabled(flags.Child) {
		dlog.Noticef("dnscrypt-proxy %s", AppVersion)
	}
}

// configureBootstrapResolvers applies validation and backward compatibility for bootstrap resolvers.
func configureBootstrapResolvers(proxy *Proxy, config *Config) error {
	if len(config.BootstrapResolvers) == 0 && len(config.BootstrapResolversLegacy) > 0 {
		dlog.Warnf("fallback_resolvers was renamed to bootstrap_resolvers - Please update your configuration")
		config.BootstrapResolvers = config.BootstrapResolversLegacy
	}
	if len(config.BootstrapResolvers) == 0 {
		return nil
	}
	for _, resolver := range config.BootstrapResolvers {
		if err := isIPAndPort(resolver); err != nil {
			return fmt.Errorf("bootstrap resolver [%v]: %w", resolver, err)
		}
	}
	proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	proxy.xTransport.bootstrapResolvers = config.BootstrapResolvers
	return nil
}

// configureHTTPProxy configures an HTTP proxy URL and performs an early bootstrap resolve.
func configureHTTPProxy(proxy *Proxy, config *Config) error {
	if len(config.HTTPProxyURL) == 0 {
		return nil
	}
	httpProxyURL, err := url.Parse(config.HTTPProxyURL)
	if err != nil {
		return fmt.Errorf("unable to parse the HTTP proxy URL [%v]: %w", config.HTTPProxyURL, err)
	}

	// Pre-resolve proxy hostname using bootstrap resolvers if it's a domain.
	host := httpProxyURL.Hostname()
	if host != "" && ParseIP(host) == nil {
		ips, ttl, err := proxy.xTransport.resolve(host, proxy.xTransport.useIPv4, proxy.xTransport.useIPv6)
		if err != nil {
			dlog.Warnf("Unable to resolve HTTP proxy hostname [%s] using bootstrap resolvers: %v", host, err)
		} else if len(ips) > 0 {
			proxy.xTransport.saveCachedIPs(host, ips, ttl)
			dlog.Infof("Resolved HTTP proxy hostname [%s] to [%s] using bootstrap resolvers", host, ips[0])
		}
	}

	proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
	return nil
}

// configureProxyDialer configures a SOCKS/HTTP CONNECT dialer for upstream connections.
func configureProxyDialer(proxy *Proxy, config *Config) error {
	if len(config.Proxy) == 0 {
		return nil
	}
	proxyDialerURL, err := url.Parse(config.Proxy)
	if err != nil {
		return fmt.Errorf("unable to parse the proxy URL [%v]: %w", config.Proxy, err)
	}
	proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
	if err != nil {
		return fmt.Errorf("unable to use the proxy: %w", err)
	}
	proxy.xTransport.proxyDialer = &proxyDialer
	proxy.xTransport.mainProto = "tcp"
	return nil
}

// configureTLSKeyLog enables TLS key logging if requested.
func configureTLSKeyLog(proxy *Proxy, config *Config) error {
	if len(config.TLSKeyLogFile) == 0 {
		return nil
	}
	f, err := os.OpenFile(config.TLSKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		// preserve existing behavior
		dlog.Fatalf("Unable to create key log file [%s]: [%s]", config.TLSKeyLogFile, err)
	}
	dlog.Warnf("TLS key log file [%s] enabled", config.TLSKeyLogFile)
	proxy.xTransport.keyLogWriter = f
	proxy.xTransport.rebuildTransport()
	return nil
}

// configureXTransport configures the XTransport.
// Refactoring only: behavior is preserved, but configuration is split into testable helpers.
func configureXTransport(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}

	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsPreferRSA = config.TLSPreferRSA
	proxy.xTransport.http3 = config.HTTP3
	proxy.xTransport.http3Probe = config.HTTP3Probe

	proxy.xTransport.useIPv4 = config.SourceIPv4
	proxy.xTransport.useIPv6 = config.SourceIPv6
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second

	if err := configureBootstrapResolvers(proxy, config); err != nil {
		return err
	}
	if err := configureHTTPProxy(proxy, config); err != nil {
		return err
	}
	if err := configureProxyDialer(proxy, config); err != nil {
		return err
	}

	proxy.xTransport.rebuildTransport()

	if err := configureTLSKeyLog(proxy, config); err != nil {
		return err
	}
	return nil
}

// configureDoHClientAuth configures DoH client authentication.
func configureDoHClientAuth(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.DoHClientX509AuthLegacy.Creds != nil {
		return errors.New("[tls_client_auth] has been renamed to [doh_client_x509_auth] - Update your config file")
	}

	dohClientCreds := config.DoHClientX509Auth.Creds
	if len(dohClientCreds) == 0 {
		return nil
	}
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
	return nil
}

// configureServerParams configures server parameters.
func configureServerParams(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.blockedQueryResponse = config.BlockedQueryResponse
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients

	proxy.timeoutLoadReduction = config.TimeoutLoadReduction
	if proxy.timeoutLoadReduction < 0.0 || proxy.timeoutLoadReduction > 1.0 {
		dlog.Warnf("timeout_load_reduction must be between 0.0 and 1.0, using default 0.75")
		proxy.timeoutLoadReduction = 0.75
	}

	proxy.xTransport.mainProto = "udp"
	if config.ForceTCP {
		proxy.xTransport.mainProto = "tcp"
	}

	proxy.certRefreshConcurrency = Max(1, config.CertRefreshConcurrency)
	proxy.certRefreshDelay = time.Duration(Max(60, config.CertRefreshDelay)) * time.Minute
	proxy.certRefreshDelayAfterFailure = 10 * time.Second
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	proxy.monitoringUI = config.MonitoringUI
}

// configureLoadBalancing configures load balancing strategy.
func configureLoadBalancing(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	lbStrategy := LBStrategy(DefaultLBStrategy)
	switch lbStrategyStr := strings.ToLower(config.LBStrategy); lbStrategyStr {
	case "":
		// default - WP2 is now the default strategy
		dlog.Noticef("Using default Weighted Power of Two (WP2) load balancing strategy")
	case "p2":
		lbStrategy = LBStrategyP2{}
	case "ph":
		lbStrategy = LBStrategyPH{}
	case "fastest":
		// kept for backward compatibility
		fallthrough
	case "first":
		lbStrategy = LBStrategyFirst{}
	case "random":
		lbStrategy = LBStrategyRandom{}
	case "wp2":
		lbStrategy = LBStrategyWP2{}
	default:
		if after, ok := strings.CutPrefix(lbStrategyStr, "p"); ok {
			n, err := strconv.ParseInt(after, 10, 32)
			if err != nil || n <= 0 {
				dlog.Warnf("Invalid load balancing strategy: [%s]", config.LBStrategy)
			} else {
				lbStrategy = LBStrategyPN{n: int(n)}
			}
		} else {
			dlog.Warnf("Unknown load balancing strategy: [%s]", config.LBStrategy)
		}
	}
	proxy.serversInfo.lbStrategy = lbStrategy
	proxy.serversInfo.lbEstimator = config.LBEstimator
}

// configurePlugins configures DNS plugins.
func configurePlugins(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}

	proxy.listenAddresses = config.ListenAddresses
	proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses

	if len(config.LocalDoH.Path) > 0 && config.LocalDoH.Path[0] != '/' {
		dlog.Fatalf("local DoH: [%s] cannot be a valid URL path. Read the documentation", config.LocalDoH.Path)
	}
	proxy.localDoHPath = config.LocalDoH.Path
	proxy.localDoHCertFile = config.LocalDoH.CertFile
	proxy.localDoHCertKeyFile = config.LocalDoH.CertKeyFile

	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.pluginBlockUnqualified = config.BlockUnqualified
	proxy.pluginBlockUndelegated = config.BlockUndelegated

	proxy.cache = config.Cache
	proxy.cacheSize = config.CacheSize

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

	proxy.queryMeta = config.QueryMeta
}

func configureEDNSClientSubnet(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.EDNSClientSubnet) == 0 {
		return nil
	}

	subnets := make([]*net.IPNet, 0, len(config.EDNSClientSubnet))
	for _, cidr := range config.EDNSClientSubnet {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid EDNS-client-subnet CIDR: [%v]", cidr)
		}
		subnets = append(subnets, ipnet)
	}
	proxy.ednsClientSubnets = subnets
	return nil
}

func configureQueryLog(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.QueryLog.Format = normalizeFormat(config.QueryLog.Format, "tsv")
	if err := validateFormat(config.QueryLog.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.queryLogFile = config.QueryLog.File
	proxy.queryLogFormat = config.QueryLog.Format
	proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes
	return nil
}

func configureNXLog(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.NxLog.Format = normalizeFormat(config.NxLog.Format, "tsv")
	if err := validateFormat(config.NxLog.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.nxLogFile = config.NxLog.File
	proxy.nxLogFormat = config.NxLog.Format
	return nil
}

func configureBlockedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.BlockName.File) > 0 && len(config.BlockNameLegacy.File) > 0 {
		return errors.New("Don't specify both [blocked_names] and [blacklist] sections - Update your config file")
	}
	if len(config.BlockNameLegacy.File) > 0 {
		dlog.Notice("Use of [blacklist] is deprecated - Update your config file")
		config.BlockName.File = config.BlockNameLegacy.File
		config.BlockName.Format = config.BlockNameLegacy.Format
		config.BlockName.LogFile = config.BlockNameLegacy.LogFile
	}
	config.BlockName.Format = normalizeFormat(config.BlockName.Format, "tsv")
	if err := validateFormat(config.BlockName.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.blockNameFile = config.BlockName.File
	proxy.blockNameFormat = config.BlockName.Format
	proxy.blockNameLogFile = config.BlockName.LogFile
	return nil
}

func configureAllowedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.AllowedName.File) > 0 && len(config.WhitelistNameLegacy.File) > 0 {
		return errors.New("Don't specify both [whitelist] and [allowed_names] sections - Update your config file")
	}
	if len(config.WhitelistNameLegacy.File) > 0 {
		dlog.Notice("Use of [whitelist] is deprecated - Update your config file")
		config.AllowedName.File = config.WhitelistNameLegacy.File
		config.AllowedName.Format = config.WhitelistNameLegacy.Format
		config.AllowedName.LogFile = config.WhitelistNameLegacy.LogFile
	}
	config.AllowedName.Format = normalizeFormat(config.AllowedName.Format, "tsv")
	if err := validateFormat(config.AllowedName.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.allowNameFile = config.AllowedName.File
	proxy.allowNameFormat = config.AllowedName.Format
	proxy.allowNameLogFile = config.AllowedName.LogFile
	return nil
}

func configureBlockedIPs(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.BlockIP.File) > 0 && len(config.BlockIPLegacy.File) > 0 {
		return errors.New("Don't specify both [blocked_ips] and [ip_blacklist] sections - Update your config file")
	}
	if len(config.BlockIPLegacy.File) > 0 {
		dlog.Notice("Use of [ip_blacklist] is deprecated - Update your config file")
		config.BlockIP.File = config.BlockIPLegacy.File
		config.BlockIP.Format = config.BlockIPLegacy.Format
		config.BlockIP.LogFile = config.BlockIPLegacy.LogFile
	}
	config.BlockIP.Format = normalizeFormat(config.BlockIP.Format, "tsv")
	if err := validateFormat(config.BlockIP.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.blockIPFile = config.BlockIP.File
	proxy.blockIPFormat = config.BlockIP.Format
	proxy.blockIPLogFile = config.BlockIP.LogFile
	return nil
}

func configureAllowedIPs(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.AllowIP.Format = normalizeFormat(config.AllowIP.Format, "tsv")
	if err := validateFormat(config.AllowIP.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.allowedIPFile = config.AllowIP.File
	proxy.allowedIPFormat = config.AllowIP.Format
	proxy.allowedIPLogFile = config.AllowIP.LogFile
	return nil
}

func configureAdditionalFiles(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.forwardFile = config.ForwardFile
	proxy.cloakFile = config.CloakFile
	proxy.captivePortalMapFile = config.CaptivePortals.MapFile
}

func configureWeeklyRanges(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.allWeeklyRanges = allWeeklyRanges
	return nil
}

// configureAnonymizedDNS configures anonymized DNS.
func configureAnonymizedDNS(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string, len(configRoutes))
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.routes = &routes
	}
	proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
	proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
}

// configureSourceRestrictions configures server source restrictions.
func configureSourceRestrictions(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if proxy == nil || config == nil {
		return
	}

	if flags != nil && flagEnabled(flags.ListAll) {
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

// determineNetprobeAddress determines the address to use for network probing.
func determineNetprobeAddress(flags *ConfigFlags, config *Config) (string, int) {
	netprobeTimeout := config.NetprobeTimeout
	if flags != nil && flags.NetprobeTimeoutOverride != nil {
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

// initializeNetworking initializes networking.
func initializeNetworking(proxy *Proxy, flags *ConfigFlags, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if isCommandMode(proxy, flags) {
		return nil
	}

	netprobeAddress, netprobeTimeout := determineNetprobeAddress(flags, config)
	if err := NetProbe(proxy, netprobeAddress, netprobeTimeout); err != nil {
		return err
	}

	for _, listenAddrStr := range proxy.listenAddresses {
		proxy.addDNSListener(listenAddrStr)
	}
	for _, listenAddrStr := range proxy.localDoHListenAddresses {
		proxy.addLocalDoHListener(listenAddrStr)
	}
	return proxy.addSystemDListeners()
}
