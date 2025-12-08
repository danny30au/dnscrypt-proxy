package main

import (
"flag"
"fmt"
"os"
"os/signal"
"runtime"
"syscall"

"github.com/jedisct1/dlog"
"github.com/kardianos/service"
)

const (
AppVersion            = "2.1.14"
DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
quit  chan os.Signal
proxy *Proxy
flags *ConfigFlags
}

func main() {
tzErr := TimezoneSetup()

dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")

if tzErr != nil {
dlog.Warnf("Timezone setup failed: [%v]", tzErr)
}

runtime.MemProfileRate = 0

// Note: Manual seeding of math/rand is removed as Go 1.20+ automatically seeds
// the global random number generator at startup.

pwd, err := os.Getwd()
if err != nil {
dlog.Fatal("Unable to find the path to the current directory")
}

svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
version := flag.Bool("version", false, "print current proxy version")

flags := ConfigFlags{}
flags.Resolve = flag.String("resolve", "", "resolve a DNS name (string can be or ,)")
flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
flags.IncludeRelays = flag.Bool("include-relays", false, "include the list of available relays in the output of -list and -list-all")
flags.JSONOutput = flag.Bool("json", false, "output list as JSON")
flags.Check = flag.Bool("check", false, "check the configuration file and exit")
flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
flags.Child = flag.Bool("child", false, "Invokes program as a child process")
flags.NetprobeTimeoutOverride = flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
flags.ShowCerts = flag.Bool("show-certs", false, "print DoH certificate chain hashes")

flag.Parse()

if *version {
fmt.Println(AppVersion)
os.Exit(0)
}

if fullexecpath, err := os.Executable(); err == nil {
WarnIfMaybeWritableByOtherUsers(fullexecpath)
}

app := &App{
flags: &flags,
}

svcOptions := make(service.KeyValue)
svcOptions["ReloadSignal"] = "HUP"

svcConfig := &service.Config{
Name:             "dnscrypt-proxy",
DisplayName:      "DNSCrypt client proxy",
Description:      "Encrypted/authenticated DNS proxy",
WorkingDirectory: pwd,
Arguments:        []string{"-config", *flags.ConfigFile},
Option:           svcOptions,
}

svc, err := service.New(app, svcConfig)
if err != nil {
svc = nil
dlog.Debug(err)
}

app.proxy = NewProxy()

_ = ServiceManagerStartNotify()

if len(*svcFlag) != 0 {
if svc == nil {
dlog.Fatal("Built-in service installation is not supported on this platform")
}

if err := service.Control(svc, *svcFlag); err != nil {
dlog.Fatal(err)
}

switch *svcFlag {
case "install":
dlog.Notice("Installed as a service. Use `-service start` to start")
case "uninstall":
dlog.Notice("Service uninstalled")
case "start":
dlog.Notice("Service started")
case "stop":
dlog.Notice("Service stopped")
case "restart":
dlog.Notice("Service restarted")
default:
dlog.Noticef("Service command %q executed", *svcFlag)
}
return
}

if svc != nil {
if err := svc.Run(); err != nil {
dlog.Fatal(err)
}
} else {
app.quit = make(chan os.Signal, 1)
signal.Notify(app.quit, os.Interrupt, syscall.SIGTERM)

// Possible to exit while initializing
go app.AppMain()

<-app.quit
dlog.Notice("Quit signal received...")

// Improvements: Ensure PID file is removed even in console mode
if err := PidFileRemove(); err != nil {
dlog.Warnf("Failed to remove the PID file: [%v]", err)
}
}
}

func (app *App) Start(service service.Service) error {
go app.AppMain()
return nil
}

func (app *App) AppMain() {
if err := ConfigLoad(app.proxy, app.flags); err != nil {
dlog.Fatal(err)
}

if err := PidFileCreate(); err != nil {
dlog.Errorf("Unable to create the PID file: [%v]", err)
}

if err := app.proxy.InitPluginsGlobals(); err != nil {
dlog.Fatal(err)
}

// Initialize hot-reloading support
if err := app.proxy.InitHotReload(); err != nil {
dlog.Warnf("Failed to initialize hot-reloading: %v", err)
}

// Optimization: Force GC to clear initialization garbage before entering main loop
runtime.GC()

app.proxy.StartProxy()
}

func (app *App) Stop(service service.Service) error {
if err := PidFileRemove(); err != nil {
dlog.Warnf("Failed to remove the PID file: [%v]", err)
}

dlog.Notice("Stopped.")
return nil
}
