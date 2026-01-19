package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "runtime"
    "runtime/debug"
    "syscall"

    "github.com/jedisct1/dlog"
    "github.com/kardianos/service"
)

const (
    AppVersion            = "2.1.15"
    DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
    proxy *Proxy
    flags *ConfigFlags
}

func main() {
    if runtime.GOOS == "linux" {
        _ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, -10)
    }

    tzErr := TimezoneSetup()
    dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")
    if tzErr != nil {
        dlog.Warnf("Timezone setup failed: [%v]", tzErr)
    }

    // Optimization: Disable profiling and set memory floor for Go 1.26
    runtime.MemProfileRate = 0
    debug.SetMemoryLimit(128 * 1024 * 1024)

    pwd, err := os.Getwd()
    if err != nil {
        dlog.Fatal("Unable to find the path to the current directory")
    }

    svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
    version := flag.Bool("version", false, "print current proxy version")
    flags := ConfigFlags{}
    flags.Resolve = flag.String("resolve", "", "resolve a DNS name (string can be <name> or <name>,<resolver address>)")
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
        return
    }

    // Fast path: use signal.NotifyContext for cleaner lifecycle management
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    if svc != nil {
        if err := svc.Run(); err != nil {
            dlog.Fatal(err)
        }
    } else {
        go app.AppMain(ctx)
        <-ctx.Done()
        dlog.Notice("Quit signal received...")
    }
}

func (app *App) Start(service service.Service) error {
    go app.AppMain(context.Background())
    return nil
}

func (app *App) AppMain(ctx context.Context) {
    if err := ConfigLoad(app.proxy, app.flags); err != nil {
        dlog.Fatal(err)
    }
    if err := PidFileCreate(); err != nil {
        dlog.Errorf("Unable to create the PID file: [%v]", err)
    }
    if err := app.proxy.InitPluginsGlobals(); err != nil {
        dlog.Fatal(err)
    }
    if err := app.proxy.InitHotReload(); err != nil {
        dlog.Warnf("Failed to initialize hot-reloading: %v", err)
    }

    // The proxy should be initialized with the tuned HTTP/2 and socket settings
    app.proxy.StartProxy()

    // Manual GC calls removed to prevent Stop-The-World latency spikes
}

func (app *App) Stop(service service.Service) error {
    if app.proxy != nil && app.proxy.udpConnPool != nil {
        app.proxy.udpConnPool.Close()
    }
    if err := PidFileRemove(); err != nil {
        dlog.Warnf("Failed to remove the PID file: [%v]", err)
    }
    dlog.Notice("Stopped.")
    return nil
}
