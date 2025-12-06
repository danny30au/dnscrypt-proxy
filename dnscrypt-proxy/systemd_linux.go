//go:build !android

package main

import (
    "fmt"
    "net"
    "os"
    "slices"

    "github.com/coreos/go-systemd/activation"
    "github.com/jedisct1/dlog"
)

func (proxy *Proxy) addSystemDListeners() error {
    files := activation.Files(true)

    if len(files) > 0 {
        if len(proxy.userName) > 0 || proxy.child {
            dlog.Fatal(
                "Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.",
            )
        }
        dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
        proxy.listenAddresses = make([]string, 0, len(files)) // Pre-allocate capacity
    }

    for i, file := range files {
        if err := proxy.processSystemdSocket(i, file); err != nil {
            dlog.Warnf("Failed to process systemd socket #%d (%s): %v", i, file.Name(), err)
        }
        file.Close() // Close immediately instead of defer
    }

    return nil
}

func (proxy *Proxy) processSystemdSocket(index int, file *os.File) error {
    var listenAddress string

    if listener, err := net.FileListener(file); err == nil {
        // Safe type assertion with comma-ok
        tcpListener, ok := listener.(*net.TCPListener)
        if !ok {
            return fmt.Errorf("listener is not a TCP listener, got %T", listener)
        }
        proxy.registerTCPListener(tcpListener)
        listenAddress = listener.Addr().String()
        dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", index, file.Name(), listenAddress)
    } else if pc, err := net.FilePacketConn(file); err == nil {
        // Safe type assertion with comma-ok
        udpConn, ok := pc.(*net.UDPConn)
        if !ok {
            return fmt.Errorf("packet connection is not UDP, got %T", pc)
        }
        proxy.registerUDPListener(udpConn)
        listenAddress = pc.LocalAddr().String()
        dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", index, file.Name(), listenAddress)
    } else {
        return fmt.Errorf("could not create listener or packet connection: %w", err)
    }

    if len(listenAddress) > 0 && !slices.Contains(proxy.listenAddresses, listenAddress) {
        proxy.listenAddresses = append(proxy.listenAddresses, listenAddress)
    }

    return nil
}
