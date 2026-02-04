//go:build !android

package main

import (
"fmt"
"net"
"slices"
"syscall"

"github.com/coreos/go-systemd/activation"
"github.com/jedisct1/dlog"
)

func (proxy *Proxy) addSystemDListeners() error {
files := activation.Files(true)
numFiles := len(files)

if numFiles > 0 {
if len(proxy.userName) > 0 || proxy.child {
dlog.Fatal(
"Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.",
)
}
dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
proxy.listenAddresses = make([]string, 0, numFiles)
}

successCount := 0

for i, file := range files {
fd := int(file.Fd())
soType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
if err != nil {
dlog.Warnf("Failed to inspect systemd socket #%d: %v", i, err)
file.Close()
continue
}

var listenAddress string
var regErr error

switch soType {
case syscall.SOCK_STREAM:
if listener, err := net.FileListener(file); err == nil {
if tcpListener, ok := listener.(*net.TCPListener); ok {
proxy.registerTCPListener(tcpListener)
listenAddress = tcpListener.Addr().String()
dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a stream but not TCP (likely Unix socket). Skipping.", i)
listener.Close()
}
} else {
regErr = err
}

case syscall.SOCK_DGRAM:
if pc, err := net.FilePacketConn(file); err == nil {
if udpConn, ok := pc.(*net.UDPConn); ok {
proxy.registerUDPListener(udpConn)
listenAddress = udpConn.LocalAddr().String()
dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a datagram but not UDP. Skipping.", i)
pc.Close()
}
} else {
regErr = err
}

default:
dlog.Warnf("Systemd socket #%d has unsupported socket type: %d", i, soType)
}

if regErr != nil {
dlog.Warnf("Failed to create listener for systemd socket #%d: %v", i, regErr)
}

if len(listenAddress) > 0 {
if !slices.Contains(proxy.listenAddresses, listenAddress) {
proxy.listenAddresses = append(proxy.listenAddresses, listenAddress)
}
successCount++
}

file.Close()
}

if numFiles > 0 && successCount == 0 {
return fmt.Errorf("failed to register any systemd sockets (%d provided)", numFiles)
}

return nil
}
