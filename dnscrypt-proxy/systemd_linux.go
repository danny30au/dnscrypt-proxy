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
var tcpCount, udpCount, failCount int

for i, file := range files {
defer file.Close()

fd := int(file.Fd())

// Verify non-blocking mode (systemd should set this via NonBlocking=true)
if flags, err := syscall.FcntlInt(uintptr(fd), syscall.F_GETFL, 0); err == nil {
if (flags & syscall.O_NONBLOCK) == 0 {
dlog.Warnf("Systemd socket #%d is blocking (expected non-blocking)", i)
}
}

soType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
if err != nil {
dlog.Warnf("Failed to inspect systemd socket #%d: %v", i, err)
failCount++
file.Close()
continue
}

var listenAddress string
var regErr error

switch soType {
case syscall.SOCK_STREAM:
if listener, err := net.FileListener(file); err == nil {
if tcpListener, ok := listener.(*net.TCPListener); ok {
// Enable TCP_NODELAY for low-latency DNS-over-TCP responses
if err := tcpListener.SetNoDelay(true); err != nil {
dlog.Warnf("Failed to set TCP_NODELAY on socket #%d: %v", i, err)
}

proxy.registerTCPListener(tcpListener)
listenAddress = tcpListener.Addr().String()
tcpCount++
dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a stream but not TCP (likely Unix socket). Skipping.", i)
listener.Close()
failCount++
}
} else {
regErr = err
}

case syscall.SOCK_DGRAM:
if pc, err := net.FilePacketConn(file); err == nil {
if udpConn, ok := pc.(*net.UDPConn); ok {
// Optimize UDP buffers for DNS workloads (typical query size 512-4096 bytes)
if err := udpConn.SetReadBuffer(65536); err != nil {
dlog.Warnf("Failed to set read buffer on socket #%d: %v", i, err)
}
if err := udpConn.SetWriteBuffer(32768); err != nil {
dlog.Warnf("Failed to set write buffer on socket #%d: %v", i, err)
}

proxy.registerUDPListener(udpConn)
listenAddress = udpConn.LocalAddr().String()
udpCount++
dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a datagram but not UDP. Skipping.", i)
pc.Close()
failCount++
}
} else {
regErr = err
}

default:
dlog.Warnf("Systemd socket #%d has unsupported socket type: %d", i, soType)
failCount++
}

if regErr != nil {
dlog.Warnf("Failed to create listener for systemd socket #%d: %v", i, regErr)
failCount++
}

if len(listenAddress) > 0 {
if !slices.Contains(proxy.listenAddresses, listenAddress) {
proxy.listenAddresses = append(proxy.listenAddresses, listenAddress)
}
successCount++
}

file.Close()
}

// Log activation summary for operational visibility
if numFiles > 0 {
dlog.Noticef("Systemd socket activation summary: %d TCP, %d UDP, %d failed out of %d total",
tcpCount, udpCount, failCount, numFiles)
}

if numFiles > 0 && successCount == 0 {
return fmt.Errorf("failed to register any systemd sockets (%d provided)", numFiles)
}

return nil
}
