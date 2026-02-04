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

const (
// SO_REUSEPORT may not be defined in syscall package on all platforms
SO_REUSEPORT = 0xf
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

// Check file descriptor limits for operational visibility
var rlimit syscall.Rlimit
if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
dlog.Noticef("File descriptor limits: current=%d, max=%d", rlimit.Cur, rlimit.Max)
if numFiles > int(rlimit.Cur/4) {
dlog.Warnf("High socket count (%d) relative to FD limit (%d)", numFiles, rlimit.Cur)
}
}

successCount := 0
var tcpCount, udpCount, failCount, socketOptErrors int

for i, file := range files {
defer file.Close()

fd := int(file.Fd())
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
// Configure all TCP socket options in a single control block
if rawConn, err := tcpListener.SyscallConn(); err == nil {
ctrlErr := rawConn.Control(func(fd uintptr) {
fdInt := int(fd)

// Verify and enable SO_REUSEADDR
if val, err := syscall.GetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_REUSEADDR); err != nil || val == 0 {
if err := syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
dlog.Warnf("Failed to set SO_REUSEADDR on socket #%d: %v", i, err)
socketOptErrors++
}
}

// Check if SO_REUSEPORT is enabled (multi-instance load balancing)
if val, err := syscall.GetsockoptInt(fdInt, syscall.SOL_SOCKET, SO_REUSEPORT); err == nil && val != 0 {
dlog.Noticef("Socket #%d has SO_REUSEPORT enabled (multi-instance mode)", i)
}

// Enable TCP_NODELAY for low-latency DNS-over-TCP responses
if err := syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
dlog.Warnf("Failed to set TCP_NODELAY on socket #%d: %v", i, err)
socketOptErrors++
}

// Configure TCP keepalive to detect dead connections
if err := syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
dlog.Warnf("Failed to enable TCP keepalive on socket #%d: %v", i, err)
socketOptErrors++
} else {
// Start keepalive after 60 seconds idle
syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 60)
// Send probes every 10 seconds
syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 10)
// Drop connection after 3 failed probes
syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
}
})

if ctrlErr != nil {
dlog.Warnf("Failed to configure socket options on #%d: %v", i, ctrlErr)
}
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
socketOptErrors++
}
if err := udpConn.SetWriteBuffer(32768); err != nil {
dlog.Warnf("Failed to set write buffer on socket #%d: %v", i, err)
socketOptErrors++
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
if socketOptErrors > 0 {
dlog.Warnf("Socket option configuration errors: %d", socketOptErrors)
}
}

if numFiles > 0 && successCount == 0 {
return fmt.Errorf("failed to register any systemd sockets (%d provided)", numFiles)
}

return nil
}
