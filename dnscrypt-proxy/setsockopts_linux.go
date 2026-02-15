package main

import (
	"net"

	"github.com/jedisct1/dlog"
	"golang.org/x/sys/unix"
)

// udpListenerConfig returns a ListenConfig with optimized UDP socket options.
func (proxy *Proxy) udpListenerConfig() (*net.ListenConfig, error) {
	return &net.ListenConfig{
		Control: func(_, _ string, c unix.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = setUDPSockOpts(int(fd))
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}, nil
}

// tcpListenerConfig returns a ListenConfig with optimized TCP socket options.
func (proxy *Proxy) tcpListenerConfig() (*net.ListenConfig, error) {
	return &net.ListenConfig{
		Control: func(_, _ string, c unix.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = setTCPSockOpts(int(fd))
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}, nil
}

// setUDPSockOpts applies UDP-specific socket options. Best-effort: logs but doesn't fail on errors.
func setUDPSockOpts(fd int) error {
	// IP_FREEBIND: Allow binding to addresses that don't exist yet.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1); err != nil {
		dlog.Debugf("Failed to set IP_FREEBIND on UDP socket: %v", err)
	}

	// IP_DF: Disable Don't Fragment flag (allow fragmentation).
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_DF, 0); err != nil {
		dlog.Debugf("Failed to set IP_DF on UDP socket: %v", err)
	}

	// IP_TOS: Set Type of Service to CS7 (0x70 = network control).
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, 0x70); err != nil {
		dlog.Debugf("Failed to set IP_TOS on UDP socket: %v", err)
	}

	// IPV6_TCLASS: IPv6 equivalent of TOS.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0x70); err != nil {
		dlog.Debugf("Failed to set IPV6_TCLASS on UDP socket: %v", err)
	}

	// IP_MTU_DISCOVER: Disable Path MTU discovery.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
		dlog.Debugf("Failed to set IP_MTU_DISCOVER on UDP socket: %v", err)
	}

	// SO_RCVBUFFORCE: Set receive buffer size (overrides system limits).
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4096); err != nil {
		// Fall back to SO_RCVBUF if SO_RCVBUFFORCE fails (requires CAP_NET_ADMIN).
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4096); err != nil {
			dlog.Debugf("Failed to set receive buffer on UDP socket: %v", err)
		}
	}

	// SO_SNDBUFFORCE: Set send buffer size (overrides system limits).
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, 4096); err != nil {
		// Fall back to SO_SNDBUF if SO_SNDBUFFORCE fails.
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
			dlog.Debugf("Failed to set send buffer on UDP socket: %v", err)
		}
	}

	return nil
}

// setTCPSockOpts applies TCP-specific socket options. Best-effort: logs but doesn't fail on errors.
func setTCPSockOpts(fd int) error {
	// IP_FREEBIND: Allow binding to addresses that don't exist yet.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1); err != nil {
		dlog.Debugf("Failed to set IP_FREEBIND on TCP socket: %v", err)
	}

	// IP_TOS: Set Type of Service to CS7 (0x70 = network control).
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, 0x70); err != nil {
		dlog.Debugf("Failed to set IP_TOS on TCP socket: %v", err)
	}

	// IPV6_TCLASS: IPv6 equivalent of TOS.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0x70); err != nil {
		dlog.Debugf("Failed to set IPV6_TCLASS on TCP socket: %v", err)
	}

	// TCP_QUICKACK: Enable quick ACK mode (send ACKs immediately).
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1); err != nil {
		dlog.Debugf("Failed to set TCP_QUICKACK on TCP socket: %v", err)
	}

	return nil
}
