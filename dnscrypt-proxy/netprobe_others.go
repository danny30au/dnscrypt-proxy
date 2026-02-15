//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

const netProbeSleep = 1 * time.Second

func NetProbe(proxy *Proxy, address string, timeout int) error {
	if proxy == nil {
		return errors.New("proxy is nil")
	}
	if address == "" || timeout == 0 {
		return nil
	}

	// ColdStart listeners are best-effort; netprobe should still run if ColdStart fails.
	if captivePortalHandler, err := ColdStart(proxy); err == nil {
		if captivePortalHandler != nil {
			defer captivePortalHandler.Stop()
		}
	} else {
		dlog.Critical(err)
	}

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	// timeout semantics in config:
	// - 0 means disabled (handled above)
	// - <0 means "max" (historical behavior)
	// - >0 is a number of seconds, capped by MaxTimeout
	retries := timeout
	if retries < 0 {
		retries = MaxTimeout
	} else {
		retries = Min(MaxTimeout, retries)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(retries)*netProbeSleep)
	defer cancel()

	retried := false
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				dlog.Error("Timeout while waiting for network connectivity")
				return nil
			}
			return nil
		default:
		}

		pc, err := net.DialTimeout("udp", remoteUDPAddr.String(), proxy.timeout)
		if err != nil {
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			t := time.NewTimer(netProbeSleep)
			select {
			case <-ctx.Done():
				t.Stop()
				continue
			case <-t.C:
			}
			continue
		}
		_ = pc.Close()
		dlog.Notice("Network connectivity detected")
		return nil
	}
}
