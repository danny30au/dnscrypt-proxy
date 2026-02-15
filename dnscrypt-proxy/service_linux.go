//go:build !android

package main

import (
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

const sdNotifyStatus = "STATUS="

// ServiceManagerStartNotify sends a notification that the service is starting.
func ServiceManagerStartNotify() error {
	if _, err := daemon.SdNotify(false, sdNotifyStatus+"Starting..."); err != nil {
		return fmt.Errorf("systemd start notification failed: %w", err)
	}
	return nil
}

// ServiceManagerReadyNotify sends a notification that the service is ready.
func ServiceManagerReadyNotify() error {
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady+"\n"+sdNotifyStatus+"Ready"); err != nil {
		return fmt.Errorf("systemd ready notification failed: %w", err)
	}
	return systemDWatchdog()
}

// systemDWatchdog initiates the systemd watchdog heartbeats.
func systemDWatchdog() error {
	watchdogDelay, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		return fmt.Errorf("failed to check systemd watchdog status: %w", err)
	}
	if watchdogDelay == 0 {
		return nil
	}

	// Send watchdog notifications more frequently than the timeout (1/3 of the delay).
	refreshInterval := watchdogDelay / 3

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				// Log or handle error if needed, but don't exit the heartbeat loop.
				continue
			}
		}
	}()

	return nil
}
