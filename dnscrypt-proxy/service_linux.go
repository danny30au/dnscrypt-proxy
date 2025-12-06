//go:build !android

package main

import (
    "context"
    "fmt"
    "time"

    "github.com/coreos/go-systemd/daemon"
)

const SdNotifyStatus = "STATUS="

var (
    watchdogCtx    context.Context
    watchdogCancel context.CancelFunc
)

func ServiceManagerStartNotify() error {
    if _, err := daemon.SdNotify(false, SdNotifyStatus+"Starting..."); err != nil {
        return fmt.Errorf("failed to notify systemd: %w", err)
    }
    return nil
}

func ServiceManagerReadyNotify() error {
    sent, err := daemon.SdNotify(false, daemon.SdNotifyReady+"
"+SdNotifyStatus+"Ready")
    if err != nil {
        return fmt.Errorf("failed to notify systemd: %w", err)
    }
    if !sent {
        // Not running under systemd supervision
        return nil
    }
    return systemDWatchdog()
}

func systemDWatchdog() error {
    watchdogFailureDelay, err := daemon.SdWatchdogEnabled(false)
    if err != nil || watchdogFailureDelay == 0 {
        return err
    }
    refreshInterval := watchdogFailureDelay / 3
    
    watchdogCtx, watchdogCancel = context.WithCancel(context.Background())
    
    go func() {
        ticker := time.NewTicker(refreshInterval)
        defer ticker.Stop()
        
        for {
            select {
            case <-watchdogCtx.Done():
                return
            case <-ticker.C:
                daemon.SdNotify(false, daemon.SdNotifyWatchdog)
            }
        }
    }()
    return nil
}

// ServiceManagerStopNotify stops the watchdog and notifies systemd of shutdown
func ServiceManagerStopNotify() error {
    if watchdogCancel != nil {
        watchdogCancel()
    }
    if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping+"
"+SdNotifyStatus+"Stopping..."); err != nil {
        return fmt.Errorf("failed to notify systemd: %w", err)
    }
    return nil
}
