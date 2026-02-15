package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

// ReloadablePlugin is an interface for plugins that support hot-reloading.
type ReloadablePlugin interface {
	Plugin
	Reload() error
	PrepareReload() error                    // Prepare new configuration but don't apply it yet
	ApplyReload() error                      // Apply prepared configuration
	CancelReload()                           // Cancel the prepared configuration
	ConfigFile() string                      // Return path to the configuration file
	SetConfigWatcher(watcher *ConfigWatcher) // Set the config watcher
}

// ReloadSafeguard ensures thread-safe configuration reloading.
type ReloadSafeguard struct {
	isReloading     atomic.Bool
	reloadMu        sync.Mutex
	configMu        sync.RWMutex
	activeTimestamp atomic.Pointer[time.Time]
}

// NewReloadSafeguard creates a initialized ReloadSafeguard.
func NewReloadSafeguard() *ReloadSafeguard {
	rs := &ReloadSafeguard{}
	now := time.Now()
	rs.activeTimestamp.Store(&now)
	return rs
}

// StartReload attempts to initiate a reload operation.
func (rs *ReloadSafeguard) StartReload() bool {
	if rs.isReloading.CompareAndSwap(false, true) {
		rs.reloadMu.Lock()
		return true
	}
	return false
}

// FinishReload completes the reload operation.
func (rs *ReloadSafeguard) FinishReload() {
	rs.isReloading.Store(false)
	rs.reloadMu.Unlock()
}

// AcquireConfigRead acquires a read lock on the active configuration.
func (rs *ReloadSafeguard) AcquireConfigRead() {
	rs.configMu.RLock()
}

// ReleaseConfigRead releases the read lock.
func (rs *ReloadSafeguard) ReleaseConfigRead() {
	rs.configMu.RUnlock()
}

// AcquireConfigWrite acquires a write lock on the active configuration.
func (rs *ReloadSafeguard) AcquireConfigWrite() {
	rs.configMu.Lock()
}

// ReleaseConfigWrite releases the write lock and updates the active timestamp.
func (rs *ReloadSafeguard) ReleaseConfigWrite() {
	now := time.Now()
	rs.activeTimestamp.Store(&now)
	rs.configMu.Unlock()
}

// SafeReload handles the entire reload process with proper locking.
func (rs *ReloadSafeguard) SafeReload(reloadFunc func() error) error {
	if !rs.StartReload() {
		return errors.New("another reload operation is already in progress")
	}
	defer rs.FinishReload()

	rs.AcquireConfigWrite()
	defer rs.ReleaseConfigWrite()

	return reloadFunc()
}

// RegisterPluginForReload registers a plugin for automatic reloading.
func RegisterPluginForReload(plugin ReloadablePlugin, watcher *ConfigWatcher) error {
	configPath := plugin.ConfigFile()
	if configPath == "" {
		return fmt.Errorf("empty configuration path for plugin: %s", plugin.Name())
	}

	reloadFunc := func() error {
		dlog.Noticef("Reloading configuration for plugin [%s]", plugin.Name())

		if err := plugin.PrepareReload(); err != nil {
			dlog.Errorf("Failed to prepare reload for plugin [%s]: %v", plugin.Name(), err)
			plugin.CancelReload()
			return err
		}

		if err := plugin.ApplyReload(); err != nil {
			dlog.Errorf("Failed to apply reload for plugin [%s]: %v", plugin.Name(), err)
			plugin.CancelReload()
			return err
		}

		dlog.Noticef("Successfully reloaded plugin [%s]", plugin.Name())
		return nil
	}

	if err := watcher.AddFile(configPath, reloadFunc); err != nil {
		return fmt.Errorf("failed to watch file [%s]: %w", configPath, err)
	}

	plugin.SetConfigWatcher(watcher)
	return nil
}

// SafeReadTextFile reads a file twice with a delay to ensure it's not being modified.
func SafeReadTextFile(filePath string) (string, error) {
	const stabilizeDelay = 50 * time.Millisecond

	content, err := ReadTextFile(filePath)
	if err != nil {
		return "", err
	}

	time.Sleep(stabilizeDelay)

	content2, err := ReadTextFile(filePath)
	if err != nil {
		return "", err
	}

	if content != content2 {
		return "", errors.New("file appears to be changing during read")
	}

	return content, nil
}

// StandardReloadPattern implements the common reload pattern.
func StandardReloadPattern(pluginName string, reloadFunc func() error) error {
	dlog.Noticef("Reloading configuration for plugin [%s]", pluginName)
	return reloadFunc()
}

// StandardPrepareReloadPattern implements the common prepare-reload pattern.
func StandardPrepareReloadPattern(pluginName, configFile string, prepareFunc func(string) error) error {
	lines, err := SafeReadTextFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file for [%s]: %w", pluginName, err)
	}

	if err := prepareFunc(lines); err != nil {
		return fmt.Errorf("error parsing config for [%s]: %w", pluginName, err)
	}

	return nil
}

// StandardApplyReloadPattern implements the common apply-reload pattern.
func StandardApplyReloadPattern(pluginName string, applyFunc func() error) error {
	if err := applyFunc(); err != nil {
		return fmt.Errorf("error applying config for [%s]: %w", pluginName, err)
	}

	dlog.Noticef("Applied new configuration for plugin [%s]", pluginName)
	return nil
}
