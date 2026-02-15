package main

import (
	"time"

	"github.com/jedisct1/dlog"
)

// PluginReloader defines the interface for plugins that support hot-reloading.
type PluginReloader interface {
	Plugin
	Reload() error
	SetConfigWatcher(*ConfigWatcher)
	ConfigFile() string
}

// InitHotReload sets up hot-reloading for configuration files.
func (proxy *Proxy) InitHotReload() error {
	// Early exit if neither hot reload nor SIGHUP is available.
	if !proxy.enableHotReload && !HasSIGHUP {
		dlog.Notice("Hot reload is disabled")
		return nil
	}

	plugins := proxy.gatherPlugins()
	setupSignalHandler(proxy, plugins)

	if !proxy.enableHotReload {
		dlog.Notice("Hot reload is disabled (SIGHUP handler only)")
		return nil
	}

	dlog.Notice("Hot reload is enabled")

	configWatcher := NewConfigWatcher(time.Second)
	proxy.registerPluginWatchers(configWatcher, plugins)

	return nil
}

// gatherPlugins collects all plugins from query and response plugin lists.
func (proxy *Proxy) gatherPlugins() []Plugin {
	proxy.pluginsGlobals.RLock()
	defer proxy.pluginsGlobals.RUnlock()

	var plugins []Plugin

	if proxy.pluginsGlobals.queryPlugins != nil {
		plugins = append(plugins, *proxy.pluginsGlobals.queryPlugins...)
	}

	if proxy.pluginsGlobals.responsePlugins != nil {
		plugins = append(plugins, *proxy.pluginsGlobals.responsePlugins...)
	}

	return plugins
}

// registerPluginWatchers registers file watches for plugins that support hot-reloading.
func (proxy *Proxy) registerPluginWatchers(configWatcher *ConfigWatcher, plugins []Plugin) {
	for _, plugin := range plugins {
		reloadable, ok := plugin.(PluginReloader)
		if !ok {
			continue
		}

		configFile := reloadable.ConfigFile()
		if configFile == "" {
			continue
		}

		if err := configWatcher.AddFile(configFile, reloadable.Reload); err != nil {
			dlog.Warnf("Failed to watch config file for plugin [%s]: %v", plugin.Name(), err)
			continue
		}

		reloadable.SetConfigWatcher(configWatcher)
		dlog.Noticef("Watching config file for plugin [%s]: %s", plugin.Name(), configFile)
	}
}
