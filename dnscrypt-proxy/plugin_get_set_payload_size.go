package main

import (
	"codeberg.org/miekg/dns"
)

const (
	defaultDNSPayloadSize = 512
	minEDNS0PayloadSize   = 512
)

// PluginGetSetPayloadSize adjusts the maximum payload size advertised in queries sent to upstream servers.
type PluginGetSetPayloadSize struct{}

func (plugin *PluginGetSetPayloadSize) Name() string {
	return "get_set_payload_size"
}

func (plugin *PluginGetSetPayloadSize) Description() string {
	return "Adjusts the maximum payload size advertised in queries sent to upstream servers."
}

func (plugin *PluginGetSetPayloadSize) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Drop() error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Reload() error {
	return nil
}

// Eval adjusts DNS payload sizes based on client capabilities and server limits.
func (plugin *PluginGetSetPayloadSize) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// Start with standard DNS payload size.
	pluginsState.originalMaxPayloadSize = defaultDNSPayloadSize - ResponseOverhead

	// Preserve DNSSEC flag from the original query.
	dnssec := msg.Security

	// If client advertised EDNS0, extract their maximum payload size.
	if msg.UDPSize > 0 {
		clientUDPSize := int(msg.UDPSize)
		pluginsState.maxUnencryptedUDPSafePayloadSize = clientUDPSize

		// Adjust original max payload to account for client's advertised size.
		pluginsState.originalMaxPayloadSize = Max(
			clientUDPSize-ResponseOverhead,
			pluginsState.originalMaxPayloadSize,
		)
	}

	// Store DNSSEC preference.
	pluginsState.dnssec = dnssec

	// Calculate the final max payload size: bounded by protocol limit and previous state.
	pluginsState.maxPayloadSize = Min(
		MaxDNSUDPPacketSize-ResponseOverhead,
		Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize),
	)

	// Only set EDNS0 if payload exceeds standard DNS limit.
	if pluginsState.maxPayloadSize > minEDNS0PayloadSize {
		msg.UDPSize = uint16(pluginsState.maxPayloadSize)
		msg.Security = dnssec
	}

	return nil
}
