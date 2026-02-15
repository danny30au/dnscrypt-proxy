package main

import (
	"math/rand"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

const (
	inetFamilyIPv4 uint16 = 1
	inetFamilyIPv6 uint16 = 2
)

// PluginECS sets EDNS Client Subnet (ECS) information in outgoing queries.
type PluginECS struct {
	nets []*net.IPNet
}

func (plugin *PluginECS) Name() string {
	return "ecs"
}

func (plugin *PluginECS) Description() string {
	return "Set EDNS-client-subnet information in outgoing queries."
}

func (plugin *PluginECS) Init(proxy *Proxy) error {
	plugin.nets = proxy.ednsClientSubnets
	if len(plugin.nets) == 0 {
		dlog.Warn("ECS plugin enabled, but no EDNS client subnets configured")
		return nil
	}
		dlog.Notice("ECS plugin enabled")
	return nil
}

func (plugin *PluginECS) Drop() error {
	return nil
}

func (plugin *PluginECS) Reload() error {
	return nil
}

func (plugin *PluginECS) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if len(plugin.nets) == 0 {
		return nil
	}

	// If ECS already exists, do nothing.
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.SUBNET); ok {
			return nil
		}
	}

	// Ensure EDNS0 is enabled.
	if msg.UDPSize == 0 {
		msg.UDPSize = uint16(pluginsState.maxPayloadSize)
	}

	ipnet := plugin.nets[rand.Intn(len(plugin.nets))]
	maskBits, addrBits := ipnet.Mask.Size()

	family, addr, ok := ipNetToECSAddress(ipnet, addrBits)
	if !ok {
		return nil
	}

	subnet := &dns.SUBNET{
		Family:  family,
		Netmask: uint8(maskBits),
		Scope:   0,
		Address: addr,
	}
	msg.Pseudo = append(msg.Pseudo, subnet)

	return nil
}

func ipNetToECSAddress(ipnet *net.IPNet, addrBits int) (uint16, netip.Addr, bool) {
	switch addrBits {
	case 32:
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			return 0, netip.Addr{}, false
		}
		return inetFamilyIPv4, netip.AddrFrom4([4]byte(ip4)), true

	case 128:
		ip6 := ipnet.IP.To16()
		if ip6 == nil {
			return 0, netip.Addr{}, false
		}
		return inetFamilyIPv6, netip.AddrFrom16([16]byte(ip6)), true

	default:
		return 0, netip.Addr{}, false
	}
}
