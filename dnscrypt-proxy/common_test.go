package main

import (
"net"
"testing"
)

var (
udpUDPAddr = &net.UDPAddr{
IP:   net.ParseIP("192.168.1.1"),
Port: 53,
}
udpNetAddr net.Addr = udpUDPAddr

tcpTCPAddr = &net.TCPAddr{
IP:   net.ParseIP("10.0.0.1"),
Port: 53,
}
tcpNetAddr net.Addr = tcpTCPAddr
)

func TestExtractClientIPStr(t *testing.T) {
tests := []struct {
name         string
pluginsState *PluginsState
wantIP       string
wantOK       bool
}{
{
name: "nil clientAddr should return empty",
pluginsState: &PluginsState{
clientProto: "tcp",
clientAddr:  nil,
},
wantIP: "",
wantOK: false,
},
{
name: "valid UDP address",
pluginsState: &PluginsState{
clientProto: "udp",
clientAddr:  &udpNetAddr,
},
wantIP: "192.168.1.1",
wantOK: true,
},
{
name: "valid TCP address",
pluginsState: &PluginsState{
clientProto: "tcp",
clientAddr:  &tcpNetAddr,
},
wantIP: "10.0.0.1",
wantOK: true,
},
{
name: "unknown protocol",
pluginsState: &PluginsState{
clientProto: "unknown",
clientAddr:  &tcpNetAddr,
},
wantIP: "",
wantOK: false,
},
}

for _, tt := range tests {
tt := tt
t.Run(tt.name, func(t *testing.T) {
t.Parallel()
gotIP, gotOK := ExtractClientIPStr(tt.pluginsState)
if gotIP != tt.wantIP {
t.Errorf("ExtractClientIPStr() IP = %v, want %v", gotIP, tt.wantIP)
}
if gotOK != tt.wantOK {
t.Errorf("ExtractClientIPStr() OK = %v, want %v", gotOK, tt.wantOK)
}
})
}
}
