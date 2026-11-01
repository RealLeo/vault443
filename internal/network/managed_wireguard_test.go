package network

import (
	"encoding/json"
	"testing"
)

func TestWorkUplinkFingerprintTracksActualUnderlayOnly(t *testing.T) {
	var link Link
	if err := json.Unmarshal([]byte(`{"ifindex":2,"ifname":"eth0","mtu":1500,"addr_info":[{"family":"inet","local":"192.0.2.2","prefixlen":24},{"family":"inet6","local":"2001:db8::2","prefixlen":64}]}`), &link); err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Links: []Link{link}, Routes: []Route{{Destination: "default", Device: "eth0", Gateway: "192.0.2.1", Family: 4, Table: json.RawMessage("254")}, {Destination: "default", Device: "eth0", Gateway: "2001:db8::1", Family: 6, Table: json.RawMessage("254")}}}
	base := WorkUplinkFingerprint(s)
	s.Routes = append(s.Routes, Route{Destination: "default", Device: "eth0", Gateway: "2001:db8::99", Family: 6, Table: json.RawMessage("52783")})
	if WorkUplinkFingerprint(s) != base {
		t.Fatal("owned routing transaction forced peer rekey")
	}
	s.Links[0].Addresses[0], s.Links[0].Addresses[1] = s.Links[0].Addresses[1], s.Links[0].Addresses[0]
	if WorkUplinkFingerprint(s) != base {
		t.Fatal("address order changed fingerprint")
	}
	s.Links[0].Addresses[1].Local = "192.0.2.3"
	if WorkUplinkFingerprint(s) == base {
		t.Fatal("DHCP address change ignored")
	}
	s.Links[0].Addresses[1].Local = "192.0.2.2"
	s.Links[0].Index++
	if WorkUplinkFingerprint(s) == base {
		t.Fatal("recreated interface ignored")
	}
	s.Links[0].Index--
	s.Routes[1].Gateway = "2001:db8::3"
	if WorkUplinkFingerprint(s) == base {
		t.Fatal("IPv6 gateway change ignored")
	}
}

func TestManagedWireGuardEndpointSnapshotsAreIndependent(t *testing.T) {
	old := managedPolicy.Load()
	defer managedPolicy.Store(old)
	managedPolicy.Store(&ManagedPolicy{Tunnels: []ManagedTunnel{{ID: "wg-test", Kind: "wireguard", Endpoints: []Endpoint{{Address: "192.0.2.1", Port: 51820, Protocol: "udp"}}}}})
	copy := CurrentManagedPolicy()
	copy.Tunnels[0].Endpoints[0].Address = "203.0.113.1"
	if CurrentManagedPolicy().Tunnels[0].Endpoints[0].Address != "192.0.2.1" {
		t.Fatal("snapshot caller mutated live endpoint exception")
	}
}
