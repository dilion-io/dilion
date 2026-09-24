package netguard

import (
	"net/netip"
	"testing"
)

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.215.14":        true,
		"2606:2800:21f:cb07::": true,
		"127.0.0.1":            false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"100.64.0.1":           false, // CGNAT
		"0.0.0.0":              false,
		"::1":                  false,
		"fd00::1":              false,
		"fe80::1":              false,
		"::ffff:127.0.0.1":     false, // IPv4-mapped loopback
		"64:ff9b::a00:1":       false, // NAT64 of 10.0.0.1
		"2002:a00:1::":         false, // 6to4 of 10.0.0.1
		"224.0.0.1":            false,
	} {
		if got := IsPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestParseNetworks(t *testing.T) {
	n := MustParseNetworks(" 10.0.0.0/8, 192.168.1.5 ,::1")
	for addr, want := range map[string]bool{
		"10.9.8.7":        true,
		"192.168.1.5":     true,
		"192.168.1.6":     false,
		"::1":             true,
		"::ffff:10.0.0.1": true,
		"11.0.0.1":        false,
	} {
		if got := n.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
	if !MustParseNetworks("*").Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("* must contain every address")
	}
	if !MustParseNetworks("").Empty() {
		t.Error("a blank list must be empty")
	}
	if _, err := ParseNetworks("10.0.0.0/8,not-an-ip"); err == nil {
		t.Error("an invalid entry was accepted")
	}
}

func TestClientIP(t *testing.T) {
	const xff = "203.0.113.9, 70.41.3.18, 10.0.0.5"
	proxies := MustParseNetworks("10.0.0.0/8")
	for _, tc := range []struct {
		name, remote, xff string
		trusted           Networks
		want              string
	}{
		{"no trust: the peer, whatever the header", "198.51.100.1:443", xff, Networks{}, "198.51.100.1"},
		{"untrusted peer", "198.51.100.1:443", xff, proxies, "198.51.100.1"},
		{"trusted proxy: first untrusted hop from the right", "10.0.0.1:443", xff, proxies, "70.41.3.18"},
		{"trust everything: leftmost", "10.0.0.1:443", xff, MustParseNetworks("*"), "203.0.113.9"},
		{"junk hops are skipped", "10.0.0.1:443", "not-an-ip, 203.0.113.10", proxies, "203.0.113.10"},
		{"no header", "10.0.0.1:443", "", proxies, "10.0.0.1"},
	} {
		if got := ClientIP(tc.remote, tc.xff, tc.trusted); got != tc.want {
			t.Errorf("%s: ClientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}
