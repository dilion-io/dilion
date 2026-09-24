package auth

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddr(t *testing.T) {
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
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}
