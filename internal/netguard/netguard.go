// Package netguard keeps outbound calls to URLs that instance admins
// configure — webhooks, custom OAuth/OIDC providers, SAML metadata, privacy
// destinations — off the server's own network, and parses the network lists
// (trusted proxies, allowed networks) the operator configures.
//
// The check runs on the address actually dialled, after DNS resolution, so a
// name that resolves to a public address when saved and an internal one later
// (DNS rebinding), or a redirect to an internal URL, is refused too.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// ErrNotPublic is what a guarded dial fails with for an address outside the
// public internet and outside the allowed networks.
var ErrNotPublic = errors.New("address is not public")

// nonPublicPrefixes are the ranges net/netip's predicates do not already
// cover: shared (CGNAT), "this network", IETF protocol assignments,
// benchmarking, reserved, and the IPv6 transition prefixes that can embed an
// IPv4 address of any kind.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
}

// IsPublic reports whether addr is on the public internet.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Networks is a set of addresses given as a comma-separated list of IPs and
// CIDRs, or "*" for every address. The zero value contains nothing.
type Networks struct {
	all      bool
	prefixes []netip.Prefix
}

// ParseNetworks parses "10.0.0.0/8, 192.168.1.5, ::1" or "*". Blank is empty.
func ParseNetworks(spec string) (Networks, error) {
	var n Networks
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
			continue
		case part == "*":
			n.all = true
		case strings.Contains(part, "/"):
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return Networks{}, fmt.Errorf("netguard: %q is not an IP or CIDR", part)
			}
			n.prefixes = append(n.prefixes, p.Masked())
		default:
			a, err := netip.ParseAddr(part)
			if err != nil {
				return Networks{}, fmt.Errorf("netguard: %q is not an IP or CIDR", part)
			}
			n.prefixes = append(n.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return n, nil
}

// MustParseNetworks is ParseNetworks for constants.
func MustParseNetworks(spec string) Networks {
	n, err := ParseNetworks(spec)
	if err != nil {
		panic(err)
	}
	return n
}

// Contains reports whether addr is in the set.
func (n Networks) Contains(addr netip.Addr) bool {
	if n.all {
		return true
	}
	addr = addr.Unmap()
	for _, p := range n.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Empty reports whether the set contains nothing.
func (n Networks) Empty() bool { return !n.all && len(n.prefixes) == 0 }

// Allowed reports whether a guarded call may reach addr: a public address,
// or one in allow.
func Allowed(addr netip.Addr, allow Networks) bool {
	return IsPublic(addr) || allow.Contains(addr)
}

// Control is a net.Dialer Control that refuses addresses Allowed rejects.
func Control(allow Networks) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !Allowed(ap.Addr(), allow) {
			return ErrNotPublic
		}
		return nil
	}
}

// Transport returns a copy of base whose dials are guarded. It ignores
// HTTP_PROXY: through a proxy the dialled address would be the proxy's. A
// base that is not an *http.Transport is replaced by a default one.
func Transport(base http.RoundTripper, allow Networks) *http.Transport {
	t, ok := base.(*http.Transport)
	if ok {
		t = t.Clone()
	} else {
		t = http.DefaultTransport.(*http.Transport).Clone()
	}
	t.Proxy = nil
	t.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   Control(allow),
	}).DialContext
	return t
}

// CheckHost resolves host, when a URL is saved, so an admin learns straight
// away that it points inside the network. The dial-time check is the one
// that holds.
func CheckHost(ctx context.Context, host string, allow Networks) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !Allowed(addr, allow) {
			return ErrNotPublic
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s", host)
	}
	for _, addr := range addrs {
		if !Allowed(addr, allow) {
			return ErrNotPublic
		}
	}
	return nil
}

// ClientIP is the address of the caller of a request that reached the server
// from remoteAddr carrying the X-Forwarded-For header xff.
//
// X-Forwarded-For is written by whoever sends the request, so it is believed
// only as far as proxies the operator trusts vouch for it: when the peer is a
// trusted proxy, the header is read from the right, skipping trusted proxies,
// and the first address that is not one is the client. An untrusted peer is
// the client itself, whatever the header says. With trusted = "*" every hop
// is trusted and the leftmost address is the client (the previous
// behaviour, and upstream's).
func ClientIP(remoteAddr, xff string, trusted Networks) string {
	peer := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		peer = host
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || xff == "" || !trusted.Contains(peerAddr) {
		return peer
	}
	var hops []netip.Addr
	for _, part := range strings.Split(xff, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
			hops = append(hops, a.Unmap())
		}
	}
	if len(hops) == 0 {
		return peer
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !trusted.Contains(hops[i]) {
			return hops[i].String()
		}
	}
	return hops[0].String()
}
