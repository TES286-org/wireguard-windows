/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"net/netip"
	"testing"
)

// mustKey parses a base64 WireGuard key, failing the test if invalid.
func mustKey(t *testing.T, s string) Key {
	t.Helper()
	k, err := NewPrivateKeyFromString(s)
	if err != nil {
		t.Fatalf("invalid key %q: %v", s, err)
	}
	return *k
}

// intersectConfig builds a minimal *Config with the supplied interface
// addresses and peer AllowedIPs. Other fields are zeroed; IntersectsWith
// only inspects Interface.Addresses and Peers[].AllowedIPs.
func intersectConfig(t *testing.T, name string, addresses []string, allowedIPs ...string) *Config {
	t.Helper()
	c := &Config{Name: name}
	c.Interface.PrivateKey = mustKey(t, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			t.Fatalf("invalid prefix %q: %v", a, err)
		}
		c.Interface.Addresses = append(c.Interface.Addresses, p)
	}
	if len(allowedIPs) > 0 {
		peer := Peer{PublicKey: mustKey(t, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")}
		for _, a := range allowedIPs {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				t.Fatalf("invalid prefix %q: %v", a, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, p)
		}
		c.Peers = []Peer{peer}
	}
	return c
}

// TestIntersectsWith verifies that Config.IntersectsWith correctly reports
// whether two tunnel configurations have overlapping interface addresses or
// peer AllowedIPs.
//
// IntersectsWith is no longer used to gate tunnel starts in the manager (the
// multi-tunnel firewall handles overlapping kill-switch tunnels), but it
// remains a public utility that the UI and other callers may use to warn
// users about potential route conflicts. These tests pin its semantics.
func TestIntersectsWith(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    *Config
		b    *Config
		want bool
	}{
		{
			name: "disjoint allowed IPs",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}, "10.0.0.0/24"),
			b:    intersectConfig(t, "b", []string{"10.1.0.1/24"}, "10.1.0.0/24"),
			want: false,
		},
		{
			name: "both default route v4",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}, "0.0.0.0/0"),
			b:    intersectConfig(t, "b", []string{"10.1.0.1/24"}, "0.0.0.0/0"),
			want: true,
		},
		{
			name: "both default route v6",
			a:    intersectConfig(t, "a", []string{"fd00::1/64"}, "::/0"),
			b:    intersectConfig(t, "b", []string{"fd01::1/64"}, "::/0"),
			want: true,
		},
		{
			name: "overlapping allowed IP subnets",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}, "192.168.0.0/16"),
			b:    intersectConfig(t, "b", []string{"10.1.0.1/24"}, "192.168.1.0/24"),
			want: true,
		},
		{
			name: "identical interface address",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}),
			b:    intersectConfig(t, "b", []string{"10.0.0.1/24"}),
			want: true,
		},
		{
			name: "overlapping interface address subnets",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}),
			b:    intersectConfig(t, "b", []string{"10.0.0.2/24"}),
			want: true,
		},
		{
			name: "interface address inside peer allowed IP",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}, "10.0.0.0/24"),
			b:    intersectConfig(t, "b", []string{"10.0.0.5/32"}),
			want: true,
		},
		{
			name: "different address families do not intersect",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}, "10.0.0.0/24"),
			b:    intersectConfig(t, "b", []string{"fd00::1/64"}, "fd00::/64"),
			want: false,
		},
		{
			name: "no peers, disjoint addresses",
			a:    intersectConfig(t, "a", []string{"10.0.0.1/24"}),
			b:    intersectConfig(t, "b", []string{"10.1.0.1/24"}),
			want: false,
		},
		{
			name: "empty configs do not intersect",
			a:    intersectConfig(t, "a", nil),
			b:    intersectConfig(t, "b", nil),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.IntersectsWith(tc.b); got != tc.want {
				t.Errorf("a.IntersectsWith(b) = %v, want %v", got, tc.want)
			}
			if got := tc.b.IntersectsWith(tc.a); got != tc.want {
				t.Errorf("b.IntersectsWith(a) = %v, want %v (should be symmetric)", got, tc.want)
			}
		})
	}
}

// TestIntersectsWithMultiplePeers ensures that when a config has multiple
// peers, the intersection check considers every peer's AllowedIPs.
func TestIntersectsWithMultiplePeers(t *testing.T) {
	a := intersectConfig(t, "a", []string{"10.0.0.1/24"}, "10.10.0.0/16")
	// Add a second peer to a with a non-overlapping range.
	secondPeer := Peer{PublicKey: mustKey(t, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=")}
	p, err := netip.ParsePrefix("172.16.0.0/12")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}
	secondPeer.AllowedIPs = []netip.Prefix{p}
	a.Peers = append(a.Peers, secondPeer)

	b := intersectConfig(t, "b", []string{"10.1.0.1/24"}, "172.17.0.0/16")
	if !a.IntersectsWith(b) {
		t.Errorf("expected intersection via second peer's 172.16.0.0/12 vs 172.17.0.0/16")
	}
}
