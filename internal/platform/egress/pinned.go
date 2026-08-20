// Package egress provides DNS-pinned, policy-governed outbound dialing.
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

var (
	ErrDestinationDenied = errors.New("egress destination is denied")
	ErrPolicyInvalid     = errors.New("egress policy is invalid")
)

type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Policy struct {
	AllowLoopback          bool
	AllowedPrivatePrefixes []netip.Prefix
}

// ParseAllowedPrivatePrefixes parses the only private ranges that may be
// explicitly admitted by enterprise configuration. Host bits, duplicates,
// public networks, and special-purpose ranges such as CGNAT are rejected.
func ParseAllowedPrivatePrefixes(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	items := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(items))
	seen := make(map[netip.Prefix]struct{}, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || !prefix.IsValid() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() {
			return nil, ErrPolicyInvalid
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrPolicyInvalid
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// specialPurposePrefixes is a conservative deny table reviewed against the
// IANA IPv4 and IPv6 Special-Purpose Address registries dated 2025-10-09:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
//
// This policy intentionally denies every listed special-purpose allocation,
// including globally-reachable exceptions inside 2001::/23. It is therefore
// stricter than, and must not be treated as an implementation of, IANA's
// Globally Reachable attribute. Only RFC1918/ULA ranges can be admitted by an
// explicit enterprise allowlist.
var specialPurposePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

func ResolvePinnedAddresses(ctx context.Context, resolver IPResolver, host string, policy Policy) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || resolver == nil {
		return nil, ErrDestinationDenied
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolved, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.Join(ErrDestinationDenied, err)
		}
		addresses = resolved
	}
	return NormalizeAddresses(addresses, policy)
}

// NormalizeAddresses applies the shared outbound address policy and returns a
// stable, de-duplicated set suitable for transactionally pinned dialing.
func NormalizeAddresses(addresses []netip.Addr, policy Policy) ([]netip.Addr, error) {
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !addressAllowed(address, policy) {
			return nil, ErrDestinationDenied
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	if len(result) == 0 {
		return nil, ErrDestinationDenied
	}
	return result, nil
}

func addressAllowed(address netip.Addr, policy Policy) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.IsLoopback() {
		return policy.AllowLoopback
	}
	if address.IsPrivate() {
		for _, prefix := range policy.AllowedPrivatePrefixes {
			if prefix.IsValid() && prefix.Addr().IsPrivate() && prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	for _, prefix := range specialPurposePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func NewPinnedDialContext(host string, addresses []netip.Addr, dialer Dialer) (func(context.Context, string, string) (net.Conn, error), error) {
	wantedHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if wantedHost == "" || len(addresses) == 0 || dialer == nil {
		return nil, ErrDestinationDenied
	}
	pinned := append([]netip.Addr(nil), addresses...)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialHost, port, err := net.SplitHostPort(address)
		if err != nil || strings.ToLower(strings.TrimSuffix(dialHost, ".")) != wantedHost {
			return nil, ErrDestinationDenied
		}
		failures := make([]error, 0, len(pinned))
		for _, candidate := range pinned {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
			if err == nil {
				return connection, nil
			}
			failures = append(failures, err)
		}
		return nil, errors.Join(failures...)
	}, nil
}
