// Package egress provides DNS-pinned, policy-governed outbound dialing.
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

var ErrDestinationDenied = errors.New("egress destination is denied")

type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Policy struct {
	AllowLoopback bool
	AllowPrivate  bool
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
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() ||
			(address.IsLoopback() && !policy.AllowLoopback) || (address.IsPrivate() && !policy.AllowPrivate) {
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
