package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestResolvePinnedAddressesRejectsUnsafeAndMixedDNSAnswers(t *testing.T) {
	// Representative addresses cover every non-private block in the IANA IPv4
	// and IPv6 Special-Purpose registries as reviewed on 2025-10-09. Broader
	// enclosing prefixes deliberately enforce the documented conservative
	// policy, including the otherwise globally-reachable 2001::/23 exceptions.
	unsafe := []netip.Addr{
		netip.MustParseAddr("0.0.0.1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("10.0.0.7"),
		netip.MustParseAddr("fd00::7"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("192.0.0.9"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.31.196.1"),
		netip.MustParseAddr("192.52.193.1"),
		netip.MustParseAddr("192.88.99.2"),
		netip.MustParseAddr("192.175.48.1"),
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("240.0.0.1"),
		netip.MustParseAddr("64:ff9b::1"),
		netip.MustParseAddr("64:ff9b:1::1"),
		netip.MustParseAddr("100::1"),
		netip.MustParseAddr("100:0:0:1::1"),
		netip.MustParseAddr("2001:1::1"),
		netip.MustParseAddr("2001:3::1"),
		netip.MustParseAddr("2001:4:112::1"),
		netip.MustParseAddr("2001:20::1"),
		netip.MustParseAddr("2001:30::1"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("2002::1"),
		netip.MustParseAddr("2620:4f:8000::1"),
		netip.MustParseAddr("3fff::1"),
		netip.MustParseAddr("5f00::1"),
	}
	for _, address := range unsafe {
		resolver := fixedIPResolver{addresses: []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), address}}
		if _, err := ResolvePinnedAddresses(context.Background(), resolver, "directory.example.com", Policy{}); !errors.Is(err, ErrDestinationDenied) {
			t.Fatalf("address %s error=%v", address, err)
		}
	}
	private, err := ResolvePinnedAddresses(context.Background(), fixedIPResolver{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fd00::7")}}, "directory.internal", Policy{AllowedPrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00::/64")}})
	if err != nil || len(private) != 2 {
		t.Fatalf("explicit private policy addresses=%v error=%v", private, err)
	}
}

func TestNormalizeAddressesProvidesSharedPolicyBoundary(t *testing.T) {
	addresses, err := NormalizeAddresses([]netip.Addr{
		netip.MustParseAddr("::ffff:8.8.8.8"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.20.30.40"),
	}, Policy{AllowedPrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0].String() != "8.8.8.8" || addresses[1].String() != "10.20.30.40" {
		t.Fatalf("normalized addresses=%v", addresses)
	}
	if _, err := NormalizeAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")}, Policy{AllowedPrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}}); !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("mixed unsafe addresses error=%v", err)
	}
}

func TestParseAllowedPrivatePrefixesRequiresMinimalCanonicalEnterpriseCIDRs(t *testing.T) {
	prefixes, err := ParseAllowedPrivatePrefixes("10.42.7.0/24, fd12:3456:789a::/48")
	if err != nil || len(prefixes) != 2 || prefixes[0] != netip.MustParsePrefix("10.42.7.0/24") || prefixes[1] != netip.MustParsePrefix("fd12:3456:789a::/48") {
		t.Fatalf("prefixes=%v error=%v", prefixes, err)
	}
	for name, raw := range map[string]string{
		"host bits": "10.42.7.1/24", "public": "8.8.8.0/24", "special": "100.64.0.0/10",
		"empty member": "10.42.7.0/24,", "duplicate": "10.42.7.0/24,10.42.7.0/24",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAllowedPrivatePrefixes(raw); !errors.Is(err, ErrPolicyInvalid) {
				t.Fatalf("ParseAllowedPrivatePrefixes(%q) error=%v", raw, err)
			}
		})
	}
}

func TestPinnedDialContextUsesOnlyResolvedAddressesAndRejectsHostReplay(t *testing.T) {
	dialer := &recordingPinnedDialer{}
	dialContext, err := NewPinnedDialContext("directory.example.com", []netip.Addr{
		netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8::20"),
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialContext(context.Background(), "tcp", "other.example.com:443"); !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("cross-host dial error=%v", err)
	}
	if _, err := dialContext(context.Background(), "tcp", "directory.example.com:443"); err == nil {
		t.Fatal("dial error=nil, want fake failures")
	}
	want := []string{"192.0.2.20:443", "[2001:db8::20]:443"}
	if len(dialer.addresses) != len(want) || dialer.addresses[0] != want[0] || dialer.addresses[1] != want[1] {
		t.Fatalf("dialed=%v want=%v", dialer.addresses, want)
	}
}

type fixedIPResolver struct{ addresses []netip.Addr }

func (resolver fixedIPResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver.addresses...), nil
}

type recordingPinnedDialer struct{ addresses []string }

func (dialer *recordingPinnedDialer) DialContext(_ context.Context, _ string, stringAddress string) (net.Conn, error) {
	dialer.addresses = append(dialer.addresses, stringAddress)
	return nil, errors.New("fake dial failure")
}
