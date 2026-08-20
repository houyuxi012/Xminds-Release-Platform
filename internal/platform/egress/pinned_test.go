package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestResolvePinnedAddressesRejectsUnsafeAndMixedDNSAnswers(t *testing.T) {
	unsafe := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("10.0.0.7"),
		netip.MustParseAddr("fd00::7"),
	}
	for _, address := range unsafe {
		resolver := fixedIPResolver{addresses: []netip.Addr{netip.MustParseAddr("2001:db8::10"), address}}
		if _, err := ResolvePinnedAddresses(context.Background(), resolver, "directory.example.com", Policy{}); !errors.Is(err, ErrDestinationDenied) {
			t.Fatalf("address %s error=%v", address, err)
		}
	}
	private, err := ResolvePinnedAddresses(context.Background(), fixedIPResolver{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fd00::7")}}, "directory.internal", Policy{AllowPrivate: true})
	if err != nil || len(private) != 2 {
		t.Fatalf("explicit private policy addresses=%v error=%v", private, err)
	}
}

func TestNormalizeAddressesProvidesSharedPolicyBoundary(t *testing.T) {
	addresses, err := NormalizeAddresses([]netip.Addr{
		netip.MustParseAddr("::ffff:192.0.2.20"), netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("10.20.30.40"),
	}, Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0].String() != "192.0.2.20" || addresses[1].String() != "10.20.30.40" {
		t.Fatalf("normalized addresses=%v", addresses)
	}
	if _, err := NormalizeAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("169.254.169.254")}, Policy{AllowPrivate: true}); !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("mixed unsafe addresses error=%v", err)
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
