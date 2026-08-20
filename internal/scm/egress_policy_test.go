package scm

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestEgressRejectsRedirectToUnregisteredHost(t *testing.T) {
	t.Parallel()

	policy, err := NewEgressPolicy([]Instance{{
		ID: "gitlab-corp", Provider: ProviderGitLab, APIBaseURL: "https://gitlab.corp.example/api/v4",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if policy.AllowRedirect("https://gitlab.corp.example/api/v4/projects", "https://169.254.169.254/latest") {
		t.Fatal("metadata redirect was allowed")
	}
}

func TestResolveConnectionPinsStableAddressesAndRejectsLinkLocalResults(t *testing.T) {
	t.Parallel()

	connection := Connection{APIBaseURL: "https://gitlab.corp.example/api/v4"}
	resolved, err := ResolveConnection(context.Background(), connection, fixedResolver{addresses: []netip.Addr{
		netip.MustParseAddr("10.20.30.41"), netip.MustParseAddr("10.20.30.40"), netip.MustParseAddr("10.20.30.40"),
	}}, netip.MustParsePrefix("10.20.30.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolved.ResolvedAddresses, []string{"10.20.30.40", "10.20.30.41"}) {
		t.Fatalf("resolved addresses = %#v", resolved.ResolvedAddresses)
	}
	if _, err := ResolveConnection(context.Background(), connection, fixedResolver{addresses: []netip.Addr{
		netip.MustParseAddr("169.254.169.254"),
	}}); err != ErrEgressDestinationDenied {
		t.Fatalf("link-local resolution error = %v, want %v", err, ErrEgressDestinationDenied)
	}
}

type fixedResolver struct {
	addresses []netip.Addr
	err       error
}

func (resolver fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver.addresses...), resolver.err
}

func TestEgressRejectsEveryHTTPRedirectEvenOnRegisteredHost(t *testing.T) {
	t.Parallel()

	policy, err := NewEgressPolicy([]Instance{{
		ID: "ghes-corp", Provider: ProviderGitHub, APIBaseURL: "https://github.corp.example/api/v3",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if policy.AllowRedirect("https://github.corp.example/api/v3/repos/acme/app", "https://github.corp.example/login") {
		t.Fatal("same-host redirect was allowed")
	}
}

func TestEgressRejectsCredentialsAndNonHTTPSInstanceURLs(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"http://gitlab.corp.example/api/v4",
		"https://token@gitlab.corp.example/api/v4",
		"https://gitlab.corp.example/api/v4?token=secret",
	} {
		if _, err := NewEgressPolicy([]Instance{{ID: "invalid", Provider: ProviderGitLab, APIBaseURL: rawURL}}); err != ErrEgressConfigurationInvalid {
			t.Fatalf("NewEgressPolicy(%q) error = %v, want %v", rawURL, err, ErrEgressConfigurationInvalid)
		}
	}
}
