package scm

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	platformegress "xminds-release-platform/internal/platform/egress"
)

var (
	ErrEgressConfigurationInvalid = errors.New("SCM egress configuration is invalid")
	ErrEgressDestinationDenied    = errors.New("SCM egress destination is denied")
	ErrRedirectDenied             = errors.New("SCM HTTP redirects are denied")
)

type EgressPolicy struct {
	instances map[string]*url.URL
}

type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func ResolveConnection(ctx context.Context, connection Connection, resolver IPResolver) (Connection, error) {
	if resolver == nil {
		return Connection{}, ErrEgressConfigurationInvalid
	}
	parsed, err := parseConnectionAPIBaseURL(connection.APIBaseURL)
	if err != nil {
		return Connection{}, err
	}
	addresses, err := platformegress.ResolvePinnedAddresses(ctx, resolver, parsed.Hostname(), platformegress.Policy{AllowPrivate: true})
	if err != nil {
		if err == platformegress.ErrDestinationDenied {
			return Connection{}, ErrEgressDestinationDenied
		}
		return Connection{}, errors.Join(ErrEgressDestinationDenied, err)
	}
	resolved := make([]string, 0, len(addresses))
	for _, address := range addresses {
		resolved = append(resolved, address.String())
	}
	sort.Strings(resolved)
	connection.ResolvedAddresses = resolved
	return connection, nil
}

func NewEgressPolicy(instances []Instance) (*EgressPolicy, error) {
	if len(instances) == 0 {
		return nil, ErrEgressConfigurationInvalid
	}
	policy := &EgressPolicy{instances: make(map[string]*url.URL, len(instances))}
	for _, instance := range instances {
		instance.ID = strings.TrimSpace(instance.ID)
		if instance.ID == "" || (instance.Provider != ProviderGitHub && instance.Provider != ProviderGitLab) {
			return nil, ErrEgressConfigurationInvalid
		}
		if _, duplicate := policy.instances[instance.ID]; duplicate {
			return nil, ErrEgressConfigurationInvalid
		}
		parsed, err := url.Parse(strings.TrimSpace(instance.APIBaseURL))
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, ErrEgressConfigurationInvalid
		}
		parsed.Path = strings.TrimSuffix(parsed.EscapedPath(), "/")
		policy.instances[instance.ID] = parsed
	}
	return policy, nil
}

// AllowRedirect always returns false. Provider calls must never follow redirects,
// including redirects that appear to stay on an allow-listed host.
func (*EgressPolicy) AllowRedirect(_, _ string) bool { return false }

func (*EgressPolicy) CheckRedirect(_ *http.Request, _ []*http.Request) error {
	return ErrRedirectDenied
}
