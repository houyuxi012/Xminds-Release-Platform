package identity

import "errors"

var ErrLocalAdminForbidden = errors.New("local admin is forbidden outside development")

type LocalAdminVerifier struct {
	enabled bool
}

func NewLocalAdminVerifier(environment string, enabled bool) (*LocalAdminVerifier, error) {
	if enabled && environment != "development" {
		return nil, ErrLocalAdminForbidden
	}
	return &LocalAdminVerifier{enabled: enabled}, nil
}

func (verifier *LocalAdminVerifier) Enabled() bool {
	return verifier.enabled
}
