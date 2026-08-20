package identity

import (
	"errors"
	"strings"
)

type PrincipalKind string

const (
	PrincipalKindHuman    PrincipalKind = "human"
	PrincipalKindWorkload PrincipalKind = "workload"
	PrincipalKindLocal    PrincipalKind = "local"
)

type WorkloadProvider string

const (
	WorkloadProviderGitHubActions           WorkloadProvider = "github-actions"
	WorkloadProviderGitHubEnterpriseActions WorkloadProvider = "github-enterprise-actions"
	WorkloadProviderGitLabCI                WorkloadProvider = "gitlab-ci"
	WorkloadProviderAPIToken                WorkloadProvider = "api-token"
)

type Role string

const (
	RoleAdmin     Role = "admin"
	RolePublisher Role = "publisher"
	RoleApprover  Role = "approver"
	RoleAuditor   Role = "auditor"
	RoleViewer    Role = "viewer"
)

var (
	ErrPrincipalSubjectRequired  = errors.New("principal subject is required")
	ErrPrincipalKindInvalid      = errors.New("principal kind is invalid")
	ErrPrincipalAssuranceInvalid = errors.New("principal authentication assurance is invalid")
)

type Principal struct {
	Subject                 string
	Kind                    PrincipalKind
	Roles                   []Role
	ProductIDs              []string
	TokenID                 string
	Provider                WorkloadProvider
	Governed                bool
	RoleScopes              []RoleScope
	AuthenticationAssurance int
}

type RoleScope struct {
	Role        Role
	Effect      string
	ScopeType   string
	ProductID   string
	ChannelName string
}

func (principal Principal) Validate() error {
	if strings.TrimSpace(principal.Subject) == "" {
		return ErrPrincipalSubjectRequired
	}
	if principal.AuthenticationAssurance < 0 || principal.AuthenticationAssurance > 3 {
		return ErrPrincipalAssuranceInvalid
	}
	switch principal.Kind {
	case PrincipalKindHuman, PrincipalKindWorkload, PrincipalKindLocal:
		return nil
	default:
		return ErrPrincipalKindInvalid
	}
}
