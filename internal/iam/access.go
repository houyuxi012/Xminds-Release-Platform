package iam

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

type EffectiveAccess struct {
	bindings []RoleBinding
}

func ResolveAccess(user UserPrincipal, organizationIDs []uuid.UUID, bindings []RoleBinding, at time.Time) EffectiveAccess {
	if user.ID == uuid.Nil || user.Status != UserStatusActive {
		return EffectiveAccess{}
	}
	organizations := make(map[uuid.UUID]struct{}, len(organizationIDs))
	for _, id := range organizationIDs {
		if id != uuid.Nil {
			organizations[id] = struct{}{}
		}
	}
	active := make([]RoleBinding, 0, len(bindings))
	for _, binding := range bindings {
		if !bindingActive(binding, at) || !bindingAppliesToSubject(binding, user.ID, organizations) {
			continue
		}
		active = append(active, binding)
	}
	return EffectiveAccess{bindings: active}
}

func (access EffectiveAccess) Allowed(role identity.Role, productID, channel string) bool {
	productID = strings.TrimSpace(productID)
	channel = strings.TrimSpace(channel)
	allowed := false
	for _, binding := range access.bindings {
		if binding.Role != role || !bindingAppliesToScope(binding, productID, channel) {
			continue
		}
		if binding.Effect == BindingEffectDeny {
			return false
		}
		if binding.Effect == BindingEffectAllow {
			allowed = true
		}
	}
	return allowed
}

func bindingActive(binding RoleBinding, at time.Time) bool {
	if binding.ID == uuid.Nil || binding.SubjectID == uuid.Nil || binding.ValidFrom.IsZero() || at.Before(binding.ValidFrom) {
		return false
	}
	if !binding.ValidUntil.IsZero() && !at.Before(binding.ValidUntil) {
		return false
	}
	return binding.Effect == BindingEffectAllow || binding.Effect == BindingEffectDeny
}

func bindingAppliesToSubject(binding RoleBinding, userID uuid.UUID, organizations map[uuid.UUID]struct{}) bool {
	switch binding.SubjectType {
	case SubjectTypeUser:
		return binding.SubjectID == userID
	case SubjectTypeOrganization:
		_, exists := organizations[binding.SubjectID]
		return exists
	default:
		return false
	}
}

func bindingAppliesToScope(binding RoleBinding, productID, channel string) bool {
	switch binding.ScopeType {
	case ScopeTypePlatform:
		return true
	case ScopeTypeProduct:
		return productID != "" && binding.ProductID == productID
	case ScopeTypeChannel:
		return productID != "" && channel != "" && binding.ProductID == productID && binding.ChannelName == channel
	default:
		return false
	}
}
