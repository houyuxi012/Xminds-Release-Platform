package iam

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// BreakGlassInvariantAuthority is the single service authority for mutations
// that can reduce emergency administrator availability. The repository lock
// and evaluation run in the caller's transaction, after the tentative
// mutation. Immediate authentication health and scheduled permission
// continuity must both hold before the transaction can commit.
type BreakGlassInvariantAuthority struct {
	repository BreakGlassInvariantRepository
}

func NewBreakGlassInvariantAuthority(repository BreakGlassInvariantRepository) *BreakGlassInvariantAuthority {
	return &BreakGlassInvariantAuthority{repository: repository}
}

func (authority *BreakGlassInvariantAuthority) LockAndRequireUsableAdministrator(ctx context.Context, tx pgx.Tx, at time.Time) error {
	if err := authority.LockAuthority(ctx, tx); err != nil {
		return err
	}
	return authority.RequireUsableAdministrator(ctx, tx, at)
}

// LockAuthority serializes every authorization-graph mutation before any
// organization, user or membership row lock is acquired.
func (authority *BreakGlassInvariantAuthority) LockAuthority(ctx context.Context, tx pgx.Tx) error {
	if authority == nil || authority.repository == nil {
		return ErrIAMConfiguration
	}
	return authority.repository.LockBreakGlassInvariant(ctx, tx)
}

// RequireUsableAdministrator evaluates the already locked tentative state.
func (authority *BreakGlassInvariantAuthority) RequireUsableAdministrator(ctx context.Context, tx pgx.Tx, at time.Time) error {
	if authority == nil || authority.repository == nil {
		return ErrIAMConfiguration
	}
	evaluation, err := authority.repository.EvaluateBreakGlassInvariant(ctx, tx, at.UTC())
	if err != nil {
		return err
	}
	if evaluation.CurrentUsableAdministrators < 1 || !evaluation.FirstScheduledPermissionGap.IsZero() {
		return ErrLastEmergencyAdministrator
	}
	return nil
}
