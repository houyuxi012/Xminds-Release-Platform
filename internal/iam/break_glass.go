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
	if authority == nil || authority.repository == nil {
		return ErrIAMConfiguration
	}
	if err := authority.repository.LockBreakGlassInvariant(ctx, tx); err != nil {
		return err
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
