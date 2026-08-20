package iam

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// BreakGlassInvariantAuthority is the single service authority for mutations
// that can reduce emergency administrator availability. The repository lock
// and count run in the caller's transaction, after the tentative mutation.
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
	count, err := authority.repository.CountUsableEmergencyAdministrators(ctx, tx, at.UTC())
	if err != nil {
		return err
	}
	if count < 1 {
		return ErrLastEmergencyAdministrator
	}
	return nil
}
