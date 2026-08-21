UPDATE iam_reauthentication_challenges
SET status='expired',version=version+1
WHERE operation IN (
    'mfa.enrollment.begin',
    'mfa.recovery_codes.regenerate',
    'emergency.user.create',
    'emergency.user.activation.reissue'
)
AND status IN ('pending','verified');

DELETE FROM iam_reauthentication_challenges
WHERE operation IN (
    'mfa.enrollment.begin',
    'mfa.recovery_codes.regenerate',
    'emergency.user.create',
    'emergency.user.activation.reissue'
);

ALTER TABLE iam_reauthentication_challenges
    DROP CONSTRAINT iam_reauthentication_challenges_operation_check,
    ADD CONSTRAINT iam_reauthentication_challenges_operation_check CHECK (operation IN (
        'identity.role_binding.create',
        'identity.role_binding.delete',
        'identity.user.disable',
        'identity.user.enable',
        'identity.user.revoke_sessions',
        'identity.sso.enable',
        'identity.sso.disable',
        'identity.directory_conflict.resolve',
        'identity.organization_membership.create',
        'identity.organization_membership.delete'
    ));

DROP TABLE iam_mfa_recovery_codes;
DROP TABLE iam_mfa_secret_gc;
DROP TABLE iam_mfa_enrollments;
