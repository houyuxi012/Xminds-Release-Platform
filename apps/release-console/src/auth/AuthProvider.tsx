import { createContext, type ReactNode, useContext, useMemo, useState } from 'react';
import type { PlatformRole, Principal } from '../api/types';

const rolePrincipals: Record<PlatformRole, Principal> = {
  admin: {
    id: 'admin',
    displayName: '林管理员',
    roles: ['admin'],
    productScopes: ['*'],
  },
  publisher: {
    id: 'alice',
    displayName: 'Alice 发布者',
    roles: ['publisher'],
    productScopes: ['ngep', 'xminds-agent'],
  },
  approver: {
    id: 'bob',
    displayName: 'Bob 审批者',
    roles: ['approver'],
    productScopes: ['ngep', 'xminds-agent'],
  },
  auditor: {
    id: 'auditor',
    displayName: '周审计员',
    roles: ['auditor'],
    productScopes: ['*'],
  },
};

interface AuthContextValue {
  principal: Principal;
  activeRole: PlatformRole;
  setActiveRole: (role: PlatformRole) => void;
  hasAnyRole: (...roles: PlatformRole[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  children,
  initialRoles = ['admin'],
}: {
  children: ReactNode;
  initialRoles?: string[];
}) {
  const firstRole =
    initialRoles.find((role): role is PlatformRole => role in rolePrincipals) || 'admin';
  const [activeRole, setActiveRole] = useState<PlatformRole>(firstRole);
  const principal = rolePrincipals[activeRole];

  const value = useMemo<AuthContextValue>(
    () => ({
      principal,
      activeRole,
      setActiveRole,
      hasAnyRole: (...roles) => roles.some((role) => principal.roles.includes(role)),
    }),
    [activeRole, principal],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth 必须在 AuthProvider 内使用');
  }
  return context;
}

export const platformRoleLabels: Record<PlatformRole, string> = {
  admin: '管理员',
  publisher: '发布者',
  approver: '审批者',
  auditor: '审计员',
};
