import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
} from 'react';
import { ApiProblemError, apiClient, createApiClient } from '../api/client';
import type {
  LocalLoginInput,
  LoginMode,
  PlatformRole,
  Principal,
  ProblemDetails,
} from '../api/types';
import { sessionStore } from './sessionStore';

const rolePrincipals: Record<PlatformRole, Principal> = {
  admin: { id: 'admin', displayName: '林管理员', roles: ['admin'], productScopes: ['*'] },
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
  auditor: { id: 'auditor', displayName: '周审计员', roles: ['auditor'], productScopes: ['*'] },
  viewer: { id: 'viewer', displayName: '只读用户', roles: ['viewer'], productScopes: ['*'] },
};

export type AuthStatus = 'loading' | 'anonymous' | 'authenticated';

interface AuthContextValue {
  status: AuthStatus;
  principal: Principal | null;
  loginMode: LoginMode | null;
  problem: ProblemDetails | null;
  authenticating: boolean;
  login: (input: LocalLoginInput, emergency: boolean) => Promise<boolean>;
  logout: () => Promise<void>;
  reloadLoginState: () => Promise<void>;
  hasAnyRole: (...roles: PlatformRole[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  children,
  initialRoles,
}: {
  children: ReactNode;
  initialRoles?: string[];
}) {
  const injectedPrincipal = useMemo(() => {
    if (initialRoles === undefined) return null;
    const firstRole =
      initialRoles.find((role): role is PlatformRole => role in rolePrincipals) || 'admin';
    return rolePrincipals[firstRole];
  }, [initialRoles]);
  const snapshot = useSyncExternalStore(
    sessionStore.subscribe,
    sessionStore.getSnapshot,
    sessionStore.getSnapshot,
  );
  const [loginMode, setLoginMode] = useState<LoginMode | null>(null);
  const [problem, setProblem] = useState<ProblemDetails | null>(null);
  const [loadingLoginState, setLoadingLoginState] = useState(injectedPrincipal === null);
  const [authenticating, setAuthenticating] = useState(false);

  const reloadLoginState = useCallback(async () => {
    if (injectedPrincipal) return;
    setLoadingLoginState(true);
    setProblem(null);
    try {
      setLoginMode((await apiClient.getLoginState()).mode);
    } catch (error) {
      setLoginMode(null);
      setProblem(problemFromError(error));
    } finally {
      setLoadingLoginState(false);
    }
  }, [injectedPrincipal]);

  useEffect(() => {
    if (!injectedPrincipal && loginMode === null && !problem) void reloadLoginState();
  }, [injectedPrincipal, loginMode, problem, reloadLoginState]);

  const login = useCallback(async (input: LocalLoginInput, emergency: boolean) => {
    setAuthenticating(true);
    setProblem(null);
    try {
      const result = emergency
        ? await apiClient.loginEmergency(input)
        : await apiClient.loginLocal(input);
      const current = await createApiClient({
        getAccessToken: () => result.accessToken,
      }).getCurrentSession();
      const principal: Principal = {
        id: current.governedUserId ?? result.subject.id,
        displayName: result.subject.displayName,
        roles: current.roles,
        productScopes: current.productIds,
      };
      sessionStore.authenticate({
        accessToken: result.accessToken,
        expiresAt: result.expiresAt,
        subject: result.subject,
        principal,
      });
      return true;
    } catch (error) {
      setProblem(problemFromError(error));
      return false;
    } finally {
      setAuthenticating(false);
    }
  }, []);

  const principal =
    injectedPrincipal ?? (snapshot.status === 'authenticated' ? snapshot.principal : null);
  const status: AuthStatus = principal
    ? 'authenticated'
    : loadingLoginState
      ? 'loading'
      : 'anonymous';
  const logout = useCallback(async () => {
    try {
      await apiClient.logout();
    } catch (error) {
      setProblem(problemFromError(error));
    } finally {
      sessionStore.clear('logout');
    }
  }, []);
  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      principal,
      loginMode,
      problem,
      authenticating,
      login,
      logout,
      reloadLoginState,
      hasAnyRole: (...roles) =>
        principal !== null && roles.some((role) => principal.roles.includes(role)),
    }),
    [status, principal, loginMode, problem, authenticating, login, logout, reloadLoginState],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function problemFromError(error: unknown): ProblemDetails {
  if (error instanceof ApiProblemError) return error.problem;
  return {
    type: 'about:blank',
    title: '认证服务暂时不可用',
    status: 503,
    detail: error instanceof Error ? error.message : undefined,
  };
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth 必须在 AuthProvider 内使用');
  return context;
}

export const platformRoleLabels: Record<PlatformRole, string> = {
  admin: '管理员',
  publisher: '发布者',
  approver: '审批者',
  auditor: '审计员',
  viewer: '只读用户',
};
