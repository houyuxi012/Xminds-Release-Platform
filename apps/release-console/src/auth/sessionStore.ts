import type { LocalAuthenticatedSubject, Principal } from '../api/types';

export type SessionEndReason = 'expired' | 'unauthorized' | 'logout';

export type AuthSnapshot =
  | { status: 'anonymous'; reason?: SessionEndReason }
  | {
      status: 'authenticated';
      expiresAt: string;
      subject: LocalAuthenticatedSubject;
      principal: Principal;
    };

export interface AuthenticatedSession {
  accessToken: string;
  expiresAt: string;
  subject: LocalAuthenticatedSubject;
  principal: Principal;
}

export interface SessionStore {
  getSnapshot(): AuthSnapshot;
  getAccessToken(): string | null;
  subscribe(listener: () => void): () => void;
  authenticate(session: AuthenticatedSession): void;
  clear(reason?: SessionEndReason): void;
}

interface SessionStoreOptions {
  now?: () => number;
}

const maximumTimerDelay = 2_147_483_647;

export function createSessionStore(options: SessionStoreOptions = {}): SessionStore {
  const now = options.now ?? Date.now;
  const listeners = new Set<() => void>();
  let accessToken: string | null = null;
  let snapshot: AuthSnapshot = { status: 'anonymous' };
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;

  const notify = () => {
    for (const listener of listeners) {
      listener();
    }
  };

  const cancelExpiry = () => {
    if (expiryTimer !== undefined) {
      clearTimeout(expiryTimer);
      expiryTimer = undefined;
    }
  };

  const clear = (reason?: SessionEndReason) => {
    cancelExpiry();
    accessToken = null;
    snapshot = reason ? { status: 'anonymous', reason } : { status: 'anonymous' };
    notify();
  };

  const scheduleExpiry = () => {
    cancelExpiry();
    if (snapshot.status !== 'authenticated') {
      return;
    }
    const remaining = Date.parse(snapshot.expiresAt) - now();
    if (remaining <= 0) {
      clear('expired');
      return;
    }
    expiryTimer = setTimeout(scheduleExpiry, Math.min(remaining, maximumTimerDelay));
  };

  return {
    getSnapshot: () => snapshot,
    getAccessToken: () => {
      if (snapshot.status === 'authenticated' && Date.parse(snapshot.expiresAt) <= now()) {
        clear('expired');
      }
      return accessToken;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    authenticate(session) {
      const token = session.accessToken.trim();
      const expiresAt = Date.parse(session.expiresAt);
      if (!token || token.length > 16 * 1024 || Number.isNaN(expiresAt) || expiresAt <= now()) {
        throw new RangeError('认证会话无效或已经到期');
      }
      accessToken = token;
      snapshot = {
        status: 'authenticated',
        expiresAt: session.expiresAt,
        subject: session.subject,
        principal: session.principal,
      };
      scheduleExpiry();
      notify();
    },
    clear,
  };
}

export const sessionStore = createSessionStore();
