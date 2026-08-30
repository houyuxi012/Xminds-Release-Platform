import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSessionStore } from './sessionStore';

afterEach(() => vi.useRealTimers());

const authenticatedSession = {
  accessToken: 'xms_memory_only_token',
  expiresAt: '2026-08-30T10:30:00Z',
  subject: {
    id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
    username: 'release.operator',
    displayName: 'Release Operator',
    kind: 'local' as const,
  },
  principal: {
    id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
    displayName: 'Release Operator',
    roles: ['admin' as const],
    productScopes: ['*'],
  },
};

describe('内存认证会话', () => {
  it('认证后只通过令牌读取器提供访问令牌', () => {
    const store = createSessionStore({ now: () => Date.parse('2026-08-30T10:00:00Z') });

    store.authenticate(authenticatedSession);

    expect(store.getAccessToken()).toBe('xms_memory_only_token');
    expect(store.getSnapshot()).toMatchObject({
      status: 'authenticated',
      principal: { displayName: 'Release Operator', roles: ['admin'] },
    });
    expect(store.getSnapshot()).not.toHaveProperty('accessToken');
  });

  it('到期时清空内存令牌与主体', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-30T10:00:00Z'));
    const store = createSessionStore();
    store.authenticate(authenticatedSession);

    vi.advanceTimersByTime(30 * 60 * 1000);

    expect(store.getSnapshot()).toEqual({ status: 'anonymous', reason: 'expired' });
    expect(store.getAccessToken()).toBeNull();
  });

  it('401 失效保留可呈现的会话结束原因', () => {
    const store = createSessionStore({ now: () => Date.parse('2026-08-30T10:00:00Z') });
    store.authenticate(authenticatedSession);

    store.clear('unauthorized');

    expect(store.getSnapshot()).toEqual({ status: 'anonymous', reason: 'unauthorized' });
    expect(store.getAccessToken()).toBeNull();
  });
});
