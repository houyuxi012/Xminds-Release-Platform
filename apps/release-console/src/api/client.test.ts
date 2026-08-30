import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiContractError, createApiClient, type ProductManifestV1 } from './client';

const productManifest: ProductManifestV1 = {
  schema_version: 'xminds-product-manifest/v1',
  product_id: 'ngep',
  display_name: 'Next-Gen Enterprise Portal',
  artifact_types: ['macos-dmg', 'windows-msi'],
  version_scheme: 'semver',
  compatibility_keys: ['platform', 'architecture'],
  catalog_format: 'xminds-tuf-v1',
  default_channels: [{ name: 'stable', display_name: 'Stable' }],
};

const productResponse = {
  id: 'ngep',
  display_name: 'Next-Gen Enterprise Portal',
  schema_version: 'xminds-product-manifest/v1',
  artifact_types: ['macos-dmg', 'windows-msi'],
  version_scheme: 'semver',
  compatibility_keys: ['platform', 'architecture'],
  catalog_format: 'xminds-tuf-v1',
  manifest: productManifest,
  manifest_digest: '8b9c7a1200000000000000000000000000000000000000000000000000000000',
  status: 'active',
  channels: [
    {
      product_id: 'ngep',
      name: 'stable',
      display_name: 'Stable',
      position: 0,
      created_at: '2026-08-30T02:00:00Z',
    },
  ],
  created_by: '0198a3b1-6c00-7f11-8000-000000000002',
  created_at: '2026-08-30T02:00:00Z',
  updated_at: '2026-08-30T02:30:00Z',
};

afterEach(() => vi.unstubAllGlobals());

describe('Console API 产品契约', () => {
  it('使用 Bearer Token 查询产品页并在边界转换 snake_case DTO', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json(
        { items: [productResponse], next_cursor: 'opaque-next-cursor' },
        { headers: { 'content-type': 'application/json' } },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = createApiClient({ getAccessToken: () => 'session-access-token' });

    const page = await client.listProducts({ limit: 25, cursor: 'cursor-+/=' });

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/products?limit=25&cursor=cursor-%2B%2F%3D');
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {
        accept: 'application/json, application/problem+json',
        authorization: 'Bearer session-access-token',
      },
    });
    expect(page.nextCursor).toBe('opaque-next-cursor');
    expect(page.items[0]).toMatchObject({
      id: 'ngep',
      displayName: 'Next-Gen Enterprise Portal',
      defaultChannel: 'stable',
      artifactTypes: ['macos-dmg', 'windows-msi'],
      compatibilityKeys: ['platform', 'architecture'],
      manifestDigest: productResponse.manifest_digest,
      updatedAt: '2026-08-30T02:30:00Z',
    });
  });

  it('创建产品时按 OpenAPI 发送完整 ProductManifestV1', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json(productResponse, {
        status: 201,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = createApiClient();

    const product = await client.createProduct(productManifest);

    expect(product.id).toBe('ngep');
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/products',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(productManifest),
        headers: expect.objectContaining({ 'content-type': 'application/json' }),
      }),
    );
  });

  it('拒绝将缺失必填字段的成功响应传入界面', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          { ...productResponse, manifest_digest: undefined },
          { headers: { 'content-type': 'application/json' } },
        ),
      ),
    );

    await expect(createApiClient().getProduct('ngep')).rejects.toBeInstanceOf(ApiContractError);
  });

  it('保留 RFC 9457 错误码、详情和请求 ID', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          {
            type: 'https://xminds.example/problems/product-manifest-invalid',
            title: '产品清单无效',
            status: 422,
            detail: '制品类型不符合约束',
            code: 'PRODUCT_MANIFEST_INVALID',
            request_id: 'req_01J5A0KQ12XM',
          },
          { status: 422, headers: { 'content-type': 'application/problem+json' } },
        ),
      ),
    );

    const failure = createApiClient().createProduct(productManifest);

    await expect(failure).rejects.toMatchObject({
      problem: {
        type: 'https://xminds.example/problems/product-manifest-invalid',
        title: '产品清单无效',
        status: 422,
        detail: '制品类型不符合约束',
        code: 'PRODUCT_MANIFEST_INVALID',
        request_id: 'req_01J5A0KQ12XM',
      },
    });
  });
});

describe('Console API 认证契约', () => {
  it('公开登录状态请求不携带 Bearer 并转换稳定枚举', async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ mode: 'configuring' }, { headers: { 'content-type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const state = await createApiClient({ getAccessToken: () => 'stale-token' }).getLoginState();

    expect(state).toEqual({ mode: 'configuring' });
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/login-state',
      expect.objectContaining({
        cache: 'no-store',
        credentials: 'same-origin',
        headers: expect.not.objectContaining({ authorization: expect.anything() }),
      }),
    );
  });

  it('本地登录不发送旧 Bearer 并转换一次性会话 DTO', async () => {
    const fetchMock = vi.fn(async () =>
      Response.json(
        {
          access_token: 'xms_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',
          token_type: 'Bearer',
          expires_at: '2026-08-30T12:00:00Z',
          subject: {
            id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
            username: 'release.operator',
            display_name: 'Release Operator',
            kind: 'local',
          },
        },
        { headers: { 'content-type': 'application/json' } },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = createApiClient({ getAccessToken: () => 'stale-token' });

    const result = await client.loginLocal({
      username: 'release.operator',
      password: 'Current-Strong-Password!',
    });

    expect(result).toMatchObject({
      tokenType: 'Bearer',
      expiresAt: '2026-08-30T12:00:00Z',
      subject: { username: 'release.operator', displayName: 'Release Operator', kind: 'local' },
    });
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/local/login',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          username: 'release.operator',
          password: 'Current-Strong-Password!',
        }),
        headers: expect.not.objectContaining({ authorization: expect.anything() }),
      }),
    );
  });

  it('受保护请求遇到 401 时只触发一次会话失效回调', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          {
            type: 'about:blank',
            title: 'Authentication failed',
            status: 401,
            code: 'AUTHENTICATION_FAILED',
            request_id: 'req_session_expired',
          },
          { status: 401, headers: { 'content-type': 'application/problem+json' } },
        ),
      ),
    );
    const onUnauthorized = vi.fn();

    await expect(
      createApiClient({ getAccessToken: () => 'expired-token', onUnauthorized }).listProducts(),
    ).rejects.toMatchObject({ problem: { status: 401 } });

    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it('当前会话只接受服务端角色与范围契约', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          {
            subject: 'release.operator',
            kind: 'local',
            governed_user_id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
            roles: ['admin', 'publisher'],
            product_ids: ['ngep'],
            role_scopes: [
              { role: 'admin', effect: 'allow', scope_type: 'platform' },
              {
                role: 'publisher',
                effect: 'allow',
                scope_type: 'product',
                product_id: 'ngep',
              },
            ],
            authentication_assurance: 1,
          },
          { headers: { 'content-type': 'application/json' } },
        ),
      ),
    );

    await expect(
      createApiClient({ getAccessToken: () => 'session-token' }).getCurrentSession(),
    ).resolves.toMatchObject({
      subject: 'release.operator',
      kind: 'local',
      roles: ['admin', 'publisher'],
      productIds: ['ngep'],
      authenticationAssurance: 1,
    });
  });

  it('退出登录调用受保护的服务端会话撤销接口', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await createApiClient({ getAccessToken: () => 'session-token' }).logout();

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/logout',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ authorization: 'Bearer session-token' }),
      }),
    );
  });
});
