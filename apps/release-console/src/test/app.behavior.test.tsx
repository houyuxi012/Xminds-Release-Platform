import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from '../app/App';
import { sessionStore } from '../auth/sessionStore';
import { apiProductFixture, productManifestFixture } from './apiFixtures';

afterEach(() => {
  sessionStore.clear();
  vi.unstubAllGlobals();
});

describe('核心授权与错误反馈', () => {
  it('发布者角色在 Release 详情中看不到批准发布操作', async () => {
    render(<App initialRoles={['publisher']} initialEntries={['/releases/release-1']} />);

    expect((await screen.findAllByText('1.2.3')).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: '批准发布' })).not.toBeInTheDocument();
  });

  it('审批者批准 Release 后不能执行发布', async () => {
    render(<App initialRoles={['approver']} initialEntries={['/releases/release-1']} />);

    await userEvent.click(await screen.findByRole('button', { name: '批准发布' }));
    await userEvent.click(await screen.findByRole('button', { name: '确认批准' }));

    expect(screen.queryByRole('button', { name: '开始发布' })).not.toBeInTheDocument();
  });

  it('产品创建失败时展示 RFC 9457 请求 ID', async () => {
    const requestId = '0198a3b1-6c00-7f11-8000-000000000001';
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              type: 'https://xminds.example/problems/product-manifest-invalid',
              title: '产品清单无效',
              status: 422,
              detail: '清单字段不符合约束',
              code: 'PRODUCT_MANIFEST_INVALID',
              request_id: requestId,
            }),
            { status: 422, headers: { 'content-type': 'application/problem+json' } },
          ),
      ),
    );

    render(<App initialRoles={['admin']} initialEntries={['/products/new']} />);
    await userEvent.click(await screen.findByRole('button', { name: '创建产品' }));

    expect(await screen.findByText(`请求 ID：${requestId}`)).toBeVisible();
  });

  it('产品创建提交完整 Manifest 并在成功后进入结果页', async () => {
    const response = {
      ...apiProductFixture,
      id: 'new-product',
      display_name: '新产品',
      manifest: {
        ...productManifestFixture,
        product_id: 'new-product',
        display_name: '新产品',
        artifact_types: ['generic-binary'],
        compatibility_keys: [],
      },
      artifact_types: ['generic-binary'],
      compatibility_keys: [],
      channels: apiProductFixture.channels.map((channel) => ({
        ...channel,
        product_id: 'new-product',
      })),
    };
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json(response, {
        status: 201,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<App initialRoles={['admin']} initialEntries={['/products/new']} />);
    await userEvent.click(await screen.findByRole('button', { name: '创建产品' }));

    expect(await screen.findByText('产品已创建并通过 Manifest 校验')).toBeVisible();
    const requestInit = fetchMock.mock.calls[0]?.[1];
    expect(JSON.parse(String(requestInit?.body))).toEqual({
      schema_version: 'xminds-product-manifest/v1',
      product_id: 'new-product',
      display_name: '新产品',
      artifact_types: ['generic-binary'],
      version_scheme: 'semver',
      compatibility_keys: [],
      catalog_format: 'xminds-tuf-v1',
      default_channels: [{ name: 'stable', display_name: 'Stable' }],
    });
  });
});

describe('真实认证入口', () => {
  it('本地模式登录后使用服务端当前会话角色进入控制台', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/auth/login-state') {
        return Response.json(
          { mode: 'local' },
          { headers: { 'content-type': 'application/json' } },
        );
      }
      if (path === '/api/v1/auth/local/login') {
        return Response.json(
          {
            access_token: 'xms_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',
            token_type: 'Bearer',
            expires_at: '2099-08-30T12:00:00Z',
            subject: {
              id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
              username: 'release.operator',
              display_name: 'Release Operator',
              kind: 'local',
            },
          },
          { headers: { 'content-type': 'application/json' } },
        );
      }
      if (path === '/api/v1/auth/session') {
        return Response.json(
          {
            subject: 'release.operator',
            kind: 'local',
            governed_user_id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
            roles: ['admin'],
            product_ids: [],
            role_scopes: [{ role: 'admin', effect: 'allow', scope_type: 'platform' }],
            authentication_assurance: 1,
          },
          { headers: { 'content-type': 'application/json' } },
        );
      }
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<App initialEntries={['/']} />);

    await userEvent.type(
      await screen.findByRole('textbox', { name: '用户名' }),
      'release.operator',
    );
    await userEvent.type(screen.getByLabelText('密码'), 'Current-Strong-Password!');
    const mfaInput = screen.getByLabelText('MFA 动态验证码（如已启用）');
    expect(mfaInput).not.toBeRequired();
    await userEvent.type(mfaInput, '123456');
    await userEvent.click(screen.getByRole('button', { name: /^登\s*录$/ }));

    expect(await screen.findByText('Release Operator')).toBeVisible();
    expect(screen.getByTestId('console-shell')).toBeVisible();
    expect(screen.queryByRole('combobox', { name: '演示角色' })).not.toBeInTheDocument();
    expect(JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))).toEqual({
      username: 'release.operator',
      password: 'Current-Strong-Password!',
      mfa_proof: '123456',
    });
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        authorization: 'Bearer xms_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',
      }),
    });
  });

  it('SSO fault 时不显示普通本地登录并保留强制 MFA 应急入口', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({ mode: 'fault' }, { headers: { 'content-type': 'application/json' } }),
      ),
    );
    render(<App initialEntries={['/']} />);

    expect(await screen.findByText('SSO 服务异常')).toBeVisible();
    expect(screen.queryByRole('textbox', { name: '用户名' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '应急管理员登录' }));

    expect(screen.getByRole('textbox', { name: '用户名' })).toBeVisible();
    expect(screen.getByLabelText('MFA 动态验证码')).toBeRequired();
    expect(screen.queryByRole('button', { name: /^登\s*录$/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '进入应急会话' })).toBeVisible();
  });

  it('SSO 模式保持普通本地登录关闭且不虚构未实现的回调', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({ mode: 'sso' }, { headers: { 'content-type': 'application/json' } }),
      ),
    );
    render(<App initialEntries={['/']} />);

    expect(await screen.findByText('企业 SSO 已启用')).toBeVisible();
    expect(screen.queryByRole('textbox', { name: '用户名' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^登\s*录$/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '应急管理员登录' })).toBeVisible();
  });

  it('受保护请求返回 401 时清除内存会话并返回登录页', async () => {
    sessionStore.authenticate({
      accessToken: 'xms_expired_session_token',
      expiresAt: '2099-08-30T12:00:00Z',
      subject: {
        id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
        username: 'release.operator',
        displayName: 'Release Operator',
        kind: 'local',
      },
      principal: {
        id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
        displayName: 'Release Operator',
        roles: ['admin'],
        productScopes: ['*'],
      },
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === '/api/v1/auth/login-state') {
        return Response.json(
          { mode: 'local' },
          { headers: { 'content-type': 'application/json' } },
        );
      }
      return Response.json(
        {
          type: 'about:blank',
          title: 'Authentication failed',
          status: 401,
          code: 'AUTHENTICATION_FAILED',
          request_id: 'req_session_expired',
        },
        { status: 401, headers: { 'content-type': 'application/problem+json' } },
      );
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App initialEntries={['/products']} />);

    expect(await screen.findByRole('textbox', { name: '用户名' })).toBeVisible();
    expect(sessionStore.getAccessToken()).toBeNull();
    expect(sessionStore.getSnapshot()).toEqual({ status: 'anonymous', reason: 'unauthorized' });
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/products?limit=50',
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: 'Bearer xms_expired_session_token' }),
      }),
    );
  });
});
