import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from '../app/App';

afterEach(() => vi.unstubAllGlobals());

describe('核心授权与错误反馈', () => {
  it('发布者角色在 Release 详情中看不到批准发布操作', async () => {
    render(<App initialRoles={['publisher']} initialEntries={['/releases/release-1']} />);

    expect((await screen.findAllByText('1.2.3')).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: '批准发布' })).not.toBeInTheDocument();
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
});
