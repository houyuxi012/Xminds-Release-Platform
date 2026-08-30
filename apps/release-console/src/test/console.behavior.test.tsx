import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from '../app/App';

describe('控制台交互与可访问性', () => {
  it('使用白色导航语义并支持键盘进入主流程', async () => {
    render(<App initialEntries={['/']} initialRoles={['admin']} />);

    expect(await screen.findByTestId('console-shell')).toHaveAttribute(
      'data-navigation-surface',
      'white',
    );
    const createRelease = await screen.findByRole('button', { name: '创建 Release' });
    createRelease.focus();
    expect(createRelease).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    expect(
      await screen.findByText('通过不可变内容、职责分离审批和幂等发布尝试构建可信发布链。'),
    ).toBeVisible();
  });

  it('审批者可批准他人提交的 Release，并需完成二次确认', async () => {
    render(<App initialEntries={['/releases/release-1']} initialRoles={['approver']} />);

    await userEvent.click(await screen.findByRole('button', { name: '批准发布' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getAllByText('批准 Release 1.2.3').length).toBeGreaterThan(0);
    await userEvent.click(within(dialog).getByRole('button', { name: '确认批准' }));

    expect(await screen.findByRole('button', { name: '开始发布' })).toBeVisible();
  });

  it('分块上传中断后可继续，并显示服务端摘要校验结果', async () => {
    render(<App initialEntries={['/artifacts']} initialRoles={['publisher']} />);

    await userEvent.click(await screen.findByRole('button', { name: '上传制品' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: '开始上传' }));
    const interrupted = await within(dialog).findByText('连接已中断，可从第 248 个分块继续');
    await waitFor(() => expect(interrupted).toBeVisible());
    await userEvent.click(within(dialog).getByRole('button', { name: '继续上传' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await screen.findByText('上传完成，服务端 SHA-256 校验通过')).toBeVisible();
    expect((await screen.findAllByText('ngep-desktop-1.2.4-arm64.dmg')).length).toBeGreaterThan(0);
  });

  it('产品详情使用白色抽屉语义，不依赖组件库内部类名', async () => {
    render(<App initialEntries={['/products']} initialRoles={['admin']} />);

    const detailButtons = await screen.findAllByRole('button', { name: '查看详情' });
    await userEvent.click(detailButtons[0]);

    expect(await screen.findByTestId('white-detail-drawer')).toBeVisible();
    expect(
      within(screen.getByTestId('white-detail-drawer')).getByText('Manifest 摘要'),
    ).toBeVisible();
  });

  it('证据导出仅对审计员显示', async () => {
    const adminView = render(<App initialEntries={['/audit']} initialRoles={['admin']} />);
    expect(await screen.findByText('审计事件不可修改或删除')).toBeVisible();
    expect(screen.queryByRole('button', { name: '导出审计证据' })).not.toBeInTheDocument();
    adminView.unmount();

    render(<App initialEntries={['/audit']} initialRoles={['auditor']} />);
    expect(await screen.findByRole('button', { name: '导出审计证据' })).toBeVisible();
  });

  it('日志中心可切换到应用请求并展示授权快照字段', async () => {
    render(<App initialEntries={['/audit']} initialRoles={['auditor']} />);

    await userEvent.click(await screen.findByRole('tab', { name: '应用请求日志' }));
    expect(await screen.findByText('Next-Gen Enterprise Portal 商业授权')).toBeVisible();
    expect(screen.getByText('2.4.0')).toBeVisible();
    expect(screen.getByText('LIC-2026-000184')).toBeVisible();
    expect(screen.getByText('2026-12-31 23:59:59')).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: '查看证据' }));
    const drawer = await screen.findByTestId('white-detail-drawer');
    expect(within(drawer).getByText('授权名称')).toBeVisible();
    expect(within(drawer).getByText('客户端应用版本')).toBeVisible();
  });

  it('Release 向导不能跳过当前步骤必填校验', async () => {
    render(<App initialEntries={['/releases']} initialRoles={['publisher']} />);

    await userEvent.click(await screen.findByRole('button', { name: '创建 Release' }));
    const drawer = await screen.findByTestId('white-detail-drawer');
    const version = within(drawer).getByPlaceholderText('例如 1.2.4');
    await userEvent.clear(version);
    await userEvent.click(within(drawer).getByRole('button', { name: '下一步' }));

    await waitFor(() => expect(version).toHaveAttribute('aria-invalid', 'true'));
    expect(version).toBeVisible();
  });

  it('修改 SCM 配置后会使旧能力探测结果失效', async () => {
    render(<App initialEntries={['/scm']} initialRoles={['admin']} />);

    await userEvent.click(await screen.findByRole('button', { name: /新建连接/ }));
    const drawer = await screen.findByTestId('white-detail-drawer');
    await userEvent.type(
      within(drawer).getByRole('textbox', { name: '私有 Base URL' }),
      'https://git.example',
    );
    await userEvent.type(
      within(drawer).getByRole('textbox', { name: 'API URL' }),
      'https://git.example/api/v3',
    );
    await userEvent.type(within(drawer).getByRole('textbox', { name: '仓库' }), 'platform/ngep');
    await userEvent.type(
      within(drawer).getByRole('textbox', { name: '企业 CA 指纹' }),
      'SHA256:01:23',
    );
    await userEvent.click(
      within(drawer).getByRole('checkbox', {
        name: '我已通过独立可信渠道核对企业 CA 指纹',
      }),
    );
    await userEvent.click(within(drawer).getByRole('button', { name: /测试连接与能力/ }));
    expect(await within(drawer).findByText('Webhook')).toBeVisible();
    expect(within(drawer).getByRole('button', { name: '保存连接' })).toBeEnabled();

    await userEvent.type(within(drawer).getByRole('textbox', { name: 'API URL' }), '/changed');
    expect(within(drawer).queryByText('Webhook')).not.toBeInTheDocument();
    expect(within(drawer).getByRole('button', { name: '保存连接' })).toBeDisabled();
  });
});
