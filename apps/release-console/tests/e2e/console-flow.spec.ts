import { expect, test } from '@playwright/test';

test('核心可信发布管理流程', async ({ page }) => {
  const identities = {
    admin: { token: `xms_${'a'.repeat(43)}`, displayName: '林管理员', roles: ['admin'] },
    approver: { token: `xms_${'b'.repeat(43)}`, displayName: 'Bob 审批者', roles: ['approver'] },
    auditor: { token: `xms_${'c'.repeat(43)}`, displayName: '周审计员', roles: ['auditor'] },
  } as const;
  const identityByToken = new Map<string, (typeof identities)[keyof typeof identities]>(
    Object.values(identities).map((identity) => [identity.token, identity]),
  );

  await page.route('**/api/v1/auth/login-state', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ mode: 'local' }),
    }),
  );
  await page.route('**/api/v1/auth/local/login', async (route) => {
    const username = String(route.request().postDataJSON().username);
    const identity = identities[username as keyof typeof identities];
    await route.fulfill({
      status: identity ? 200 : 401,
      contentType: 'application/json',
      body: JSON.stringify(
        identity
          ? {
              access_token: identity.token,
              token_type: 'Bearer',
              expires_at: '2099-08-30T12:00:00Z',
              subject: {
                id: `018f835d-7e4b-7abc-9f42-67a2f5f48e1${username === 'admin' ? '3' : username === 'approver' ? '4' : '5'}`,
                username,
                display_name: identity.displayName,
                kind: 'local',
              },
            }
          : {
              type: 'about:blank',
              title: 'Authentication failed',
              status: 401,
              code: 'AUTHENTICATION_FAILED',
              request_id: 'req_login',
            },
      ),
    });
  });
  await page.route('**/api/v1/auth/session', async (route) => {
    const token = route.request().headers().authorization?.replace('Bearer ', '') ?? '';
    const identity = identityByToken.get(token);
    await route.fulfill({
      status: identity ? 200 : 401,
      contentType: 'application/json',
      body: JSON.stringify({
        subject: identity?.displayName ?? '',
        kind: 'local',
        governed_user_id: '018f835d-7e4b-7abc-9f42-67a2f5f48e13',
        roles: identity?.roles ?? [],
        product_ids: [],
        role_scopes: (identity?.roles ?? []).map((role) => ({
          role,
          effect: 'allow',
          scope_type: 'platform',
        })),
        authentication_assurance: 1,
      }),
    });
  });
  await page.route('**/api/v1/auth/logout', (route) => route.fulfill({ status: 204 }));

  const loginAs = async (username: keyof typeof identities) => {
    await page.getByLabel('用户名').fill(username);
    await page.getByLabel('密码').fill('Current-Strong-Password!');
    await page.getByRole('button', { name: /^登\s*录$/ }).click();
    await expect(page.getByText(identities[username].displayName)).toBeVisible();
  };
  const logout = async () => {
    await page.getByRole('button', { name: '账户菜单' }).click();
    await page.getByText('退出登录', { exact: true }).click();
    await expect(page.getByLabel('用户名')).toBeVisible();
  };

  let productCreateRequests = 0;
  let productCreateBody: unknown;
  await page.route('**/api/v1/products', async (route) => {
    productCreateRequests += 1;
    productCreateBody = route.request().postDataJSON();
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 'desktop-tools',
        display_name: 'Desktop Tools',
        schema_version: 'xminds-product-manifest/v1',
        artifact_types: ['generic-binary'],
        version_scheme: 'semver',
        compatibility_keys: [],
        catalog_format: 'xminds-tuf-v1',
        manifest: {
          schema_version: 'xminds-product-manifest/v1',
          product_id: 'desktop-tools',
          display_name: 'Desktop Tools',
          artifact_types: ['generic-binary'],
          version_scheme: 'semver',
          compatibility_keys: [],
          catalog_format: 'xminds-tuf-v1',
          default_channels: [{ name: 'stable', display_name: 'Stable' }],
        },
        manifest_digest: '3e18a94f00000000000000000000000000000000000000000000000000000000',
        status: 'active',
        channels: [
          {
            product_id: 'desktop-tools',
            name: 'stable',
            display_name: 'Stable',
            position: 0,
            created_at: '2026-08-20T15:10:00Z',
          },
        ],
        created_by: 'admin',
        created_at: '2026-08-20T15:10:00Z',
        updated_at: '2026-08-20T15:10:00Z',
      }),
    });
  });

  await page.goto('/products/new');
  await expect(page).toHaveTitle('Xminds Release Platform');
  await loginAs('admin');
  await page.getByLabel('产品标识').fill('desktop-tools');
  await page.getByLabel('产品名称').fill('Desktop Tools');
  await page.getByRole('button', { name: '创建产品' }).click();
  await expect(page.getByText('产品已创建并通过 Manifest 校验')).toBeVisible();
  expect(productCreateRequests).toBe(1);
  expect(productCreateBody).toEqual({
    schema_version: 'xminds-product-manifest/v1',
    product_id: 'desktop-tools',
    display_name: 'Desktop Tools',
    artifact_types: ['generic-binary'],
    version_scheme: 'semver',
    compatibility_keys: [],
    catalog_format: 'xminds-tuf-v1',
    default_channels: [{ name: 'stable', display_name: 'Stable' }],
  });

  await page.getByRole('button', { name: /制品/ }).click();
  await page.getByRole('button', { name: '上传制品' }).click();
  const uploadDialog = page.getByRole('dialog', { name: '可恢复分块上传' });
  await uploadDialog.getByRole('button', { name: '开始上传' }).click();
  await expect(uploadDialog.getByText('连接已中断，可从第 248 个分块继续')).toBeVisible();
  await uploadDialog.getByRole('button', { name: '继续上传' }).click();
  await expect(uploadDialog).toBeHidden();
  await expect(page.getByText('ngep-desktop-1.2.4-arm64.dmg').first()).toBeVisible();

  await page.getByRole('button', { name: /Release/ }).click();
  await page.getByRole('button', { name: '创建 Release' }).click();
  const wizard = page.getByTestId('white-detail-drawer');
  await wizard.getByRole('button', { name: '下一步' }).click();
  await wizard.getByRole('button', { name: '下一步' }).click();
  await wizard.getByRole('button', { name: '下一步' }).click();
  await expect(wizard.getByText('提交后等待不同审批者审批')).toBeVisible();
  await wizard.getByRole('button', { name: '确认提交审批' }).click();
  await expect(page.getByText('Release 已提交，等待不同审批者审批')).toBeVisible();

  await page.getByRole('button', { name: '查看详情' }).first().click();
  await page.getByRole('button', { name: '批准发布' }).click();
  await page.getByRole('dialog').getByRole('button', { name: '确认批准' }).click();
  await page.getByRole('button', { name: '开始发布' }).click();
  await page.getByRole('dialog').getByRole('button', { name: '确认发布' }).click();
  await expect(
    page.getByTestId('pro-page-header').getByText('已发布', { exact: true }),
  ).toBeVisible();

  await page.getByText('集成与分发', { exact: true }).click();
  await page.getByRole('button', { name: /SCM 连接/ }).click();
  await page.getByRole('button', { name: /新建连接/ }).click();
  const scmDrawer = page.getByTestId('white-detail-drawer');
  await scmDrawer.getByLabel('私有 Base URL').fill('https://git.corp.example');
  await scmDrawer.getByLabel('API URL').fill('https://git.corp.example/api/v3');
  await scmDrawer.getByLabel('仓库').fill('platform/desktop-tools');
  await scmDrawer.getByRole('textbox', { name: '企业 CA 指纹' }).fill('SHA256:5A:9C:7E:21');
  await scmDrawer.getByRole('checkbox', { name: '我已通过独立可信渠道核对企业 CA 指纹' }).check();
  await scmDrawer.getByRole('button', { name: '测试连接与能力' }).click();
  await expect(scmDrawer.getByText('Webhook')).toBeVisible();
  await scmDrawer.getByRole('button', { name: '保存连接' }).click();

  await page.getByRole('button', { name: /分发端点/ }).click();
  await expect(page.getByText('华东主 Origin')).toBeVisible();
  await expect(page.getByText('健康').first()).toBeVisible();

  await page.getByText('可观测与治理', { exact: true }).click();
  await page.getByRole('button', { name: /日志中心/ }).click();
  await logout();
  await loginAs('auditor');
  await expect(page.getByRole('button', { name: '导出审计证据' })).toBeVisible();
  await page.getByRole('button', { name: '查看证据' }).first().click();
  await expect(page.getByText('req_01J5A0JH8Q4V')).toBeVisible();
});
