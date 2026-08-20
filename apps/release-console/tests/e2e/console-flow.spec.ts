import { expect, test } from '@playwright/test';

test('核心可信发布管理流程', async ({ page }) => {
  const chooseNextRole = async () => {
    const roleSelect = page.getByLabel('演示角色');
    await roleSelect.click();
    await roleSelect.press('ArrowDown');
    await roleSelect.press('Enter');
  };

  let productCreateRequests = 0;
  await page.route('**/api/v1/products', async (route) => {
    productCreateRequests += 1;
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 'desktop-tools',
        name: 'Desktop Tools',
        description: '桌面工具可信发布',
        defaultChannel: 'stable',
        channels: ['stable'],
        status: 'active',
        manifestDigest: 'sha256:3e18…a94f',
        updatedAt: '2026-08-20T15:10:00Z',
      }),
    });
  });

  await page.goto('/products/new');
  await expect(page).toHaveTitle('Xminds Release Platform');
  await page.getByLabel('产品标识').fill('desktop-tools');
  await page.getByLabel('产品名称').fill('Desktop Tools');
  await page.getByRole('button', { name: '创建产品' }).click();
  await expect(page.getByText('产品已创建并通过 Manifest 校验')).toBeVisible();
  expect(productCreateRequests).toBe(1);

  await chooseNextRole();
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

  await chooseNextRole();
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
  await page.getByRole('button', { name: /操作审计/ }).click();
  await chooseNextRole();
  await expect(page.getByRole('button', { name: '导出审计证据' })).toBeVisible();
  await page.getByRole('button', { name: '查看证据' }).first().click();
  await expect(page.getByText('req_01J5A0JH8Q4V')).toBeVisible();
});
