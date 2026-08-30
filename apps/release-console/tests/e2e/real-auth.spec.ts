import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

interface RuntimeCredentials {
  username: string;
  password: string;
  totp_secret: string;
  display_name: string;
  totp_available_at: string;
}

function loadCredentials(): RuntimeCredentials {
  const path = process.env.XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE?.trim();
  if (!path) {
    throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE is required');
  }
  const credentials = JSON.parse(readFileSync(path, 'utf8')) as Partial<RuntimeCredentials>;
  for (const field of [
    'username',
    'password',
    'totp_secret',
    'display_name',
    'totp_available_at',
  ] as const) {
    if (typeof credentials[field] !== 'string' || credentials[field].trim() === '') {
      throw new Error(`runtime credentials field ${field} is required`);
    }
  }
  return credentials as RuntimeCredentials;
}

function decodeBase32(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const character of value.trim().toUpperCase().replaceAll('=', '')) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error('runtime TOTP secret is invalid');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function currentTOTP(secret: string): string {
  const counter = BigInt(Math.floor(Date.now() / 30_000));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac('sha1', decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value =
    (((digest[offset] & 0x7f) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3]) %
    1_000_000;
  return value.toString().padStart(6, '0');
}

test('真实 API 完成本地 MFA 登录、产品创建读取和退出', async ({ page, request }) => {
  test.setTimeout(75_000);
  const credentials = loadCredentials();
  const apiTarget = process.env.XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET?.trim();
  if (!apiTarget) throw new Error('XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET is required');
  const apiOrigin = new URL(apiTarget).origin;
  const readiness = await request.get(`${apiOrigin}/health/ready`);
  expect(readiness.status()).toBe(200);
  let sessionToken = '';
  page.on('request', (outbound) => {
    if (outbound.url().endsWith('/api/v1/auth/session')) {
      sessionToken = outbound.headers().authorization?.replace(/^Bearer\s+/i, '') ?? '';
    }
  });
  const nextTOTPWindow = (Math.floor(Date.now() / 30_000) + 1) * 30_000;
  const totpAvailableAt = Math.max(
    new Date(credentials.totp_available_at).getTime(),
    nextTOTPWindow,
  );

  await expect
    .poll(() => Date.now(), {
      message: '等待激活验证码的防重放窗口结束',
      timeout: 35_000,
      intervals: [250, 500, 1_000],
    })
    .toBeGreaterThanOrEqual(totpAvailableAt);

  await page.goto('/products');
  await expect(page).toHaveTitle('Xminds Release Platform');
  await page.getByLabel('用户名').fill(credentials.username);
  await page.getByLabel('密码').fill(credentials.password);
  await page.getByLabel('MFA 动态验证码（如已启用）').fill(currentTOTP(credentials.totp_secret));
  await page.getByRole('button', { name: /^登\s*录$/ }).click();

  await expect(page.getByTestId('console-shell')).toBeVisible();
  await expect(page.getByText(credentials.display_name)).toBeVisible();
  await expect(
    page.getByText('统一注册产品 Manifest、默认通道与发布范围，不在业务代码中硬编码产品特例。'),
  ).toBeVisible();
  const productID = `runtime-${Date.now().toString(36)}`;
  await page.getByRole('button', { name: '创建产品' }).click();
  await page.getByLabel('产品标识').fill(productID);
  await page.getByLabel('产品名称').fill('Runtime Acceptance Product');
  await page.getByRole('button', { name: '创建产品' }).click();
  await expect(page.getByText('产品已创建并通过 Manifest 校验')).toBeVisible();
  await page.getByRole('button', { name: '返回产品列表' }).click();
  await expect(page.getByText(productID)).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);

  await page.getByRole('button', { name: '账户菜单' }).click();
  await page.getByText('退出登录', { exact: true }).click();
  await expect(page.getByLabel('用户名')).toBeVisible();
  await expect(page.getByTestId('console-shell')).toBeHidden();
  expect(sessionToken).toMatch(/^xms_[A-Za-z0-9_-]{43}$/);
  const revokedSession = await request.get(`${apiOrigin}/api/v1/auth/session`, {
    headers: { authorization: `Bearer ${sessionToken}` },
  });
  expect(revokedSession.status()).toBe(401);
  sessionToken = '';
});
