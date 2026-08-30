import { defineConfig, devices } from '@playwright/test';
import { lstatSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

function requireLoopbackOrigin(name: string, value: string | undefined): string {
  if (!value?.trim()) throw new Error(`${name} is required`);
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error(`${name} must be a valid URL`);
  }
  const loopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';
  if (
    !loopback ||
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`${name} must be an origin-only loopback HTTP(S) URL`);
  }
  return parsed.origin;
}

const realApiTarget = requireLoopbackOrigin(
  'XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET',
  process.env.XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET,
);
const credentialsPath = process.env.XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE?.trim();
if (!credentialsPath || !isAbsolute(credentialsPath)) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE must be an absolute path');
}
const credentialsInfo = lstatSync(credentialsPath);
if (credentialsInfo.isSymbolicLink() || !credentialsInfo.isFile()) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE must be a regular non-link file');
}
if ((credentialsInfo.mode & 0o777) !== 0o600) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE must have mode 0600');
}
if (typeof process.getuid === 'function' && credentialsInfo.uid !== process.getuid()) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE must be owned by the current user');
}
const credentialsParentInfo = statSync(dirname(credentialsPath));
if (!credentialsParentInfo.isDirectory() || (credentialsParentInfo.mode & 0o077) !== 0) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE parent directory must be private');
}
const repositoryRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const canonicalCredentialsPath = realpathSync(credentialsPath);
const repositoryRelativePath = relative(repositoryRoot, canonicalCredentialsPath);
if (
  repositoryRelativePath === '' ||
  (repositoryRelativePath !== '..' &&
    !repositoryRelativePath.startsWith(`..${sep}`) &&
    !isAbsolute(repositoryRelativePath))
) {
  throw new Error('XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE must be outside the repository');
}

export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: 'real-auth.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  outputDir: '/tmp/xminds-release-console-real-playwright',
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 90_000,
    env: { XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET: realApiTarget },
  },
});
