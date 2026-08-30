import { sessionStore } from '../auth/sessionStore';
import type {
  CurrentSession,
  CurrentSessionRoleScope,
  LocalAuthenticatedSubject,
  LocalLoginInput,
  LocalLoginResult,
  LoginMode,
  PlatformRole,
  ProblemDetails,
  Product,
  ProductChannel,
  ProductManifestV1,
  ProductPage,
  PublicLoginState,
} from './types';

export type { ProductManifestV1 } from './types';

export class ApiProblemError extends Error {
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title);
    this.name = 'ApiProblemError';
    this.problem = problem;
  }
}

export class ApiContractError extends Error {
  readonly path: string;

  constructor(path: string, detail: string) {
    super(`API 响应契约无效（${path}）：${detail}`);
    this.name = 'ApiContractError';
    this.path = path;
  }
}

export type AccessTokenProvider = () =>
  | string
  | null
  | undefined
  | Promise<string | null | undefined>;

export interface ApiClientOptions {
  baseUrl?: string;
  getAccessToken?: AccessTokenProvider;
  onUnauthorized?: () => void | Promise<void>;
}

export interface ProductPageParameters {
  limit?: number;
  cursor?: string;
}

export interface ApiClient {
  getLoginState(): Promise<PublicLoginState>;
  loginLocal(input: LocalLoginInput): Promise<LocalLoginResult>;
  loginEmergency(input: LocalLoginInput): Promise<LocalLoginResult>;
  getCurrentSession(): Promise<CurrentSession>;
  logout(): Promise<void>;
  listProducts(parameters?: ProductPageParameters): Promise<ProductPage>;
  getProduct(productId: string): Promise<Product>;
  createProduct(manifest: ProductManifestV1): Promise<Product>;
}

type JsonRecord = Record<string, unknown>;
type Decoder<T> = (value: unknown, path: string) => T;

interface ResolvedApiClientOptions {
  baseUrl: string;
  getAccessToken: AccessTokenProvider;
  onUnauthorized: () => void | Promise<void>;
}

interface RequestPolicy {
  authenticated: boolean;
}

function expectRecord(value: unknown, path: string): JsonRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ApiContractError(path, '应为 JSON 对象');
  }
  return value as JsonRecord;
}

function expectString(value: unknown, path: string): string {
  if (typeof value !== 'string') {
    throw new ApiContractError(path, '应为字符串');
  }
  return value;
}

function expectNonEmptyString(value: unknown, path: string): string {
  const result = expectString(value, path);
  if (result.length === 0) {
    throw new ApiContractError(path, '不得为空');
  }
  return result;
}

function expectOptionalString(value: unknown, path: string): string | undefined {
  return value === undefined ? undefined : expectNonEmptyString(value, path);
}

function expectStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new ApiContractError(path, '应为字符串数组');
  }
  return value.map((item, index) => expectNonEmptyString(item, `${path}[${index}]`));
}

function expectInteger(value: unknown, path: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ApiContractError(path, `应为 ${minimum} 至 ${maximum} 的整数`);
  }
  return value as number;
}

function expectDateTime(value: unknown, path: string): string {
  const result = expectNonEmptyString(value, path);
  if (Number.isNaN(Date.parse(result))) {
    throw new ApiContractError(path, '应为 RFC 3339 时间');
  }
  return result;
}

function decodeProductManifest(value: unknown, path: string): ProductManifestV1 {
  const record = expectRecord(value, path);
  const schemaVersion = expectNonEmptyString(record.schema_version, `${path}.schema_version`);
  const versionScheme = expectNonEmptyString(record.version_scheme, `${path}.version_scheme`);
  const catalogFormat = expectNonEmptyString(record.catalog_format, `${path}.catalog_format`);
  if (schemaVersion !== 'xminds-product-manifest/v1') {
    throw new ApiContractError(`${path}.schema_version`, '不支持的 Manifest 版本');
  }
  if (versionScheme !== 'semver') {
    throw new ApiContractError(`${path}.version_scheme`, '不支持的版本规则');
  }
  if (catalogFormat !== 'xminds-tuf-v1') {
    throw new ApiContractError(`${path}.catalog_format`, '不支持的目录格式');
  }
  if (!Array.isArray(record.default_channels) || record.default_channels.length === 0) {
    throw new ApiContractError(`${path}.default_channels`, '应为非空通道数组');
  }

  return {
    schema_version: schemaVersion,
    product_id: expectNonEmptyString(record.product_id, `${path}.product_id`),
    display_name: expectNonEmptyString(record.display_name, `${path}.display_name`),
    artifact_types: expectStringArray(record.artifact_types, `${path}.artifact_types`),
    version_scheme: versionScheme,
    compatibility_keys: expectStringArray(record.compatibility_keys, `${path}.compatibility_keys`),
    catalog_format: catalogFormat,
    default_channels: record.default_channels.map((channel, index) => {
      const channelPath = `${path}.default_channels[${index}]`;
      const channelRecord = expectRecord(channel, channelPath);
      return {
        name: expectNonEmptyString(channelRecord.name, `${channelPath}.name`),
        display_name: expectNonEmptyString(
          channelRecord.display_name,
          `${channelPath}.display_name`,
        ),
      };
    }),
  };
}

function decodeProductChannel(value: unknown, path: string): ProductChannel {
  const record = expectRecord(value, path);
  if (!Number.isInteger(record.position) || (record.position as number) < 0) {
    throw new ApiContractError(`${path}.position`, '应为非负整数');
  }
  return {
    productId: expectNonEmptyString(record.product_id, `${path}.product_id`),
    name: expectNonEmptyString(record.name, `${path}.name`),
    displayName: expectNonEmptyString(record.display_name, `${path}.display_name`),
    position: record.position as number,
    createdAt: expectDateTime(record.created_at, `${path}.created_at`),
  };
}

function decodeProduct(value: unknown, path: string): Product {
  const record = expectRecord(value, path);
  const status = expectNonEmptyString(record.status, `${path}.status`);
  if (status !== 'active' && status !== 'inactive') {
    throw new ApiContractError(`${path}.status`, '应为 active 或 inactive');
  }
  const manifestDigest = expectNonEmptyString(record.manifest_digest, `${path}.manifest_digest`);
  if (!/^[0-9a-f]{64}$/.test(manifestDigest)) {
    throw new ApiContractError(`${path}.manifest_digest`, '应为 64 位小写十六进制 SHA-256');
  }
  if (!Array.isArray(record.channels)) {
    throw new ApiContractError(`${path}.channels`, '应为通道数组');
  }
  const channels = record.channels.map((channel, index) =>
    decodeProductChannel(channel, `${path}.channels[${index}]`),
  );
  const defaultChannel = channels.reduce<ProductChannel | undefined>(
    (current, channel) => (!current || channel.position < current.position ? channel : current),
    undefined,
  );

  return {
    id: expectNonEmptyString(record.id, `${path}.id`),
    displayName: expectNonEmptyString(record.display_name, `${path}.display_name`),
    schemaVersion: expectNonEmptyString(record.schema_version, `${path}.schema_version`),
    artifactTypes: expectStringArray(record.artifact_types, `${path}.artifact_types`),
    versionScheme: expectNonEmptyString(record.version_scheme, `${path}.version_scheme`),
    compatibilityKeys: expectStringArray(record.compatibility_keys, `${path}.compatibility_keys`),
    catalogFormat: expectNonEmptyString(record.catalog_format, `${path}.catalog_format`),
    manifest: decodeProductManifest(record.manifest, `${path}.manifest`),
    defaultChannel: defaultChannel?.name ?? '',
    channels,
    status,
    manifestDigest,
    createdBy: expectNonEmptyString(record.created_by, `${path}.created_by`),
    createdAt: expectDateTime(record.created_at, `${path}.created_at`),
    updatedAt: expectDateTime(record.updated_at, `${path}.updated_at`),
    deactivatedAt: record.deactivated_at
      ? expectDateTime(record.deactivated_at, `${path}.deactivated_at`)
      : undefined,
  };
}

function decodeProductPage(value: unknown, path: string): ProductPage {
  const record = expectRecord(value, path);
  if (!Array.isArray(record.items)) {
    throw new ApiContractError(`${path}.items`, '应为产品数组');
  }
  return {
    items: record.items.map((item, index) => decodeProduct(item, `${path}.items[${index}]`)),
    nextCursor: expectOptionalString(record.next_cursor, `${path}.next_cursor`),
  };
}

const loginModes = new Set<LoginMode>(['local', 'configuring', 'sso', 'fault']);
const platformRoles = new Set<PlatformRole>([
  'admin',
  'publisher',
  'approver',
  'auditor',
  'viewer',
]);

function decodeLoginMode(value: unknown, path: string): LoginMode {
  const mode = expectNonEmptyString(value, path) as LoginMode;
  if (!loginModes.has(mode)) {
    throw new ApiContractError(path, '应为 local、configuring、sso 或 fault');
  }
  return mode;
}

function decodePlatformRole(value: unknown, path: string): PlatformRole {
  const role = expectNonEmptyString(value, path) as PlatformRole;
  if (!platformRoles.has(role)) {
    throw new ApiContractError(path, '是不受支持的平台角色');
  }
  return role;
}

function decodeLoginState(value: unknown, path: string): PublicLoginState {
  const record = expectRecord(value, path);
  return { mode: decodeLoginMode(record.mode, `${path}.mode`) };
}

function decodeAuthenticatedSubject(value: unknown, path: string): LocalAuthenticatedSubject {
  const record = expectRecord(value, path);
  const kind = expectNonEmptyString(record.kind, `${path}.kind`);
  if (kind !== 'local' && kind !== 'emergency') {
    throw new ApiContractError(`${path}.kind`, '应为 local 或 emergency');
  }
  return {
    id: expectNonEmptyString(record.id, `${path}.id`),
    username: expectNonEmptyString(record.username, `${path}.username`),
    displayName: expectNonEmptyString(record.display_name, `${path}.display_name`),
    kind,
  };
}

function decodeLocalLoginResult(value: unknown, path: string): LocalLoginResult {
  const record = expectRecord(value, path);
  const accessToken = expectNonEmptyString(record.access_token, `${path}.access_token`);
  if (!/^xms_[A-Za-z0-9_-]{43}$/.test(accessToken)) {
    throw new ApiContractError(`${path}.access_token`, '不是合法的不透明本地会话令牌');
  }
  const tokenType = expectNonEmptyString(record.token_type, `${path}.token_type`);
  if (tokenType !== 'Bearer') {
    throw new ApiContractError(`${path}.token_type`, '应为 Bearer');
  }
  return {
    accessToken,
    tokenType,
    expiresAt: expectDateTime(record.expires_at, `${path}.expires_at`),
    subject: decodeAuthenticatedSubject(record.subject, `${path}.subject`),
  };
}

function decodeCurrentSessionRoleScope(value: unknown, path: string): CurrentSessionRoleScope {
  const record = expectRecord(value, path);
  const effect = expectNonEmptyString(record.effect, `${path}.effect`);
  if (effect !== 'allow' && effect !== 'deny') {
    throw new ApiContractError(`${path}.effect`, '应为 allow 或 deny');
  }
  const scopeType = expectNonEmptyString(record.scope_type, `${path}.scope_type`);
  if (scopeType !== 'platform' && scopeType !== 'product' && scopeType !== 'product_channel') {
    throw new ApiContractError(`${path}.scope_type`, '是不受支持的授权范围');
  }
  return {
    role: decodePlatformRole(record.role, `${path}.role`),
    effect,
    scopeType,
    productId: expectOptionalString(record.product_id, `${path}.product_id`),
    channelName: expectOptionalString(record.channel_name, `${path}.channel_name`),
  };
}

function decodeCurrentSession(value: unknown, path: string): CurrentSession {
  const record = expectRecord(value, path);
  const kind = expectNonEmptyString(record.kind, `${path}.kind`);
  if (kind !== 'human' && kind !== 'local' && kind !== 'workload') {
    throw new ApiContractError(`${path}.kind`, '是不受支持的主体类型');
  }
  if (!Array.isArray(record.roles) || !Array.isArray(record.role_scopes)) {
    throw new ApiContractError(path, 'roles 与 role_scopes 应为数组');
  }
  return {
    subject: expectNonEmptyString(record.subject, `${path}.subject`),
    kind,
    governedUserId: expectOptionalString(record.governed_user_id, `${path}.governed_user_id`),
    roles: record.roles.map((role, index) => decodePlatformRole(role, `${path}.roles[${index}]`)),
    productIds: expectStringArray(record.product_ids, `${path}.product_ids`),
    roleScopes: record.role_scopes.map((scope, index) =>
      decodeCurrentSessionRoleScope(scope, `${path}.role_scopes[${index}]`),
    ),
    authenticationAssurance: expectInteger(
      record.authentication_assurance,
      `${path}.authentication_assurance`,
      0,
      3,
    ),
  };
}

function decodeProblem(value: unknown, response: Response): ProblemDetails {
  try {
    const record = expectRecord(value, '$problem');
    return {
      type: expectNonEmptyString(record.type, '$problem.type'),
      title: expectNonEmptyString(record.title, '$problem.title'),
      status: typeof record.status === 'number' ? record.status : response.status,
      detail: expectOptionalString(record.detail, '$problem.detail'),
      code: expectOptionalString(record.code, '$problem.code'),
      request_id:
        expectOptionalString(record.request_id, '$problem.request_id') ??
        response.headers.get('x-request-id') ??
        undefined,
    };
  } catch {
    return {
      type: 'about:blank',
      title: '请求失败',
      status: response.status,
      request_id: response.headers.get('x-request-id') || undefined,
    };
  }
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
}

async function request<T>(
  path: string,
  init: RequestInit | undefined,
  decoder: Decoder<T>,
  options: ResolvedApiClientOptions,
  policy: RequestPolicy = { authenticated: true },
): Promise<T> {
  const accessToken = policy.authenticated ? (await options.getAccessToken())?.trim() : null;
  const headers: Record<string, string> = {
    accept: 'application/json, application/problem+json',
  };
  if (init?.body !== undefined && init.body !== null) {
    headers['content-type'] = 'application/json';
  }
  if (accessToken) {
    headers.authorization = `Bearer ${accessToken}`;
  }
  const response = await fetch(`${options.baseUrl}${path}`, {
    ...init,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { ...headers, ...init?.headers },
  });

  if (!response.ok) {
    if (policy.authenticated && response.status === 401) {
      await options.onUnauthorized();
    }
    const contentType = response.headers.get('content-type') || '';
    if (
      contentType.includes('application/problem+json') ||
      contentType.includes('application/json')
    ) {
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        payload = undefined;
      }
      throw new ApiProblemError(decodeProblem(payload, response));
    }
    throw new ApiProblemError({
      type: 'about:blank',
      title: '请求失败',
      status: response.status,
      request_id: response.headers.get('x-request-id') || undefined,
    });
  }

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    throw new ApiContractError('$response', '成功响应必须为 application/json');
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiContractError('$response', '成功响应不是有效 JSON');
  }
  return decoder(payload, '$response');
}

async function requestNoContent(
  path: string,
  init: RequestInit,
  options: ResolvedApiClientOptions,
): Promise<void> {
  const accessToken = (await options.getAccessToken())?.trim();
  const headers: Record<string, string> = {
    accept: 'application/problem+json',
  };
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  const response = await fetch(`${options.baseUrl}${path}`, {
    ...init,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { ...headers, ...init.headers },
  });
  if (response.status === 204) return;
  if (response.status === 401) await options.onUnauthorized();
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }
  throw new ApiProblemError(decodeProblem(payload, response));
}

function productPagePath(parameters: ProductPageParameters = {}): string {
  const query = new URLSearchParams();
  if (parameters.limit !== undefined) {
    if (!Number.isInteger(parameters.limit) || parameters.limit < 1 || parameters.limit > 200) {
      throw new RangeError('产品列表 limit 必须为 1 至 200 的整数');
    }
    query.set('limit', String(parameters.limit));
  }
  if (parameters.cursor) {
    query.set('cursor', parameters.cursor);
  }
  const serialized = query.toString();
  return serialized ? `/api/v1/products?${serialized}` : '/api/v1/products';
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const resolvedOptions: ResolvedApiClientOptions = {
    baseUrl: normalizeBaseUrl(options.baseUrl ?? ''),
    getAccessToken: options.getAccessToken ?? (() => null),
    onUnauthorized: options.onUnauthorized ?? (() => undefined),
  };
  return {
    getLoginState() {
      return request('/api/v1/auth/login-state', undefined, decodeLoginState, resolvedOptions, {
        authenticated: false,
      });
    },
    loginLocal(input) {
      return request(
        '/api/v1/auth/local/login',
        { method: 'POST', body: JSON.stringify(localLoginBody(input)) },
        decodeLocalLoginResult,
        resolvedOptions,
        { authenticated: false },
      );
    },
    loginEmergency(input) {
      return request(
        '/api/v1/auth/emergency/login',
        { method: 'POST', body: JSON.stringify(localLoginBody(input)) },
        decodeLocalLoginResult,
        resolvedOptions,
        { authenticated: false },
      );
    },
    getCurrentSession() {
      return request('/api/v1/auth/session', undefined, decodeCurrentSession, resolvedOptions);
    },
    logout() {
      return requestNoContent('/api/v1/auth/logout', { method: 'POST' }, resolvedOptions);
    },
    listProducts(parameters) {
      return request(productPagePath(parameters), undefined, decodeProductPage, resolvedOptions);
    },
    getProduct(productId) {
      return request(
        `/api/v1/products/${encodeURIComponent(productId)}`,
        undefined,
        decodeProduct,
        resolvedOptions,
      );
    },
    createProduct(manifest) {
      return request(
        '/api/v1/products',
        { method: 'POST', body: JSON.stringify(manifest) },
        decodeProduct,
        resolvedOptions,
      );
    },
  };
}

function localLoginBody(input: LocalLoginInput): Record<string, string> {
  const body: Record<string, string> = {
    username: input.username,
    password: input.password,
  };
  if (input.mfaProof) {
    body.mfa_proof = input.mfaProof;
  }
  if (input.recoveryCode) {
    body.recovery_code = input.recoveryCode;
  }
  return body;
}

export const apiClient = createApiClient({
  getAccessToken: sessionStore.getAccessToken,
  onUnauthorized: () => sessionStore.clear('unauthorized'),
});
