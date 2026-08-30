export type PlatformRole = 'admin' | 'publisher' | 'approver' | 'auditor' | 'viewer';

export interface Principal {
  id: string;
  displayName: string;
  roles: PlatformRole[];
  productScopes: string[];
}

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  code?: string;
  request_id?: string;
}

export type LoginMode = 'local' | 'configuring' | 'sso' | 'fault';

export interface PublicLoginState {
  mode: LoginMode;
}

export interface LocalLoginInput {
  username: string;
  password: string;
  mfaProof?: string;
  recoveryCode?: string;
}

export interface LocalAuthenticatedSubject {
  id: string;
  username: string;
  displayName: string;
  kind: 'local' | 'emergency';
}

export interface LocalLoginResult {
  accessToken: string;
  tokenType: 'Bearer';
  expiresAt: string;
  subject: LocalAuthenticatedSubject;
}

export interface CurrentSessionRoleScope {
  role: PlatformRole;
  effect: 'allow' | 'deny';
  scopeType: 'platform' | 'product' | 'product_channel';
  productId?: string;
  channelName?: string;
}

export interface CurrentSession {
  subject: string;
  kind: 'human' | 'local' | 'workload';
  governedUserId?: string;
  roles: PlatformRole[];
  productIds: string[];
  roleScopes: CurrentSessionRoleScope[];
  authenticationAssurance: number;
}

export interface Product {
  id: string;
  displayName: string;
  schemaVersion: string;
  artifactTypes: string[];
  versionScheme: string;
  compatibilityKeys: string[];
  catalogFormat: string;
  manifest: ProductManifestV1;
  defaultChannel: string;
  channels: ProductChannel[];
  status: 'active' | 'inactive';
  manifestDigest: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  deactivatedAt?: string;
}

export interface ProductManifestV1 {
  schema_version: 'xminds-product-manifest/v1';
  product_id: string;
  display_name: string;
  artifact_types: string[];
  version_scheme: 'semver';
  compatibility_keys: string[];
  catalog_format: 'xminds-tuf-v1';
  default_channels: ProductChannelManifest[];
}

export interface ProductChannelManifest {
  name: string;
  display_name: string;
}

export interface ProductChannel {
  productId: string;
  name: string;
  displayName: string;
  position: number;
  createdAt: string;
}

export interface ProductPage {
  items: Product[];
  nextCursor?: string;
}

export interface Artifact {
  id: string;
  product: string;
  filename: string;
  version: string;
  size: string;
  sha256: string;
  status: 'verified' | 'uploading' | 'quarantined';
  progress: number;
  updatedAt: string;
}

export type ReleaseStatus =
  | 'draft'
  | 'submitted'
  | 'approved'
  | 'publishing'
  | 'published'
  | 'failed';

export interface ReleaseRecord {
  id: string;
  product: string;
  version: string;
  channel: string;
  status: ReleaseStatus;
  submittedBy: string;
  updatedAt: string;
  notes: string;
  artifacts: string[];
}

export interface ScmConnection {
  id: string;
  name: string;
  provider: 'GitHub' | 'GitHub Enterprise Server' | 'GitLab Self-Managed';
  baseUrl: string;
  apiUrl: string;
  repository: string;
  proxyPolicy: string;
  caFingerprint: string;
  credentialLabel: string;
  status: 'healthy' | 'attention';
  checkedAt: string;
}

export interface DistributionEndpoint {
  id: string;
  name: string;
  kind: 'Origin' | 'CDN' | 'Private';
  region: string;
  priority: number;
  health: 'healthy' | 'degraded' | 'offline';
  rootDigest: string;
  timestampDigest: string;
  checkedAt: string;
}

export interface AuditEvent {
  id: string;
  time: string;
  product: string;
  actor: string;
  action: string;
  target: string;
  result: 'success' | 'denied' | 'failed';
  requestId: string;
  releaseId?: string;
  summary: string;
}

export type LogCenterKind = 'operation' | 'authentication' | 'application' | 'git';

export interface LogCenterEvent extends AuditEvent {
  kind: LogCenterKind;
  decision?: 'allow' | 'deny';
  reasonCode?: string;
  clientAppId?: string;
  clientAppVersion?: string;
  authorizationName?: string;
  licenseId?: string;
  licenseExpiresAt?: string;
  provider?: string;
  repository?: string;
  syncStage?: string;
}
