export type PlatformRole = 'admin' | 'publisher' | 'approver' | 'auditor';

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

export interface Product {
  id: string;
  name: string;
  description: string;
  defaultChannel: string;
  channels: string[];
  status: 'active' | 'inactive';
  manifestDigest: string;
  updatedAt: string;
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
