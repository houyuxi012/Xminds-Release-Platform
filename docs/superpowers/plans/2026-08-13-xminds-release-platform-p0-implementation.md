# Xminds Release Platform P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `Release platform` 内交付支持多产品可信发布、身份治理、统一日志、请求时授权快照、GitHub/GHES、GitLab Self-Managed、Distribution Endpoint 和 Docker Compose 的 Xminds Release Platform P0。

**Architecture:** 采用 Go 模块化单体，运行时拆为 `release-api` 与 `release-worker`，前端为 React 管理控制台。PostgreSQL 负责强一致元数据、Outbox、身份治理和分区日志，S3 Port 负责不可变制品、目录对象和日志归档；核心领域只依赖 Port，SCM、对象存储、OIDC、目录同步、授权上下文、签名和数据库均由 Adapter 实现。License 生命周期由外部系统负责，P0 仅固化可信上游的请求时授权快照。

**Tech Stack:** Go 1.26.5、Chi v5、pgx v5、React 19.2、TypeScript 7、Ant Design 6.5、Vite 8.1、Node.js 24 LTS、PostgreSQL 17.10、MinIO AIStor、OpenTelemetry、Prometheus、Docker Compose。

## Global Constraints

- 当前仓库根目录即原计划中的 `Release platform/`。所有文件路径执行时省略该前缀，所有 `cd 'Release platform' && ...` 命令直接在仓库根目录执行；禁止再创建嵌套的 `Release platform` 目录。
- 所有代码、文档、配置、生成物规则和测试必须位于 `Release platform`，不得引用父项目相对路径。
- 项目已接入独立 Git 仓库 `houyuxi012/Xminds-Release-Platform`；实施必须在功能分支完成，并保持整体移动后可独立构建、测试和运行。
- Go module 固定为 `xminds-release-platform`；显示名称固定为 `Xminds Release Platform`；配置前缀固定为 `XMINDS_RELEASE_`。
- Go 工具链固定为 1.26.5；前端构建工具链固定为 Node.js 24 LTS；所有直接依赖必须由 `go.sum` 或 `package-lock.json` 锁定。
- PostgreSQL 固定使用 17.10；数据库名固定为 `xminds_release_platform`。
- 对象存储通过 `ObjectStore` Port 接入。生产 Compose 使用 `quay.io/minio/aistor/minio:RELEASE.2026-03-17T21-25-16Z` 并固定镜像摘要；AIStor 许可证是部署前置条件，禁止使用已归档且存在未修复安全公告的 MinIO OSS 最终版本替代。
- root 私钥不得进入 API、Worker、容器镜像、数据库或源码；在线角色只使用 Ed25519 密钥引用。
- API 错误固定使用 RFC 9457 Problem Details；外部 ID 使用 UUIDv7；版本使用 SemVer 2.0.0。
- 所有状态修改必须认证、授权、审计；发布者不得审批本人提交的 Release。
- SSO 未启用时使用本地登录；启用后普通本地登录关闭，故障时不得自动降级，仅独立应急入口可用。
- 客户端自报 Header、Query 或请求体不得作为授权事实；请求时授权快照仅接受 mTLS 网关、签名上下文或进程内可信适配器，并且一次写入、禁止回填。
- 日志使用字段允许清单，禁止采集 Token、Cookie、Authorization、License Key、密码、私钥、恢复代码、完整请求体和原始敏感 Query String。
- 领域开发采用测试驱动：先写失败测试，再写最小实现，再运行相关测试和全量测试。
- 关键领域覆盖率不低于 85%；不得用空函数、永久占位、跳过 TLS 校验或测试桩冒充生产实现。
- macOS 元数据检查必须阻断 `.DS_Store`、`._*`、`__MACOSX`、AppleDouble、FinderInfo 和 ResourceFork 进入 Git 或离线包。
- 前端任务开始前必须读取并遵循 `antd`、`build-web-apps:frontend-app-builder`、`build-web-apps:react-best-practices`；浏览器验收使用 Playwright。
- 设计基线为 `docs/superpowers/specs/2026-08-13-xminds-release-platform-p0-design.md` 和 `docs/superpowers/specs/2026-08-14-xminds-release-platform-p0-identity-log-baseline-design.md`。

---

## Locked File Structure

```text
Xminds-Release-Platform/
├── api/openapi.yaml
├── apps/
│   ├── release-api/main.go
│   ├── release-worker/main.go
│   └── release-console/
├── internal/
│   ├── artifact/
│   ├── audit/
│   ├── catalog/
│   ├── endpoint/
│   ├── identity/
│   ├── iam/
│   ├── authorizationcontext/
│   ├── logcenter/
│   ├── product/
│   ├── release/
│   ├── scm/
│   ├── signing/
│   └── platform/
│       ├── config/
│       ├── database/
│       ├── httpx/
│       ├── jobs/
│       ├── objectstore/
│       └── observability/
├── migrations/
├── deploy/
│   ├── compose/
│   ├── config/
│   ├── monitoring/
│   └── offline/
├── docs/
├── scripts/
├── tests/
│   ├── contract/
│   ├── e2e/
│   ├── integration/
│   └── performance/
├── .gitignore
├── .golangci.yml
├── Makefile
├── README.md
├── go.mod
└── go.sum
```

跨任务接口一经建立不得随意改名。确需修改时，必须在同一提交中更新所有消费者、契约测试和 OpenAPI。

---

### Task 1: Independent Buildable Project Skeleton

**Files:**
- Create: `Release platform/go.mod`
- Create: `Release platform/.gitignore`
- Create: `Release platform/.golangci.yml`
- Create: `Release platform/Makefile`
- Create: `Release platform/README.md`
- Create: `Release platform/internal/platform/buildinfo/version.go`
- Create: `Release platform/internal/platform/buildinfo/version_test.go`
- Create: `Release platform/apps/release-api/main.go`
- Create: `Release platform/apps/release-worker/main.go`
- Create: `Release platform/scripts/check-boundaries.sh`
- Create: `Release platform/scripts/check-macos-metadata.sh`

**Interfaces:**
- Produces: `buildinfo.Info{Version, Commit, BuildTime string}` and two independently compilable Go binaries.
- Produces: canonical commands `make fmt`, `make lint`, `make test`, `make build`, `make verify`.

- [ ] **Step 1: Write the failing build information test**

```go
package buildinfo

import "testing"

func TestCurrentHasStableProductIdentity(t *testing.T) {
    got := Current()
    if got.Product != "xminds-release-platform" {
        t.Fatalf("Product = %q", got.Product)
    }
    if got.Version == "" {
        t.Fatal("Version must not be empty")
    }
}
```

- [ ] **Step 2: Run the test and verify the package does not exist**

Run: `cd 'Release platform' && go test ./internal/platform/buildinfo -v`

Expected: FAIL because `go.mod` and `buildinfo.Current` do not exist.

- [ ] **Step 3: Create the module and minimal build information implementation**

```go
module xminds-release-platform

go 1.26.0

toolchain go1.26.5
```

```go
package buildinfo

type Info struct {
    Product   string `json:"product"`
    Version   string `json:"version"`
    Commit    string `json:"commit"`
    BuildTime string `json:"build_time"`
}

var version = "0.1.0-p0"
var commit = "development"
var buildTime = "unknown"

func Current() Info {
    return Info{Product: "xminds-release-platform", Version: version, Commit: commit, BuildTime: buildTime}
}
```

Both `main.go` files must print a startup error and exit non-zero until Task 2 supplies validated configuration; they must not start an unsecured placeholder HTTP server.

- [ ] **Step 4: Add repository hygiene and boundary checks**

`.gitignore` must include build output, coverage, `.env`, local secrets, Node output, and the six macOS pollution patterns. `check-boundaries.sh` must fail when Go or TypeScript source below `Release platform` imports a path beginning with `../` that escapes the project. `check-macos-metadata.sh` must call the repository-copied hygiene checker installed in Task 12; until then it must perform an equivalent `find` check for `.DS_Store`, `._*`, and `__MACOSX`.

- [ ] **Step 5: Add Make targets and compile both binaries**

Run: `cd 'Release platform' && go test ./... && go build ./apps/release-api ./apps/release-worker && ./scripts/check-boundaries.sh`

Expected: PASS, with no files created outside `Release platform`.

- [ ] **Step 6: Commit the skeleton**

```bash
git add 'Release platform'
git commit -m "build: scaffold Xminds Release Platform"
```

---

### Task 2: Configuration, Problem Details, PostgreSQL, Migrations, and Outbox

**Files:**
- Create: `Release platform/internal/platform/config/config.go`
- Create: `Release platform/internal/platform/config/config_test.go`
- Create: `Release platform/internal/platform/httpx/problem.go`
- Create: `Release platform/internal/platform/httpx/problem_test.go`
- Create: `Release platform/internal/platform/database/pool.go`
- Create: `Release platform/internal/platform/database/tx.go`
- Create: `Release platform/internal/platform/jobs/model.go`
- Create: `Release platform/internal/platform/jobs/repository.go`
- Create: `Release platform/internal/platform/jobs/postgres_repository.go`
- Create: `Release platform/migrations/000001_platform.up.sql`
- Create: `Release platform/migrations/000001_platform.down.sql`
- Create: `Release platform/tests/integration/platform_database_test.go`
- Create: `Release platform/api/openapi.yaml`
- Modify: `Release platform/apps/release-api/main.go`
- Modify: `Release platform/apps/release-worker/main.go`

**Interfaces:**
- Produces: `config.Load(environ map[string]string) (config.Config, error)`.
- Produces: `database.WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error`.
- Produces: `jobs.Repository.Enqueue`, `Lease`, `Complete`, `Retry`, `DeadLetter`.
- Produces: RFC 9457 `httpx.Problem` and `httpx.WriteProblem`.
- Produces: `release-api serve` and `release-api migrate` command modes; migration never runs implicitly during `serve`.

- [ ] **Step 1: Write failing configuration and Problem Details tests**

```go
func TestLoadRejectsMissingDatabaseURL(t *testing.T) {
    _, err := Load(map[string]string{"XMINDS_RELEASE_ENVIRONMENT": "test"})
    if !errors.Is(err, ErrDatabaseURLRequired) {
        t.Fatalf("error = %v", err)
    }
}

func TestProblemNeverSerializesInternalCause(t *testing.T) {
    p := NewProblem(http.StatusBadRequest, "PRODUCT_MANIFEST_INVALID", "Invalid product manifest", errors.New("secret=abc"))
    raw, _ := json.Marshal(p)
    if bytes.Contains(raw, []byte("secret=abc")) {
        t.Fatal("internal cause leaked")
    }
}
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `cd 'Release platform' && go test ./internal/platform/config ./internal/platform/httpx -v`

Expected: FAIL because the packages do not exist.

- [ ] **Step 3: Implement validated configuration**

```go
type Config struct {
    Environment     string
    APIListen       string
    PublicListen    string
    DatabaseURL     string
    ObjectStoreURL  string
    ObjectBucket    string
    OIDCIssuer      string
    OIDCAudience    string
    LocalAdmin      bool
    WorkerID        string
    JobLease        time.Duration
}
```

`Load` must reject missing database/object store/OIDC settings outside `development`; `LocalAdmin` must be rejected unless environment equals `development`. Never read generic names such as `DATABASE_URL`; accept only `XMINDS_RELEASE_*` names.

- [ ] **Step 4: Implement the first migration**

The migration must create `schema_migrations`, `outbox_jobs`, and `idempotency_keys`. `outbox_jobs` fields are `id UUID`, `kind TEXT`, `aggregate_id UUID`, `payload JSONB`, `status TEXT`, `attempts INT`, `available_at TIMESTAMPTZ`, `lease_owner TEXT`, `lease_expires_at TIMESTAMPTZ`, `last_error_code TEXT`, `created_at`, and `updated_at`. Add a partial index for leaseable `pending` jobs.

- [ ] **Step 5: Implement lease-safe Outbox repository**

```go
type Repository interface {
    Enqueue(ctx context.Context, tx pgx.Tx, job Job) error
    Lease(ctx context.Context, owner string, limit int, lease time.Duration) ([]Job, error)
    Complete(ctx context.Context, owner string, id uuid.UUID) error
    Retry(ctx context.Context, owner string, id uuid.UUID, code string, availableAt time.Time) error
    DeadLetter(ctx context.Context, owner string, id uuid.UUID, code string) error
}
```

`Lease` must use `FOR UPDATE SKIP LOCKED`; completion/retry must match both job ID and lease owner.

- [ ] **Step 6: Run PostgreSQL integration tests**

Run: `cd 'Release platform' && XMINDS_RELEASE_TEST_DATABASE_URL='postgres://xminds_release_test:xminds_release_test@127.0.0.1:55432/xminds_release_test?sslmode=disable' go test ./tests/integration -run PlatformDatabase -v`

Expected: PASS; two concurrent lease calls must never return the same job.

- [ ] **Step 7: Define the OpenAPI base contract**

Create OpenAPI 3.1 metadata, `/health/live`, `/health/ready`, `/version`, security schemes `oidcBearer` and `workloadBearer`, and the shared `ProblemDetails` schema with required `type`, `title`, `status`, `code`, and `request_id`.

Add Chi v5, pgx v5, UUIDv7, OpenTelemetry, and migration dependencies with explicit major versions, run `go mod tidy`, and commit the resolved `go.sum`. The `migrate` command must acquire a PostgreSQL advisory lock, apply only checked-in migrations, and exit before starting any HTTP listener.

- [ ] **Step 8: Commit platform foundations**

```bash
git add 'Release platform'
git commit -m "feat: add platform configuration and durable jobs"
```

---

### Task 3: OIDC, Workload Identity, Product-Scoped RBAC, and Immutable Audit

**Files:**
- Create: `Release platform/internal/identity/principal.go`
- Create: `Release platform/internal/identity/authorizer.go`
- Create: `Release platform/internal/identity/oidc_verifier.go`
- Create: `Release platform/internal/identity/workload_verifier.go`
- Create: `Release platform/internal/identity/middleware.go`
- Create: `Release platform/internal/identity/authorizer_test.go`
- Create: `Release platform/internal/audit/model.go`
- Create: `Release platform/internal/audit/repository.go`
- Create: `Release platform/internal/audit/postgres_repository.go`
- Create: `Release platform/internal/audit/service.go`
- Create: `Release platform/internal/audit/service_test.go`
- Create: `Release platform/migrations/000002_identity_audit.up.sql`
- Create: `Release platform/migrations/000002_identity_audit.down.sql`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: `identity.Principal`, `identity.Verifier`, `identity.Authorizer`.
- Produces: `audit.Service.Append`, `Query`, `StartExport`, and `GetExport`.
- Consumes: Task 2 transaction and Problem Details infrastructure.

- [ ] **Step 1: Write failing authorization tests**

```go
func TestApproverCannotApproveOutsideProductScope(t *testing.T) {
    p := Principal{Subject: "alice", Roles: []Role{RoleApprover}, ProductIDs: []string{"ngep"}}
    if NewAuthorizer().Allowed(p, ActionReleaseApprove, "product-b") {
        t.Fatal("cross-product approval allowed")
    }
}

func TestLocalAdminIsDevelopmentOnly(t *testing.T) {
    _, err := NewLocalAdminVerifier("production", true)
    if !errors.Is(err, ErrLocalAdminForbidden) { t.Fatalf("error = %v", err) }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `cd 'Release platform' && go test ./internal/identity ./internal/audit -v`

Expected: FAIL because the packages do not exist.

- [ ] **Step 3: Implement stable authorization types**

```go
type Role string
const (
    RoleAdmin Role = "admin"
    RolePublisher Role = "publisher"
    RoleApprover Role = "approver"
    RoleAuditor Role = "auditor"
)

type Principal struct {
    Subject    string
    Kind       string
    Roles      []Role
    ProductIDs []string
    TokenID    string
}

type Verifier interface {
    Verify(ctx context.Context, rawToken string) (Principal, error)
}

type Authorizer interface {
    Require(principal Principal, action Action, productID string) error
}
```

Define an explicit action-to-role matrix; do not infer permissions from HTTP methods.

- [ ] **Step 4: Implement OIDC and workload verification**

OIDC verification must validate issuer, audience, signature, expiry, not-before, and token ID. Workload verification must expose the same `Principal` type and distinguish `github-actions`, `github-enterprise-actions`, and `gitlab-ci`. API token fallback stores only an Argon2id hash and expiry.

- [ ] **Step 5: Implement append-only audit storage**

```go
type Event struct {
    ID, RequestID uuid.UUID
    ActorSubject, ActorKind, ProductID, Action, TargetType, TargetID, Result string
    SourceIP netip.Addr
    BeforeDigest, AfterDigest string
    OccurredAt time.Time
}
```

The database role used by API/Worker receives `INSERT` and `SELECT` on `audit_events`, never `UPDATE` or `DELETE`. Add a hash-chain column `event_hash` derived from canonical event content and the previous hash within each product stream. `StartExport` stores an immutable export request and enqueues `audit.export.v1`; Task 8 supplies its object-store handler.

- [ ] **Step 6: Add authorization and audit contract tests**

Test missing token, wrong audience, expired token, wrong product scope, publisher approval attempt, auditor write attempt, and log redaction. Add `/api/v1/audit-events`, `POST /api/v1/audit-exports`, and `GET /api/v1/audit-exports/{export_id}` to OpenAPI with cursor filters and auditor-only authorization.

- [ ] **Step 7: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/identity ./internal/audit ./tests/integration -v`

```bash
git add 'Release platform'
git commit -m "feat: enforce scoped identity and immutable audit"
```

---

### Task 4: Multi-Product Registration and Manifest Contract

**Files:**
- Create: `Release platform/internal/product/model.go`
- Create: `Release platform/internal/product/manifest.go`
- Create: `Release platform/internal/product/repository.go`
- Create: `Release platform/internal/product/postgres_repository.go`
- Create: `Release platform/internal/product/service.go`
- Create: `Release platform/internal/product/http_handler.go`
- Create: `Release platform/internal/product/service_test.go`
- Create: `Release platform/internal/product/testdata/valid-ngep.json`
- Create: `Release platform/internal/product/testdata/valid-second-product.json`
- Create: `Release platform/internal/product/product-manifest-v1.schema.json`
- Create: `Release platform/migrations/000003_products.up.sql`
- Create: `Release platform/migrations/000003_products.down.sql`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: `product.Service.Register`, `Get`, `List`, `Deactivate`.
- Produces: `product.Repository` for later Artifact, Release, SCM, and Endpoint services.
- Consumes: Task 3 Authorizer and Audit Service.

- [ ] **Step 1: Write failing product isolation tests**

```go
func TestRegisterTwoProductsWithoutNGEPSpecialCase(t *testing.T) {
    svc := newTestService()
    for _, manifest := range []string{"testdata/valid-ngep.json", "testdata/valid-second-product.json"} {
        if _, err := svc.Register(ctx, principalAdmin, mustRead(manifest)); err != nil { t.Fatal(err) }
    }
    got, _ := svc.List(ctx, principalAdmin, Page{})
    if len(got.Items) != 2 { t.Fatalf("products = %d", len(got.Items)) }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/product -v`

Expected: FAIL because product service does not exist.

- [ ] **Step 3: Implement versioned manifest validation**

```go
type Manifest struct {
    SchemaVersion     string            `json:"schema_version"`
    ProductID         string            `json:"product_id"`
    DisplayName       string            `json:"display_name"`
    ArtifactTypes     []string          `json:"artifact_types"`
    VersionScheme     string            `json:"version_scheme"`
    CompatibilityKeys []string          `json:"compatibility_keys"`
    CatalogFormat     string            `json:"catalog_format"`
    DefaultChannels   []ChannelManifest `json:"default_channels"`
}
```

Enforce lowercase product IDs matching `^[a-z][a-z0-9-]{1,62}$`, SemVer only, unique artifact types/channels, and catalog format `xminds-tuf-v1`.

- [ ] **Step 4: Implement transactional registration**

Register Product and default Channels in one transaction, append audit evidence, and reject duplicate Product ID or duplicate manifest digest. Store both canonical manifest JSON and SHA-256 digest.

- [ ] **Step 5: Add OpenAPI and HTTP contract tests**

Define `POST /api/v1/products`, `GET /api/v1/products`, `GET /api/v1/products/{product_id}`. Assert 201, 409 duplicate, 422 invalid manifest, 403 scope violation, and RFC 9457 bodies.

- [ ] **Step 6: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/product ./tests/integration -v`

```bash
git add 'Release platform'
git commit -m "feat: register isolated release products"
```

---

### Task 5: Resumable Artifact Upload and Immutable S3 Storage

**Files:**
- Create: `Release platform/internal/platform/objectstore/store.go`
- Create: `Release platform/internal/platform/objectstore/minio_store.go`
- Create: `Release platform/internal/artifact/model.go`
- Create: `Release platform/internal/artifact/repository.go`
- Create: `Release platform/internal/artifact/postgres_repository.go`
- Create: `Release platform/internal/artifact/service.go`
- Create: `Release platform/internal/artifact/http_handler.go`
- Create: `Release platform/internal/artifact/service_test.go`
- Create: `Release platform/migrations/000004_artifacts.up.sql`
- Create: `Release platform/migrations/000004_artifacts.down.sql`
- Create: `Release platform/tests/integration/artifact_minio_test.go`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: `objectstore.Store`.
- Produces: `artifact.Service.BeginUpload`, `PutPart`, `Complete`, `Get`.
- Consumes: Product Repository, Authorizer, Audit Service.

- [ ] **Step 1: Write failing digest and immutability tests**

```go
func TestCompleteRejectsDigestMismatchAndNeverPublishesObject(t *testing.T) {
    svc, store := newArtifactService()
    upload, _ := svc.BeginUpload(ctx, publisher, BeginUpload{ProductID: "ngep", Size: 3, SHA256: strings.Repeat("0", 64)})
    _ = svc.PutPart(ctx, publisher, upload.ID, 1, bytes.NewBufferString("abc"))
    _, err := svc.Complete(ctx, publisher, upload.ID)
    if !errors.Is(err, ErrDigestMismatch) { t.Fatalf("error = %v", err) }
    if store.Has("artifacts/sha256/ba/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") { t.Fatal("mismatched object published") }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/artifact -v`

Expected: FAIL because Artifact service does not exist.

- [ ] **Step 3: Lock the ObjectStore Port**

```go
type Store interface {
    BeginMultipart(ctx context.Context, key, contentType string) (string, error)
    PutPart(ctx context.Context, key, uploadID string, partNumber int, body io.Reader, size int64, sha256 string) (Part, error)
    CompleteMultipart(ctx context.Context, key, uploadID string, parts []Part) error
    AbortMultipart(ctx context.Context, key, uploadID string) error
    Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error)
    Stat(ctx context.Context, key string) (ObjectInfo, error)
}
```

Object keys are `artifacts/sha256/{first-two}/{full-digest}`. The adapter must disable redirects, use configured TLS roots, and never log access keys.

- [ ] **Step 4: Implement upload limits and server-side verification**

Use fixed limits: 20 GiB per object, 10,000 parts, part size 5 MiB–256 MiB except final part, and 24-hour upload expiry. Completion streams the assembled object to compute SHA-256 independently; client-provided ETag is not trusted.

- [ ] **Step 5: Implement database uniqueness and cleanup**

`artifacts` is unique on digest; `artifact_uploads` stores product, expected digest, expected size, object upload ID, state, and expiry. Digest mismatch transitions to `quarantined` and enqueues cleanup. A completed artifact cannot return to an upload state.

- [ ] **Step 6: Add HTTP and MinIO integration tests**

Define begin, upload-part, complete, and download metadata operations in OpenAPI. Test happy path, duplicate content dedupe, cross-product denial, oversized part, expired session, retry of the same part, and range reads.

- [ ] **Step 7: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/artifact ./internal/platform/objectstore ./tests/integration -run Artifact -v`

```bash
git add 'Release platform'
git commit -m "feat: store verified immutable artifacts"
```

---

### Task 6: Release State Machine and Segregated Approval

**Files:**
- Create: `Release platform/internal/release/model.go`
- Create: `Release platform/internal/release/state_machine.go`
- Create: `Release platform/internal/release/repository.go`
- Create: `Release platform/internal/release/postgres_repository.go`
- Create: `Release platform/internal/release/service.go`
- Create: `Release platform/internal/release/http_handler.go`
- Create: `Release platform/internal/release/state_machine_test.go`
- Create: `Release platform/internal/release/service_test.go`
- Create: `Release platform/migrations/000005_releases.up.sql`
- Create: `Release platform/migrations/000005_releases.down.sql`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: `release.Service.Create`, `Submit`, `Approve`, `Reject`, `Publish`, `Revoke`, `Get`.
- Produces: published Job kind `catalog.publish.v1`.
- Consumes: Product, Artifact, Authorizer, Audit, and Jobs.

- [ ] **Step 1: Write failing state and separation-of-duties tests**

```go
func TestSubmitterCannotApproveOwnRelease(t *testing.T) {
    svc := newReleaseService()
    rel := mustCreateAndSubmit(t, svc, Principal{Subject: "alice", Roles: []Role{RolePublisher}})
    err := svc.Approve(ctx, Principal{Subject: "alice", Roles: []Role{RoleApprover}}, rel.ID)
    if !errors.Is(err, ErrSelfApprovalForbidden) { t.Fatalf("error = %v", err) }
}

func TestPublishedCannotReturnToDraft(t *testing.T) {
    if TransitionAllowed(StatusPublished, StatusDraft) { t.Fatal("invalid transition allowed") }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/release -v`

- [ ] **Step 3: Implement the exact state model**

```go
type Status string
const (
    StatusDraft Status = "DRAFT"
    StatusSubmitted Status = "SUBMITTED"
    StatusApproved Status = "APPROVED"
    StatusRejected Status = "REJECTED"
    StatusPublishing Status = "PUBLISHING"
    StatusPublished Status = "PUBLISHED"
    StatusFailed Status = "FAILED"
)
```

Allowed transitions are `DRAFT→SUBMITTED`, `SUBMITTED→APPROVED|REJECTED`, `APPROVED→PUBLISHING`, and `PUBLISHING→PUBLISHED|FAILED`. Failed publication retries create a new attempt and transition `FAILED→PUBLISHING` only after an approver-authorized retry.

Revocation is orthogonal to the immutable publication status: a published Release retains `PUBLISHED` and receives `revoked_at`, mandatory reason, approver identity, and a revocation attempt. `Revoke` is valid only for `PUBLISHED`, requires the `approver` role, writes audit evidence, and enqueues `catalog.revoke.v1`.

- [ ] **Step 4: Implement Release validation**

Require product, channel, SemVer, Release Notes bytes and digest, compatibility JSON and digest, artifact bindings, repository, commit SHA, tag, and pipeline reference. Enforce unique `(product_id, channel_id, version)` and exact artifact ownership.

- [ ] **Step 5: Enqueue publication atomically**

`Publish` must transition to `PUBLISHING`, append audit, create a `release_attempt`, and enqueue `catalog.publish.v1` in one transaction. A repeated `Idempotency-Key` returns the original result.

- [ ] **Step 6: Add API contract tests**

Define create, submit, approve, reject, publish, retry, revoke, and get operations. Test invalid transition, self-approval, missing artifact, wrong product, duplicate version, stale optimistic lock, idempotent retry, mandatory revocation reason, and duplicate revocation.

- [ ] **Step 7: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/release ./tests/integration -run Release -v`

```bash
git add 'Release platform'
git commit -m "feat: enforce release approval workflow"
```

---

### Task 7: Ed25519 Signing Port and Exact Five-Role Catalog Contract

**Files:**
- Create: `Release platform/internal/signing/provider.go`
- Create: `Release platform/internal/signing/local_encrypted_provider.go`
- Create: `Release platform/internal/signing/local_encrypted_provider_test.go`
- Create: `Release platform/internal/catalog/canonicaljson.go`
- Create: `Release platform/internal/catalog/model.go`
- Create: `Release platform/internal/catalog/builder.go`
- Create: `Release platform/internal/catalog/verifier.go`
- Create: `Release platform/internal/catalog/repository.go`
- Create: `Release platform/internal/catalog/postgres_repository.go`
- Create: `Release platform/internal/catalog/builder_test.go`
- Create: `Release platform/internal/catalog/testdata/ngep-golden/`
- Create: `Release platform/migrations/000006_signing_catalog.up.sql`
- Create: `Release platform/migrations/000006_signing_catalog.down.sql`
- Create: `Release platform/scripts/root-key/main.go`
- Create: `Release platform/docs/security/key-ceremony.md`

**Interfaces:**
- Produces: `signing.Provider.Sign` and `PublicKeys`.
- Produces: `catalog.Builder.Build(ctx, release.Release, Versions) (catalog.Bundle, error)`.
- Produces: exact wire envelopes for root, targets, snapshot, timestamp, revocation.
- Consumes: Release and Artifact data; ObjectStore is consumed in Task 8.

- [ ] **Step 1: Freeze consumer golden vectors before implementation**

Copy protocol fixtures, not Python code, from the existing upgrade consumer into `testdata/ngep-golden`: one valid five-role chain, digest mismatch, expiry, duplicate JSON key, invalid signature, and revoked target. Add `PROVENANCE.md` containing original source paths, source commit, copied test names, and SHA-256 for each fixture.

- [ ] **Step 2: Write failing canonical JSON and chain tests**

```go
func TestCanonicalJSONMatchesNGEPGoldenVector(t *testing.T) {
    got, err := CanonicalJSON(map[string]any{"z": 1, "中文": "值", "a": true})
    if err != nil { t.Fatal(err) }
    if string(got) != `{"a":true,"z":1,"中文":"值"}` { t.Fatalf("canonical = %s", got) }
}

func TestVerifyRejectsSnapshotTargetDigestMismatch(t *testing.T) {
    bundle := mustLoadGolden(t, "digest-mismatch")
    if !errors.Is(Verify(bundle, fixedClock), ErrRoleDigestMismatch) { t.Fatal("mismatch accepted") }
}
```

- [ ] **Step 3: Verify failure**

Run: `cd 'Release platform' && go test ./internal/catalog ./internal/signing -v`

- [ ] **Step 4: Lock the signing interface**

```go
type Provider interface {
    Sign(ctx context.Context, keyRef string, payload []byte) (Signature, error)
    PublicKeys(ctx context.Context, keyRefs []string) ([]PublicKey, error)
}

type Signature struct { KeyID string; Algorithm string; Value []byte }
type PublicKey struct { KeyID string; Algorithm string; Value []byte }
```

The local provider uses envelope encryption with an operator-supplied master key file mode `0600`; it rejects keys named `root`. The root-key CLI runs offline, prints public bootstrap material, and never writes private key bytes to stdout.

- [ ] **Step 5: Implement the consumer-compatible wire schema**

Each role uses `{signed, signatures}`; signed content includes `_type`, positive integer `version`, UTC `expires`, and role data. Signatures are unpadded base64url Ed25519 over the exact canonical `signed` JSON. Root contains Ed25519 keys and role thresholds. Targets custom fields must include `product_id`, `release_id`, `version`, `plan_digest`, `artifact_digest`, `manifest_digest`, `release_notes_markdown`, `release_notes_digest`, `compatibility`, `compatibility_digest`, `target_images`, `image_mode`, and optional `offline_image_bundle_digest`.

- [ ] **Step 6: Implement cross-role binding and expiry policy**

Snapshot binds `targets.json` version and SHA-256 envelope digest; timestamp binds `snapshot.json`; revocation contains signed revocation entries. Default expiry: targets 30 days, snapshot 7 days, timestamp 24 hours, revocation 7 days. The verifier rejects floats, duplicate JSON keys, `-0`, invalid UTF-8, expired roles, insufficient threshold, digest mismatch, version mismatch, Release Notes digest mismatch, compatibility digest mismatch, and revoked target/key.

- [ ] **Step 7: Run golden contract tests**

Run: `cd 'Release platform' && go test ./internal/catalog ./internal/signing -v`

Expected: all copied consumer vectors pass without altering fixture bytes.

- [ ] **Step 8: Commit signing and catalog core**

```bash
git add 'Release platform'
git commit -m "feat: generate consumer-compatible trusted catalogs"
```

---

### Task 8: Publication Worker, Atomic Catalog Switch, Retry, and Dead Letter

**Files:**
- Create: `Release platform/internal/catalog/publication_service.go`
- Create: `Release platform/internal/catalog/publication_service_test.go`
- Create: `Release platform/internal/platform/jobs/worker.go`
- Create: `Release platform/internal/platform/jobs/worker_test.go`
- Create: `Release platform/internal/platform/jobs/handlers.go`
- Create: `Release platform/internal/audit/export_handler.go`
- Create: `Release platform/internal/audit/export_handler_test.go`
- Modify: `Release platform/apps/release-worker/main.go`
- Modify: `Release platform/internal/release/service.go`
- Modify: `Release platform/migrations/000006_signing_catalog.up.sql`
- Create: `Release platform/tests/integration/catalog_publication_test.go`

**Interfaces:**
- Produces: `jobs.Handler.Handle(ctx, Job) error` registry.
- Produces: catalog Job handler for `catalog.publish.v1`.
- Consumes: Jobs, Release Repository, Catalog Builder, Signing Provider, ObjectStore, Audit.

- [ ] **Step 1: Write failing crash-recovery and visibility tests**

```go
func TestCatalogIsInvisibleUntilAllRolesPersistAndDatabaseSwitchCommits(t *testing.T) {
    svc, store, repo := newPublicationService(failAfterRole("snapshot"))
    err := svc.Publish(ctx, job)
    if err == nil { t.Fatal("expected failure") }
    if repo.CurrentCatalog(job.ProductID, job.ChannelID) != nil { t.Fatal("partial catalog became current") }
    if store.Exists("catalogs/current/") { t.Fatal("mutable current object written") }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/platform/jobs ./internal/catalog -run 'Crash|Invisible' -v`

- [ ] **Step 3: Implement immutable catalog publication**

Write every role to `catalogs/{product}/{channel}/{catalog-version}/{role}.json`, verify it by reading back and hashing, then atomically update the PostgreSQL current-catalog pointer. Never copy objects to a mutable `current` key.

- [ ] **Step 4: Implement Worker retry semantics**

Lease 10 jobs for 30 seconds, renew at 10 seconds, and stop work if renewal fails. Retry with capped exponential delays `5s, 30s, 2m, 10m, 30m`; after five failed attempts, dead-letter the job, transition Release to `FAILED`, and append an audit event with the stable error code.

- [ ] **Step 5: Complete Release only after publication**

The publish handler transitions `PUBLISHING→PUBLISHED` only after the current-catalog pointer commits. A repeated handler call detects the existing attempt digest and completes idempotently without incrementing metadata versions. The `catalog.revoke.v1` handler adds the signed revocation entry and publishes a new timestamp while keeping every metadata version monotonic.

Add `internal/audit/export_handler.go` for `audit.export.v1`: stream filtered audit rows as UTF-8 JSON Lines into immutable object storage, store its SHA-256 and expiry, and expose only an authorized short-lived download response. Export failure must be retryable and auditable.

- [ ] **Step 6: Run integration tests**

Test Worker process restart, lease theft prevention, partial S3 failure, signing failure, PostgreSQL commit failure, retry, dead-letter, and idempotent replay.

Run: `cd 'Release platform' && go test ./internal/platform/jobs ./internal/catalog ./tests/integration -run CatalogPublication -v`

- [ ] **Step 7: Commit**

```bash
git add 'Release platform'
git commit -m "feat: publish catalogs with durable worker recovery"
```

---

### Task 9: GitHub/GHES and GitLab Self-Managed Enterprise Integration

**Files:**
- Create: `Release platform/internal/scm/provider.go`
- Create: `Release platform/internal/scm/model.go`
- Create: `Release platform/internal/scm/egress_policy.go`
- Create: `Release platform/internal/scm/tls_config.go`
- Create: `Release platform/internal/scm/credential_store.go`
- Create: `Release platform/internal/scm/github_adapter.go`
- Create: `Release platform/internal/scm/gitlab_adapter.go`
- Create: `Release platform/internal/scm/webhook_handler.go`
- Create: `Release platform/internal/scm/service.go`
- Create: `Release platform/internal/scm/github_adapter_test.go`
- Create: `Release platform/internal/scm/gitlab_adapter_test.go`
- Create: `Release platform/internal/scm/egress_policy_test.go`
- Create: `Release platform/migrations/000007_scm.up.sql`
- Create: `Release platform/migrations/000007_scm.down.sql`
- Create: `Release platform/tests/contract/scm/`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: `scm.Provider` and normalized SCM types.
- Produces: Webhook-to-domain event parser and `scm.status.writeback.v1` Job.
- Consumes: Product, Identity, Audit, Jobs, Release Service.

- [ ] **Step 1: Write failing SSRF and webhook replay tests**

```go
func TestEgressRejectsRedirectToUnregisteredHost(t *testing.T) {
    p := NewEgressPolicy([]Instance{{BaseURL: "https://gitlab.corp.example"}})
    if p.AllowRedirect("https://gitlab.corp.example/api/v4", "https://169.254.169.254/latest") {
        t.Fatal("metadata redirect allowed")
    }
}

func TestDuplicateWebhookReturnsOriginalDeliveryWithoutCreatingSecondRelease(t *testing.T) {
    svc := newWebhookService()
    first := mustHandle(t, svc, "connection-1", "event-42", payload)
    second := mustHandle(t, svc, "connection-1", "event-42", payload)
    if first.DeliveryID != second.DeliveryID || svc.ReleaseCount() != 1 { t.Fatal("webhook was not idempotent") }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/scm -v`

- [ ] **Step 3: Lock normalized SCM Port**

```go
type Provider interface {
    VerifyConnection(ctx context.Context, c Connection) (Capabilities, error)
    VerifyWebhook(ctx context.Context, c Connection, headers http.Header, body []byte) (WebhookEvent, error)
    GetCommit(ctx context.Context, c Connection, repository, sha string) (Commit, error)
    WriteStatus(ctx context.Context, c Connection, status CommitStatus) error
    VerifyWorkload(ctx context.Context, c Connection, token string) (identity.Principal, error)
}
```

Normalized `WebhookEvent` contains Provider, EventID, Repository, Ref, Tag, CommitSHA, PipelineID, Actor, OccurredAt, and PayloadDigest.

- [ ] **Step 4: Implement private-instance TLS and egress policy**

Connection verification resolves the configured host, verifies the full TLS chain using system roots plus the versioned enterprise CA, rejects hostname mismatch, records the certificate fingerprint, and never accepts `InsecureSkipVerify`. Redirects are disabled at the HTTP client; proxy and `NO_PROXY` are built from connection policy, not ambient process environment.

- [ ] **Step 5: Implement GitHub.com and GHES adapter**

Support explicit API Base URL, GitHub webhook `X-Hub-Signature-256`, Actions OIDC issuer/audience validation, repository/commit lookup, and Check Run or Commit Status writeback selected by probed capability.

- [ ] **Step 6: Implement GitLab Self-Managed EE adapter**

Support arbitrary Base URL, GitLab API v4, `X-Gitlab-Token` or configured webhook secret verification, GitLab CI OIDC issuer/audience validation, Project/Group Access Token fallback, repository commit lookup, and Commit Status writeback.

- [ ] **Step 7: Implement encrypted credential persistence**

Store provider credentials using envelope encryption with key ID and ciphertext; API responses expose only credential type, creation time, expiry, and last four non-secret identifier characters. Rotation creates a new version; revocation invalidates the old version immediately.

- [ ] **Step 8: Add contract servers and offline tests**

Create local TLS test servers for GitHub and GitLab, issue a private CA, and test custom Base URL, CA trust, proxy, `NO_PROXY`, absence of public DNS calls, webhook validation, replay, capability probing, commit lookup, and status writeback.

- [ ] **Step 9: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/scm ./tests/contract/scm -v`

```bash
git add 'Release platform'
git commit -m "feat: integrate private GitHub and GitLab release pipelines"
```

---

### Task 10: Distribution Endpoints and Public Catalog API

**Files:**
- Create: `Release platform/internal/endpoint/model.go`
- Create: `Release platform/internal/endpoint/repository.go`
- Create: `Release platform/internal/endpoint/postgres_repository.go`
- Create: `Release platform/internal/endpoint/service.go`
- Create: `Release platform/internal/endpoint/synchronizer.go`
- Create: `Release platform/internal/endpoint/http_handler.go`
- Create: `Release platform/internal/endpoint/service_test.go`
- Create: `Release platform/internal/catalog/http_handler.go`
- Create: `Release platform/internal/catalog/http_handler_test.go`
- Create: `Release platform/migrations/000008_endpoints.up.sql`
- Create: `Release platform/migrations/000008_endpoints.down.sql`
- Modify: `Release platform/apps/release-api/main.go`
- Modify: `Release platform/api/openapi.yaml`

**Interfaces:**
- Produces: Endpoint registration, verification, synchronization, and health.
- Produces: public compatibility path and product/channel path.
- Consumes: Catalog current pointer, ObjectStore, Authorizer, Audit, Jobs.

- [ ] **Step 1: Write failing compatibility and cache tests**

```go
func TestCompatibilityPathServesConfiguredDefaultProductOnly(t *testing.T) {
    h := newCatalogHandler(defaultCatalog("ngep", "stable"))
    rr := serve(h, "/metadata/timestamp.json")
    if rr.Code != http.StatusOK { t.Fatalf("status = %d", rr.Code) }
    if rr.Header().Get("Cache-Control") != "public, max-age=30, must-revalidate" { t.Fatal("timestamp cache policy") }
}

func TestUnhealthyEndpointCannotBecomeActive(t *testing.T) {
    svc := newEndpointService(digestMismatchProbe())
    err := svc.Activate(ctx, admin, endpointID)
    if !errors.Is(err, ErrCatalogDigestMismatch) { t.Fatalf("error = %v", err) }
}
```

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./internal/endpoint ./internal/catalog -run 'Compatibility|Endpoint' -v`

- [ ] **Step 3: Implement Endpoint model**

Endpoint fields are ID, ProductID, Type (`origin|cdn|private`), Region, Priority, BaseURL, PathPrefix, HealthPath, TLSCARef, Status, LastRootDigest, LastTimestampDigest, LastCheckedAt, and FailureCount. Activation requires successful HTTPS probe and digest equality with the current catalog.

- [ ] **Step 4: Implement synchronization jobs**

`endpoint.sync.v1` copies all five role objects and referenced artifacts, reads them back, verifies SHA-256, and marks Endpoint healthy. Three consecutive failures mark it unhealthy and append an audit event. The client-facing primary/backup decision remains outside the upgrade client and is represented by Endpoint priority and health.

- [ ] **Step 5: Implement the public catalog handlers**

Serve exactly:

```text
GET /metadata/{root|targets|snapshot|timestamp|revocation}.json
GET /v1/products/{product}/channels/{channel}/metadata/{role}.json
GET /v1/products/{product}/artifacts/{sha256}
```

Root/targets/snapshot/revocation use immutable ETag and long cache; timestamp uses 30-second cache and conditional GET. Reject unknown roles before object store access. Set `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, and no redirects.

- [ ] **Step 6: Add API and health tests**

Test default product mapping, second product isolation, conditional requests, range artifact downloads, unknown role, stale Endpoint, digest mismatch, and three-failure ejection.

- [ ] **Step 7: Run tests and commit**

Run: `cd 'Release platform' && go test ./internal/endpoint ./internal/catalog ./tests/integration -run Endpoint -v`

```bash
git add 'Release platform'
git commit -m "feat: distribute verified catalogs through healthy endpoints"
```

---

### Task 11: React and Ant Design Pro Core Release Console

**Files:**
- Create: `Release platform/apps/release-console/package.json`
- Create: `Release platform/apps/release-console/package-lock.json`
- Create: `Release platform/apps/release-console/tsconfig.json`
- Create: `Release platform/apps/release-console/vite.config.ts`
- Create: `Release platform/apps/release-console/src/main.tsx`
- Create: `Release platform/apps/release-console/src/app/App.tsx`
- Create: `Release platform/apps/release-console/src/app/routes.tsx`
- Create: `Release platform/apps/release-console/src/app/theme.ts`
- Create: `Release platform/apps/release-console/src/api/client.ts`
- Create: `Release platform/apps/release-console/src/api/types.ts`
- Create: `Release platform/apps/release-console/src/auth/AuthProvider.tsx`
- Create: `Release platform/apps/release-console/src/layout/AppShell.tsx`
- Create: `Release platform/apps/release-console/src/pages/products/`
- Create: `Release platform/apps/release-console/src/pages/releases/`
- Create: `Release platform/apps/release-console/src/pages/artifacts/`
- Create: `Release platform/apps/release-console/src/pages/scm/`
- Create: `Release platform/apps/release-console/src/pages/endpoints/`
- Create: `Release platform/apps/release-console/src/pages/audit/`
- Create: `Release platform/apps/release-console/src/components/WhiteDetailDrawer.tsx`
- Create: `Release platform/apps/release-console/src/test/`
- Create: `Release platform/tests/e2e/console.spec.ts`
- Modify: `Release platform/Makefile`

**Interfaces:**
- Consumes: OpenAPI operations from Tasks 3–10.
- Produces: role-aware core Release Console routes, Ant Design Pro v6.6.0 white-shell baseline, and build output consumed by Docker image in Task 12.

- [ ] **Step 1: Load required frontend skills and lock dependencies**

Read `antd`, `build-web-apps:frontend-app-builder`, and `build-web-apps:react-best-practices`. Initialize Vite with React/TypeScript, then install `react@19.2`, `react-dom@19.2`, `antd@6.5`, `@ant-design/icons@6`, `@ant-design/pro-components@3`, React Router, TanStack Query, Vitest, Testing Library, MSW, and Playwright. Commit the generated `package-lock.json`; do not use floating runtime dependencies. Visual and interaction mapping follows Ant Design Pro v6.6.0.

- [ ] **Step 2: Write failing route authorization and error tests**

```tsx
it('hides approval action from publisher-only principals', async () => {
  renderApp({ roles: ['publisher'], route: '/releases/release-1' });
  expect(await screen.findByText('1.2.3')).toBeVisible();
  expect(screen.queryByRole('button', { name: '批准发布' })).not.toBeInTheDocument();
});

it('renders RFC 9457 request id on API failure', async () => {
  server.use(problem('PRODUCT_MANIFEST_INVALID', '0198a3b1-6c00-7f11-8000-000000000001', 422));
  renderApp({ roles: ['admin'], route: '/products/new' });
  await userEvent.click(screen.getByRole('button', { name: '创建产品' }));
  expect(await screen.findByText(/请求 ID：019/)).toBeVisible();
});
```

- [ ] **Step 3: Verify failure**

Run: `cd 'Release platform/apps/release-console' && npm test -- --run`

- [ ] **Step 4: Implement the application shell and auth boundary**

Use Ant Design `ConfigProvider` and App together with ProComponents `ProLayout`, `PageContainer`, `ProTable`, and semantic theme tokens. Routes are Products, Artifacts, Releases, SCM Connections, Distribution Endpoints, and Operation Audit. The side navigation, Logo area, collapse control, and all detail drawers are white; current navigation uses a light blue surface and blue text. UI authorization improves UX only; the API remains authoritative.

- [ ] **Step 5: Implement product, artifact, and release workflows**

Product pages support manifest creation/validation and list two products. Artifact page supports resumable upload, progress, digest display, retry, and quarantine error. Release pages support draft creation, submit, approval separation warning, publish, attempt timeline, Release Notes, and stable error code display.

- [ ] **Step 6: Implement SCM, Endpoint, and Audit pages**

SCM form supports Provider, private Base URL, API URL, enterprise CA fingerprint confirmation, proxy policy, credential metadata, capability probe, and status. Endpoint page shows priority, region, root/timestamp digests, health and last check. Audit page provides cursor pagination and filters for product, actor, action, result, Release, request ID, and time range.

- [ ] **Step 7: Add accessibility and component tests**

Test keyboard navigation, labels, loading/empty/error states, destructive confirmations, long Chinese/English text, role-driven actions, upload retry, request ID visibility, white navigation and white drawer semantic tokens at 1280px and 1440px. Do not target Ant Design internal DOM class names.

- [ ] **Step 8: Add Playwright happy path**

Automate admin product creation, publisher upload/create/submit, a different approver approving/publishing, SCM connection verification, Endpoint health, and auditor query. Use an API test server, not hard-coded UI delays.

- [ ] **Step 9: Run frontend verification and commit**

Run: `cd 'Release platform/apps/release-console' && npm run lint && npm run typecheck && npm test -- --run && npm run build`

Run: `cd 'Release platform' && npx playwright test tests/e2e/console.spec.ts`

```bash
git add 'Release platform'
git commit -m "feat: add Xminds release management console"
```

---

### Task 12: Hardened Docker Compose, Observability, Offline Bundle, and Hygiene Guard

**Files:**
- Create: `Release platform/deploy/compose/compose.yaml`
- Create: `Release platform/deploy/compose/compose.test.yaml`
- Create: `Release platform/deploy/config/schema.json`
- Create: `Release platform/deploy/config/example.env`
- Create: `Release platform/deploy/monitoring/prometheus.yml`
- Create: `Release platform/deploy/monitoring/alerts.yml`
- Create: `Release platform/deploy/monitoring/otel-collector.yaml`
- Create: `Release platform/deploy/monitoring/grafana/`
- Create: `Release platform/deploy/offline/manifest.schema.json`
- Create: `Release platform/scripts/build-offline-bundle.sh`
- Create: `Release platform/scripts/verify-offline-bundle.sh`
- Create: `Release platform/scripts/backup.sh`
- Create: `Release platform/scripts/restore.sh`
- Create: `Release platform/build/api.Dockerfile`
- Create: `Release platform/build/worker.Dockerfile`
- Create: `Release platform/build/console.Dockerfile`
- Create: `Release platform/internal/platform/observability/telemetry.go`
- Create: `Release platform/internal/platform/observability/metrics.go`
- Create: `Release platform/tests/contract/deployment_test.go`
- Modify: `Release platform/scripts/check-macos-metadata.sh`
- Modify: `Release platform/Makefile`

**Interfaces:**
- Produces: secure local/production-like Compose deployment and offline artifact.
- Consumes: all three application build outputs and configuration keys.

- [ ] **Step 1: Write failing deployment contract tests**

Tests must parse Compose and Dockerfiles and assert non-root users, read-only root filesystem, dropped capabilities, no Docker socket, Secret file mounts, health checks, fixed image versions, separate migration job, private networks, and no plaintext secret values.

- [ ] **Step 2: Verify failure**

Run: `cd 'Release platform' && go test ./tests/contract -run Deployment -v`

- [ ] **Step 3: Create hardened images and Compose services**

Compose services are `migration`, `release-api`, `release-worker`, `release-console`, `postgres`, `minio`, `prometheus`, `grafana`, `alertmanager`, and `otel-collector`. Pin PostgreSQL to `17.10`; pin MinIO AIStor to `RELEASE.2026-03-17T21-25-16Z` plus resolved multi-architecture digest. Use named volumes for PostgreSQL, object data, Grafana, and key metadata. Configure public catalog and management API on separate listeners.

- [ ] **Step 4: Add OpenTelemetry and Prometheus signals**

Instrument API duration/error, publication success/failure, signing duration/failure, catalog build/switch, webhook validation/replay, SCM reachability, Endpoint digest mismatch/sync latency, Job pending/retry/dead-letter, artifact digest mismatch, PostgreSQL readiness, and object store readiness. Include correlation ID in spans and structured logs; never attach tokens or payload bodies.

- [ ] **Step 5: Add actionable alerts**

Alerts require stable names and runbook URLs for signing failure, catalog mismatch, key expiry, SCM unreachable, artifact verification failure, dead-letter jobs, PostgreSQL unavailable, object storage unavailable, timestamp near expiry, and Endpoint unhealthy.

- [ ] **Step 6: Build and verify offline bundle**

Bundle contains OCI images for amd64/arm64, image digests, cosign signatures, SBOM files, Compose/config templates, migration binary, install/verify scripts, and a canonical manifest. Verification rejects absolute paths, `..`, unsafe links, duplicate members, excessive members/bytes/compression ratio, digest mismatch, signature failure, and macOS metadata.

- [ ] **Step 7: Install repository hygiene guard inside the project**

Copy the hygiene CLI and license into `Release platform/tools/macos-hygiene/`, update `check-macos-metadata.sh` to run `scan --xattrs` and `check-git --scope all`, and add the same command to `make verify`. Do not install or change global Git configuration.

- [ ] **Step 8: Add backup and restore scripts**

`backup.sh` creates PostgreSQL base/WAL metadata, object version inventory, config digest manifest, and encrypted key-provider metadata backup. `restore.sh` requires an empty target, validates every digest, restores database before object pointers, and runs catalog consistency verification before enabling API traffic.

- [ ] **Step 9: Run deployment verification**

Run: `cd 'Release platform' && docker compose -f deploy/compose/compose.yaml config --quiet`

Run: `cd 'Release platform' && docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.test.yaml up -d --wait`

Run: `cd 'Release platform' && make verify && go test ./tests/contract -v`

- [ ] **Step 10: Commit delivery baseline**

```bash
git add 'Release platform'
git commit -m "ops: deliver hardened observable release platform"
```

---

### Task 13: Multi-Product, `ngep` Compatibility, SCM, Performance, and Recovery Acceptance

**Files:**
- Create: `Release platform/tests/e2e/p0_release_flow_test.go`
- Create: `Release platform/tests/e2e/private_scm_flow_test.go`
- Create: `Release platform/tests/e2e/worker_recovery_test.go`
- Create: `Release platform/tests/contract/ngep/catalog_contract_test.go`
- Create: `Release platform/tests/contract/ngep/fixtures/`
- Create: `Release platform/tests/performance/catalog_read_test.js`
- Create: `Release platform/tests/performance/control_api_test.js`
- Create: `Release platform/scripts/run-p0-acceptance.sh`
- Create: `Release platform/docs/operations/p0-acceptance.md`
- Create: `Release platform/docs/operations/backup-restore.md`
- Create: `Release platform/docs/operations/private-scm.md`
- Create: `Release platform/docs/api/ci-integration.md`
- Modify: `Release platform/README.md`
- Modify: `Release platform/Makefile`

**Interfaces:**
- Consumes: the complete P0 platform.
- Produces: auditable acceptance report and repeatable commands.

- [ ] **Step 1: Write the failing multi-product end-to-end test**

The test must register `ngep` and `xminds-example-agent` through the same API; upload distinct artifacts; create, submit, approve with a different identity, and publish each Release; then assert separate catalog pointers, versions, objects, audit streams, and permissions.

- [ ] **Step 2: Add the frozen `ngep` contract verifier**

The verifier must request all five `/metadata/{role}.json` paths over HTTPS, reject redirects, parse strict JSON, verify Ed25519 thresholds and role digests, validate signed Release Notes and compatibility digests, and assert the exact target custom field set expected by the existing upgrade module. Fixtures record the source consumer commit and are independent of the parent repository at runtime.

- [ ] **Step 3: Add private SCM acceptance**

Run local GHES-compatible and GitLab Self-Managed-compatible TLS contract servers with a private CA and no external network. Exercise capability probe, workload identity, Webhook, upload/create Release, and status writeback for both providers. Assert that DNS and HTTP logs contain no public SaaS requests.

- [ ] **Step 4: Add failure and idempotency acceptance**

Exercise duplicate Webhook, duplicate CI `Idempotency-Key`, Worker kill after signing, Worker kill before database switch, object-store failure, signature failure, and SCM writeback failure. Assert no duplicate Release/catalog version and complete audit evidence.

- [ ] **Step 5: Add performance gates**

Use k6 to verify public catalog P95 below 100 ms and authenticated control API P95 below 300 ms under the documented local reference profile. Store the profile, request mix, duration, thresholds, and raw summary in the acceptance artifact.

- [ ] **Step 6: Execute backup/restore acceptance**

Publish both products, take a backup, destroy the test volumes, restore into empty volumes, verify all five role digests, artifacts, current pointers, audit chain, and authentication configuration, then publish one additional version to prove version counters remain monotonic.

- [ ] **Step 7: Run security and dependency checks**

Run `govulncheck`, `npm audit --audit-level=high`, secret scanning, container image scanning, Go race tests, frontend lint/typecheck/tests, strict OpenAPI validation, macOS metadata scan, and offline archive verification. Any high or critical finding blocks acceptance.

- [ ] **Step 8: Run the complete acceptance command**

Run: `cd 'Release platform' && ./scripts/run-p0-acceptance.sh`

Expected: all unit, integration, contract, E2E, security, performance, offline, and recovery gates pass and produce `artifacts/acceptance/p0-summary.json` with no secrets.

- [ ] **Step 9: Update operations documentation**

Document installation, configuration, OIDC, CI tokens, GitHub/GHES, GitLab Self-Managed, enterprise CA, proxies, no-public-network deployment, backup/restore, alert response, key ceremony, audit export, and rollback by revocation plus new timestamp. Every command must be executable from inside `Release platform`.

- [ ] **Step 10: Commit P0 acceptance closure**

```bash
git add 'Release platform'
git commit -m "test: close Xminds Release Platform P0 acceptance"
```

---

### Task 14: Identity Governance, Directory Sync, Local Accounts, and SSO State Machine

**Files:**
- Create: `Release platform/internal/iam/model.go`
- Create: `Release platform/internal/iam/ports.go`
- Create: `Release platform/internal/iam/service.go`
- Create: `Release platform/internal/iam/sso_state_machine.go`
- Create: `Release platform/internal/iam/password.go`
- Create: `Release platform/internal/iam/postgres_repository.go`
- Create: `Release platform/internal/iam/http_handlers.go`
- Create: `Release platform/internal/iam/service_test.go`
- Create: `Release platform/internal/iam/sso_state_machine_test.go`
- Create: `Release platform/internal/iam/password_test.go`
- Create: `Release platform/migrations/000009_iam.up.sql`
- Create: `Release platform/migrations/000009_iam.down.sql`
- Create: `Release platform/tests/integration/iam_repository_test.go`
- Create: `Release platform/tests/contract/identity_directory_test.go`
- Modify: `Release platform/api/openapi.yaml`
- Modify: `Release platform/apps/release-api/main.go`

**Interfaces:**
- Consumes: `identity.Principal`, `identity.Authorizer`, Task 3 audit writer, configuration Secret references, and PostgreSQL transaction boundary.
- Produces: `iam.Service`, `iam.DirectoryAdapter`, `iam.SessionRevoker`, identity-source HTTP operations, and immutable identity audit events.

```go
type LoginMode string

const (
    LoginModeLocal       LoginMode = "local"
    LoginModeConfiguring LoginMode = "configuring"
    LoginModeSSO         LoginMode = "sso"
    LoginModeFault       LoginMode = "fault"
)

type DirectoryAdapter interface {
    Verify(ctx context.Context, source IdentitySource) (CapabilityReport, error)
    Preview(ctx context.Context, source IdentitySource) (SyncDiff, error)
    Sync(ctx context.Context, source IdentitySource, cursor string) (SyncPage, error)
}

type SessionRevoker interface {
    RevokeSubject(ctx context.Context, subjectID uuid.UUID, reason string) error
}
```

- [ ] **Step 1: Write failing SSO safety tests**

```go
func TestEnableSSORequiresVerifiedSourceMappingPreviewAndEmergencyAccount(t *testing.T) {
    h := newIAMHarness(t)
    err := h.Service.EnableSSO(h.AdminContext(), h.SourceID)
    require.ErrorIs(t, err, iam.ErrSSOPreconditionFailed)
    require.Equal(t, iam.LoginModeLocal, h.Repository.LoginMode())
}

func TestFaultDoesNotEnableRegularLocalLogin(t *testing.T) {
    h := newIAMHarness(t)
    h.EnableSSOWithValidPreconditions()
    h.Service.MarkIdentitySourceFault(h.SystemContext(), h.SourceID, "OIDC_UNREACHABLE")
    require.Equal(t, iam.LoginModeFault, h.Repository.LoginMode())
    require.ErrorIs(t, h.Service.AuthenticateLocal(h.UserContext(), "member", "secret"), iam.ErrLocalLoginDisabled)
}

func TestCannotDisableLastUsableEmergencyAdministrator(t *testing.T) {
    h := newIAMHarness(t)
    err := h.Service.DisableUser(h.AdminContext(), h.LastEmergencyAdminID, "rotation")
    require.ErrorIs(t, err, iam.ErrLastEmergencyAdministrator)
}
```

- [ ] **Step 2: Verify the tests fail before implementation**

Run: `cd 'Release platform' && go test ./internal/iam -run 'TestEnableSSO|TestFault|TestCannotDisable' -v`

Expected: package or symbols do not exist; no test may be skipped.

- [ ] **Step 3: Create the IAM schema and repository contract**

Create append-audited tables for `user_principals`, `identity_sources`, `organization_units`, `organization_memberships`, `role_bindings`, `local_credentials`, `sync_jobs`, `sync_conflicts`, and `emergency_access_events`. External identity uniqueness is `(identity_source_id, external_subject)`; local account names use a canonical, case-insensitive unique key. `role_bindings` supports user or organization subjects, platform/product/channel scopes, allow/deny effect, validity interval, creator, and version. Down migration removes only these P0 IAM objects in reverse dependency order.

- [ ] **Step 4: Implement password and local-account protection**

Use Argon2id with parameters loaded from bounded configuration; store algorithm, parameters, salt and hash, never plaintext. Enforce minimum length, breached-password policy Port, password history, activation-token digest, expiry, progressive lockout and IP/account rate limits. Administrators and emergency accounts require MFA enrollment before activation. Activation tokens and recovery codes are returned once and are redacted by logging middleware.

- [ ] **Step 5: Implement directory synchronization**

Implement verify, preview and paged incremental sync behind `DirectoryAdapter`. External name, email, organization and enabled status are source-owned and read-only. Platform roles, product scopes and local supplemental organizations are platform-owned and cannot be overwritten. Duplicate stable subjects, ambiguous email matching and organization cycles become `sync_conflicts`; they retain the last safe state and require an explicit resolution event.

- [ ] **Step 6: Implement the login-mode state machine**

`EnableSSO` requires a successful connection verification, complete required mappings, a successful sync preview, at least one active emergency administrator with MFA and fresh credential rotation, reauthentication and explicit confirmation. In `sso` or `fault`, regular local authentication fails closed. `DisableSSO` is allowed only to an authorized emergency/admin principal after reauthentication and writes before/after state summaries in the same transaction as the mode change.

- [ ] **Step 7: Implement role and scope evaluation**

Resolve direct and organization bindings for platform, product and channel. Explicit deny wins; disabled subjects and expired bindings win over allows. Keep Task 3 API authorization as the authoritative enforcement point. Revoke active sessions after user disable, source disable or high-risk role removal. Preserve self-approval prohibition independently of role union.

- [ ] **Step 8: Add REST contracts and handlers**

Implement the exact user, local-user, organization, role-binding and identity-source endpoints from the supplemental design. Use cursor pagination, optimistic version checks, RFC 9457 errors, reauthentication challenges for high-risk actions and asynchronous sync jobs. Secrets are accepted by write-only secret reference and never returned by GET.

- [ ] **Step 9: Run IAM verification and commit**

Run: `cd 'Release platform' && go test ./internal/iam ./tests/integration ./tests/contract -run 'IAM|Identity|Directory|SSO|Emergency|RoleBinding' -race -count=1`

Run: `cd 'Release platform' && make lint && make test`

```bash
git add 'Release platform'
git commit -m "feat: add governed SSO and local identity management"
```

---

### Task 15: Unified Log Center and Trusted Request-Time Authorization Snapshots

**Files:**
- Create: `Release platform/internal/authorizationcontext/model.go`
- Create: `Release platform/internal/authorizationcontext/resolver.go`
- Create: `Release platform/internal/authorizationcontext/jws_resolver.go`
- Create: `Release platform/internal/authorizationcontext/jws_resolver_test.go`
- Create: `Release platform/internal/logcenter/model.go`
- Create: `Release platform/internal/logcenter/ports.go`
- Create: `Release platform/internal/logcenter/service.go`
- Create: `Release platform/internal/logcenter/middleware.go`
- Create: `Release platform/internal/logcenter/postgres_repository.go`
- Create: `Release platform/internal/logcenter/http_handlers.go`
- Create: `Release platform/internal/logcenter/redaction.go`
- Create: `Release platform/internal/logcenter/service_test.go`
- Create: `Release platform/internal/logcenter/redaction_test.go`
- Create: `Release platform/migrations/000010_log_center.up.sql`
- Create: `Release platform/migrations/000010_log_center.down.sql`
- Create: `Release platform/tests/integration/log_center_repository_test.go`
- Create: `Release platform/tests/contract/authorization_context_test.go`
- Modify: `Release platform/api/openapi.yaml`
- Modify: `Release platform/apps/release-api/main.go`
- Modify: `Release platform/apps/release-worker/main.go`

**Interfaces:**
- Consumes: authenticated gateway identity, allow-listed JWS issuers or an in-process trusted adapter; Task 3 operation audit; Task 9 SCM events; PostgreSQL and object-store archive ports.
- Produces: `authorizationcontext.Resolver`, immutable `authorizationcontext.Snapshot`, four typed log writers, query/export services, and request-correlation middleware.

```go
type Snapshot struct {
    CustomerID       string
    CustomerName     string
    TenantID         string
    AuthorizationName string
    ClientAppVersion string
    LicenseID        string
    LicenseExpiresAt time.Time
    LicenseStatus    LicenseStatus
    Decision         Decision
    ReasonCode       string
    ValidatedAt      time.Time
    ValidatorIssuer  string
    ContextDigest    [32]byte
}

type Resolver interface {
    Resolve(ctx context.Context, envelope SignedEnvelope, binding RequestBinding) (Snapshot, error)
}

type Writer interface {
    WriteApplicationRequest(ctx context.Context, event ApplicationRequestEvent) error
    WriteAuthentication(ctx context.Context, event AuthenticationEvent) error
    WriteGitSync(ctx context.Context, event GitSyncEvent) error
}
```

- [ ] **Step 1: Write failing trust-boundary and immutability tests**

```go
func TestUnsignedClientFieldsCannotBecomeAuthorizationFacts(t *testing.T) {
    resolver := newTestResolver(t)
    _, err := resolver.Resolve(context.Background(), unsignedEnvelopeFromHeaders(), validRequestBinding())
    require.ErrorIs(t, err, authorizationcontext.ErrUntrustedContext)
}

func TestRequestSnapshotDoesNotChangeAfterUpstreamLicenseMutation(t *testing.T) {
    h := newLogCenterHarness(t)
    eventID := h.RecordAllowedRequest(validSnapshot("LIC-2026-000184", "valid"))
    h.Upstream.ChangeLicense("LIC-2026-000184", "revoked")
    got := h.Repository.ApplicationRequest(eventID)
    require.Equal(t, logcenter.LicenseStatusValid, got.AuthorizationSnapshot.LicenseStatus)
}

func TestExpiredAuthorizationIsDeniedAndRecordedWithoutSecrets(t *testing.T) {
    h := newLogCenterHarness(t)
    response := h.CallWithSignedExpiredContext()
    require.Equal(t, http.StatusForbidden, response.StatusCode)
    event := h.Repository.LastApplicationRequest()
    require.Equal(t, logcenter.DecisionDeny, event.AuthorizationSnapshot.Decision)
    require.NotContains(t, event.CanonicalJSON(), "Authorization")
    require.NotContains(t, event.CanonicalJSON(), "license_key")
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `cd 'Release platform' && go test ./internal/authorizationcontext ./internal/logcenter -v`

Expected: packages or required symbols do not exist.

- [ ] **Step 3: Implement signed authorization-context validation**

Validate JWS algorithm allow-list, issuer, audience, signature, `exp`, `nbf`, `iat`, request ID/method/path binding and bounded clock skew. Reject replayed context identifiers through a TTL replay store. Normalize fields before SHA-256 digest generation. Enforce maximum lengths and strict enums. Do not log the signed envelope. mTLS gateway mode additionally verifies the authenticated client certificate identity against configuration.

- [ ] **Step 4: Create append-only partitioned log storage**

Create monthly partitioned tables for operation, authentication, application-request and Git-sync logs. Application-request rows embed immutable snapshot columns and a canonical snapshot digest. Database roles used by API and Worker receive `INSERT`/`SELECT` but no `UPDATE`/`DELETE` on audit evidence. Add indexes for time, product, customer, authorization name, client app version, License ID, status, Request ID and Correlation ID; prove representative query plans use bounded partition scans.

- [ ] **Step 5: Implement data-minimizing middleware and typed writers**

Record HTTP method, route template, status, duration, source IP policy result, Request ID, Correlation ID and Trace ID. Never record raw query strings, request bodies, Cookie, Authorization, tokens, passwords, private keys, recovery codes, License Key or JWS. If a protected request has missing/invalid context, return RFC 9457 `AUTHORIZATION_CONTEXT_INVALID` and record only validated identity, request metadata, deny decision and stable reason code.

- [ ] **Step 6: Implement four log queries and related-event lookup**

Implement the exact endpoints from the supplemental design with cursor pagination and explicit per-type filter DTOs. Application-request queries support time, product, customer, authorization name, client app version, License ID, License status, decision, HTTP status, Request ID and Correlation ID. Related-event lookup requires at least one authorized correlation key and re-applies product-scope authorization to every result.

- [ ] **Step 7: Implement retention, archive and evidence export**

Default online retention is 90 days and immutable archive retention is 365 days. A scheduled job exports closed partitions as newline-delimited canonical JSON plus manifest, SHA-256 digest and Ed25519 archive signature through the object-store Port. It verifies the uploaded object before marking the partition archived. Partition deletion is a separate privileged job, requires policy age and verified archive, and emits an operation audit event. Exports are asynchronous, permission-filtered, time-limited and download-audited.

- [ ] **Step 8: Add failure policy and observability**

High-risk administrative operations fail closed when operation-audit persistence fails. Application-request logging uses a bounded encrypted local spool with retry; spool saturation triggers alerting and control-plane rate limiting, never silent drop. Add metrics for validation failures, log write failures, partition size, query latency, export depth, archive verification and spool occupancy.

- [ ] **Step 9: Run log and authorization-context verification and commit**

Run: `cd 'Release platform' && go test ./internal/authorizationcontext ./internal/logcenter ./tests/integration ./tests/contract -run 'AuthorizationContext|LogCenter|Redaction|Snapshot|Partition' -race -count=1`

Run: `cd 'Release platform' && make lint && make test`

```bash
git add 'Release platform'
git commit -m "feat: add trusted authorization snapshots and unified logs"
```

---

### Task 16: Ant Design Pro Identity and Log Center Console, Integration, and Final P0 Acceptance

**Files:**
- Create: `Release platform/apps/release-console/src/pages/users/UsersPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/users/OrganizationsPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/users/LocalAccountsPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/roles/RoleBindingsPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/identity/IdentitySourcesPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/logs/LogCenterPage.tsx`
- Create: `Release platform/apps/release-console/src/pages/logs/ApplicationRequestLogTable.tsx`
- Create: `Release platform/apps/release-console/src/pages/logs/AuthorizationSnapshotPanel.tsx`
- Create: `Release platform/apps/release-console/src/pages/logs/logFilters.ts`
- Create: `Release platform/apps/release-console/src/pages/logs/LogCenterPage.test.tsx`
- Create: `Release platform/apps/release-console/src/pages/identity/IdentitySourcesPage.test.tsx`
- Create: `Release platform/apps/release-console/src/pages/users/UsersPage.test.tsx`
- Create: `Release platform/tests/e2e/identity-log-console.spec.ts`
- Create: `Release platform/tests/e2e/p0_identity_log_flow_test.go`
- Create: `Release platform/docs/operations/identity-sso.md`
- Create: `Release platform/docs/operations/log-retention-export.md`
- Modify: `Release platform/apps/release-console/src/app/routes.tsx`
- Modify: `Release platform/apps/release-console/src/layout/AppShell.tsx`
- Modify: `Release platform/apps/release-console/src/api/types.ts`
- Modify: `Release platform/deploy/compose/compose.yaml`
- Modify: `Release platform/deploy/monitoring/alerts.yml`
- Modify: `Release platform/scripts/run-p0-acceptance.sh`
- Modify: `Release platform/docs/operations/p0-acceptance.md`

**Interfaces:**
- Consumes: Task 14 IAM APIs, Task 15 log APIs, Task 11 white-shell components, Task 12 deployment baseline, and the confirmed `xminds-release-console.html` interaction model.
- Produces: complete P0 management console, identity/log operating procedures, monitoring rules, and final auditable P0 acceptance result.

- [ ] **Step 1: Write failing frontend behavior tests**

```tsx
it('labels client application version separately from license state', async () => {
  renderApp({ route: '/logs/application-requests', principal: auditor });
  expect(await screen.findByRole('columnheader', { name: '客户端应用版本' })).toBeVisible();
  expect(screen.getByRole('columnheader', { name: 'License ID' })).toBeVisible();
  expect(screen.getByText('请求时授权快照')).toBeVisible();
});

it('keeps regular local login disabled while SSO is in fault state', async () => {
  renderApp({ route: '/identity/sources', principal: administrator, loginMode: 'fault' });
  expect(await screen.findByText('SSO 故障')).toBeVisible();
  expect(screen.getByText('普通本地登录保持关闭')).toBeVisible();
  expect(screen.getByRole('link', { name: '应急管理员入口' })).toBeVisible();
});
```

- [ ] **Step 2: Verify frontend tests fail**

Run: `cd 'Release platform/apps/release-console' && npm test -- --run src/pages/logs src/pages/identity src/pages/users`

Expected: routes and components do not exist.

- [ ] **Step 3: Implement system-management navigation and identity pages**

Add Users, Organizations, Local Accounts, Role Bindings and Identity Sources under “系统管理”. Implement directory-source badges, read-only external fields, product/channel scope previews, SSO verification and enable checklist, sync progress/conflicts, local account activation, last-emergency-account blocking and high-risk confirmation. Do not show any credential value after creation.

- [ ] **Step 4: Implement the four-tab log center**

Replace the standalone Audit route with Operation, Authentication, Application Request and Git Sync tabs while preserving direct links. Application requests show time, customer, authorization name, client app version, shortened License ID, expiry, request-time status, HTTP status and Request ID. At 1280px use table-container horizontal scrolling with sticky time/customer columns; the document body must not overflow. The white 760–840px drawer shows the complete License ID and snapshot metadata with controlled copy.

- [ ] **Step 5: Implement filter, reset, related-event and export interactions**

Filters are URL-addressable and typed. Customer, authorization name, client app version, License ID, status and time filters must compose; reset clears all non-default parameters. Related-event navigation preserves the original query state. Export displays permission scope, field redaction, retention notice and asynchronous completion status.

- [ ] **Step 6: Add browser visual and accessibility regression**

At 1280×800 and 1440×900, assert white side navigation, white Logo/collapse area, white drawers, visible current-item state, no body horizontal overflow, keyboard-accessible filters/drawers, visible focus, text-plus-color statuses and usable fixed columns. Capture screenshots only as test artifacts; never accept pixel snapshots as the sole semantic assertion.

- [ ] **Step 7: Extend Compose, alerts and recovery acceptance**

Configure identity Secret references, trusted authorization-context issuers/audiences, log retention, archive signing key reference and encrypted spool bounds. Add alerts for SSO outage, unavailable emergency access, repeated sync failures, context validation spikes, log-write failure, spool saturation, archive verification failure and storage capacity. Recovery must restore identity modes, role bindings, log partitions, archive manifests and snapshot digests before serving traffic.

- [ ] **Step 8: Run integrated security and history tests**

Create a valid request, mutate the upstream License fixture to revoked, and assert the original log remains valid while a later request records revoked/deny. Attempt unsigned, expired, wrong-audience and replayed contexts and assert rejection. Scan API responses, console DOM, log rows, exports and archive files for forbidden secret field names and fixture secret values.

- [ ] **Step 9: Execute final P0 verification**

Run: `cd 'Release platform/apps/release-console' && npm run lint && npm run typecheck && npm test -- --run && npm run build`

Run: `cd 'Release platform' && npx playwright test tests/e2e/console.spec.ts tests/e2e/identity-log-console.spec.ts`

Run: `cd 'Release platform' && go test ./... -race -count=1 && ./scripts/run-p0-acceptance.sh && git diff --check`

Expected: all release, identity, authorization-context, log, UI, security, offline and recovery gates pass; `artifacts/acceptance/p0-summary.json` contains no secret values and explicitly reports all 18 P0 acceptance criteria.

- [ ] **Step 10: Commit the final P0 baseline**

```bash
git add 'Release platform'
git commit -m "feat: complete P0 identity and log management baseline"
```

---

## Specification Coverage Matrix

| 设计要求 | 实施任务 |
|---|---|
| 独立、可拆仓工程边界 | Task 1、Task 12 |
| OIDC、工作负载身份、RBAC、审计和导出 | Task 3、Task 8、Task 14、Task 15 |
| 多产品与 `product-manifest` | Task 4、Task 13 |
| 分块上传、SHA-256、不可变制品 | Task 5 |
| Release 状态机、职责分离、幂等 | Task 6 |
| 五角色目录、root 离线、revocation 回滚 | Task 7、Task 8 |
| GitHub.com、GHES、GitLab Self-Managed | Task 9、Task 13 |
| 企业 CA、代理、私网和无公网 | Task 9、Task 13 |
| Distribution Endpoint 与兼容目录 API | Task 10 |
| React + Ant Design Pro v6.6.0 浅色管理控制台 | Task 11、Task 16 |
| 外部身份同步、本地/应急账户和 SSO 状态机 | Task 14、Task 16 |
| 用户、组织、角色和产品/通道范围治理 | Task 14、Task 16 |
| 四类统一日志、关联检索和证据导出 | Task 15、Task 16 |
| 客户、授权名称、客户端版本和 License 请求时快照 | Task 15、Task 16 |
| 授权上下文信任边界、历史不可变和敏感字段禁采 | Task 15、Task 16 |
| Compose、离线包、监控告警、备份恢复 | Task 12、Task 13、Task 16 |
| `ngep` 零代码修改消费契约 | Task 7、Task 10、Task 13 |
| 性能、安全与 P0 综合验收 | Task 13、Task 16 |

---

## Plan Completion Gate

Before declaring P0 complete, run:

```bash
cd 'Release platform'
make verify
./scripts/run-p0-acceptance.sh
git diff --check
```

Completion requires all 16 tasks, all 18 P0 acceptance criteria, all acceptance gates, the identity/SSO failure-mode tests, authorization-snapshot history tests, log archive recovery exercise, private SCM no-public-network test, frozen `ngep` compatibility contract, white-console browser regression, secret scan, and macOS metadata scan to pass. A skipped environment-dependent test is not a pass; its required environment must be supplied before P0 completion.
