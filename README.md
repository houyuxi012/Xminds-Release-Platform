# Xminds Release Platform

Xminds Release Platform 是面向企业软件交付场景的多产品可信发布平台。平台统一管理制品、Release、职责分离审批、TUF 风格可信目录、SCM 集成、分发端点、身份治理和审计证据。

## 当前状态

项目处于 P0 实施阶段，已交付第一批平台基础能力：

- 严格的 `XMINDS_RELEASE_*` 配置边界和非开发环境必填校验；
- 显式 `release-api migrate` 与 `release-api serve` 模式，服务启动不会隐式修改数据库；
- PostgreSQL 内嵌迁移、advisory lock 串行化和已执行迁移 SHA-256 漂移防护；
- 基于 UUIDv7、事务入队和 `FOR UPDATE SKIP LOCKED` 的可靠 Outbox；
- RFC 9457 Problem Details、请求 ID、安全响应头和 OpenTelemetry HTTP 插桩；
- OpenAPI 3.1 基础契约及机器校验测试。
- OIDC Discovery/JWKS 验签、issuer/audience/时间声明校验和强制 token ID；
- GitHub Actions、GitHub Enterprise Actions、GitLab CI 工作负载区分，以及仅保存 Argon2id 哈希的 API Token fallback；
- 显式角色-动作矩阵、产品范围 RBAC、审计查询与导出的对象级授权；
- 按产品分区的不可变审计哈希链、敏感字段递归脱敏，以及事务化审计导出 Outbox；
- 版本化 `xminds-product-manifest/v1`、双产品无特例注册、默认通道和稳定 SHA-256 Manifest 摘要；
- 产品、默认通道和审计证据的事务一致性，以及数据库层 Manifest 不可变保护；
- 产品注册、范围内列表/详情和停用的 OpenAPI 3.1 与 RFC 9457 HTTP 适配器契约。
- 24 小时可恢复分块上传、20 GiB/10000 分块硬限制、同分块安全重传和产品范围隔离；
- MinIO/S3 兼容存储适配器、服务端独立 SHA-256 流式校验、内容寻址去重与最终对象不可删除；
- 摘要不匹配隔离及事务化清理 Outbox，以及制品上传/完成的不可变审计证据；
- 制品上传、分块、完成与元数据查询的 OpenAPI 3.1 和 RFC 9457 HTTP 适配器契约。
- `DRAFT → SUBMITTED → APPROVED/REJECTED → PUBLISHING → PUBLISHED/FAILED` 精确 Release 状态机；
- 显式审批者角色、提交者与审批者职责分离、数据库乐观锁及不可变 Release 内容；
- 并发安全的发布幂等键、事务化 attempt/审计/Outbox，以及审批者授权重试和正交撤销证据；
- Release 创建、提交、批准、拒绝、发布、重试、撤销和查询的 OpenAPI 3.1 与 RFC 9457 HTTP 契约。
- 严格 Canonical JSON、Ed25519 五角色签名链、跨角色摘要/版本绑定和 NGEP 消费端黄金向量；
- AES-256-GCM 本地加密 Signing Provider、在线 root 拒绝门禁、单调 Catalog 版本仓储和原子 current pointer；
- 离线 root 密钥工具及双人控制的[密钥仪式规范](docs/security/key-ceremony.md)。
- 可续租的持久化 Worker、分级退避重试、五次失败死信和领域状态终结；
- 五角色目录的不可变对象发布、回读摘要校验、数据库原子 current 切换和崩溃后幂等恢复；
- 发布后撤销目录、Release/attempt 完成与失败回写，以及 UTF-8 JSONL 审计导出的摘要和过期控制。
- GitHub.com/GHES 与 GitLab Self-Managed 统一 Provider Port、显式 API Base URL 和标准化 Webhook 事件；
- 固定 DNS 解析地址、系统根加版本化企业 CA、禁用重定向与环境代理的 SSRF/TLS 出站边界；
- GitHub HMAC-SHA256、GitLab Standard Webhooks/旧版 Secret Token 验签、事件重放幂等和事务审计；
- 提交查询、Check Run/Commit Status 能力回写、`scm.status.writeback.v1` 持久作业与本地私有 CA 契约测试；
- AES-256-GCM Provider 凭据密文持久化、AAD 元数据绑定、主密钥 ID 轮换和旧凭据即时撤销。
- origin、CDN 与私有分发端点的产品范围注册、HTTPS 摘要校验、优先级和连续失败健康状态；
- `endpoint.sync.v1` 五角色目录与引用制品复制、目标端回读 SHA-256 校验和三次失败摘除；
- 独立公网监听端口、默认产品兼容目录路径、产品/通道隔离目录路径和支持单段 Range 的内容寻址制品下载。
- 基于受信任 Secret 根的 OIDC discovery/JWKS 与 SCIM 2.0 连接验证，并强制非对称签名算法、可用公钥材料、同源 JWKS、TLS 1.2+、禁用环境代理与重定向；
- SCIM Users/Groups 分页归一化、有界对象计数与持久化 preview/apply 作业，支持 Worker 崩溃后从服务端游标幂等恢复；
- 目录来源字段所有权、本地角色/补充成员关系保留、full snapshot 终页停用及冲突对象最后安全状态保留。
- 基于 React 19、Ant Design 6 与 Ant Design Pro Components 的发布管理控制台；
- 白色管理台导航与详情抽屉、产品注册、断点续传、职责分离审批、SCM 能力探测、端点健康和审计证据主流程；
- 真实 Chromium 组件测试与 Playwright 端到端主流程验收。

当前管理 API 运行时已挂载产品、制品、Release、分发端点、审计查询/导出和 IAM 治理路由。业务路由统一位于 OIDC 人工身份、OIDC 工作负载身份和 Argon2id API Token 组合验证边界之后；任一验证器缺失都会拒绝启动或对业务路由 fail closed。角色变更、用户启停/会话撤销和 SSO 切换还必须消费与 actor、operation 及完成 Bearer token ID 精确绑定的服务端一次性重认证 evidence；工作负载和 API Token 不具备 human reauthentication 能力。存活、就绪和版本端点保持匿名可用。分发端点激活使用 DNS 解析地址固定、禁用环境代理和重定向的 TLS 探测，私有 CA 仅能通过受控 Secret 目录中的单文件引用。独立 Public API 只挂载公开目录和制品读取路由，不包含管理操作。Worker 已挂载目录发布、目录撤销、审计导出和版本化身份目录同步处理器；端点同步的具体目标写入适配器仍需在部署组合根注入。统一日志中心属于后续任务。所有签名材料、IAM Secret 与对象存储凭据必须在启动时显式注入，否则拒绝运行。

## P0 能力范围

- 多产品注册与产品级权限隔离；
- 分块制品上传、SHA-256 校验和不可变对象存储；
- Release 创建、提交、职责分离审批、发布和失败重试；
- root、targets、snapshot、timestamp、revocation 五角色可信目录；
- GitHub.com、GitHub Enterprise Server 和 GitLab Self-Managed 集成；
- OIDC、目录同步、本地账户、应急账户和产品范围授权；
- 操作、登录、应用请求和 Git 同步统一日志中心；
- Docker Compose 在线/离线交付、监控、审计和恢复基线。

P0 只保存可信上游产生的请求时授权快照，不负责 License 创建、签发、续期、计量和吊销。

## 工程结构

```text
apps/       API、Worker 和 Console 入口
api/        OpenAPI 3.1 接口契约与校验测试
internal/   模块化单体领域与平台能力
migrations/ 编译内嵌的 PostgreSQL 迁移
scripts/    构建、边界和交付检查
tests/      集成、契约、端到端和性能测试
```

## 开发环境

- Go 1.26.5；
- Node.js 24 LTS；
- PostgreSQL 17.10；
- Docker Compose；
- golangci-lint v2（执行扩展静态检查时需要）。

## 常用命令

```bash
make fmt
make lint
make test
make test-integration
make build
make console-verify
make console-e2e
make verify
```

`make verify` 会执行格式、Go Vet、竞态测试、双二进制构建、仓库边界检查、macOS 元数据污染检查，以及 Console 的静态检查、类型检查、真实浏览器组件测试和生产构建。`make console-e2e` 单独执行产品创建、制品续传、职责分离发布、SCM、端点和审计证据主流程。

## 管理控制台

控制台位于 `apps/release-console`。首次启动先安装锁定依赖：

```bash
make console-install
cd apps/release-console
npx playwright install chromium
npm run dev
```

默认开发地址为 `http://127.0.0.1:4173`。开发环境提供确定性的演示数据用于交互验收；产品创建在生产构建中调用 `/api/v1/products`，后端仍是身份、授权、状态机和审计证据的唯一权威来源。当前 Console 交付 P0 核心可信发布管理流程，用户与组织、统一日志中心按后续实施任务接入，不在前端复制服务端安全策略。

## 本地启动

复制 [`.env.example`](.env.example) 中的变量到本地环境，并确保 PostgreSQL 已创建对应数据库。迁移与服务启动必须分开执行：

```bash
go run ./apps/release-api migrate
go run ./apps/release-api serve
go run ./apps/release-worker
```

默认管理 API 监听 `127.0.0.1:8080`，可访问：

- `GET /health/live`：进程存活检查；
- `GET /health/ready`：PostgreSQL 就绪检查；
- `GET /version`：构建版本信息；
- `POST /api/v1/auth/local/activate`：一次性激活本地账户；
- `POST /api/v1/auth/local/login`：本地账户登录；
- `POST /api/v1/auth/emergency/login`：强制 MFA 的应急账户登录。

上述 3 个认证入口不要求现有 Bearer，重认证挑战创建/完成和其他管理 API 仍在统一认证中间件之后。所有环境都必须配置绝对路径 `XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY`；生产、测试和预发环境还必须配置指向非可写 SHA-1/SHA-256 摘要文件的 `XMINDS_RELEASE_IAM_BREACH_CORPUS`，缺失时服务拒绝启动。仅显式 `development` 环境可通过 `XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS=true` 单独启用内置最小语料库；缺省环境、其他环境或与外部语料库同时配置时均拒绝启动。锁定阶段可通过 `XMINDS_RELEASE_IAM_LOCKOUT_STAGES=5:5m,8:30m,10:24h` 配置，次数和时长必须严格递增且满足运行时安全上下界。高风险挑战 TTL、evidence TTL、OIDC 新鲜度/时钟偏差、终态保留期和有界清理批次可通过 `.env.example` 中的 `XMINDS_RELEASE_IAM_REAUTH_*` 变量调整；越过安全边界的配置会导致服务拒绝启动。

### 目录连接与异步同步

`XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY` 是 API 与 Worker 共享的受信任 IAM Secret 根（变量名为兼容已有部署保留）。目录必须是无符号链接的绝对路径，Secret 文件不得对 group/other 开放权限，单文件上限 4 KiB。数据库只保存 `secret://iam/<name>` 引用，不保存 Bearer、CA 或 Secret 内容。OIDC 来源 Secret 为严格 JSON：

```json
{
  "issuer": "https://id.example.invalid",
  "audience": "xminds-release-platform",
  "roles_claim": "roles",
  "product_ids_claim": "product_ids",
  "token_use_claim": "token_use",
  "signing_algorithms": ["RS256"],
  "ca_reference": "secret://iam/corporate-ca"
}
```

SCIM 来源 Secret 只引用另一个 Bearer 文件，禁止将 Token 直接写入来源 JSON：

```json
{
  "base_url": "https://id.example.invalid/scim/v2",
  "bearer_token_reference": "secret://iam/scim-bearer",
  "ca_reference": "secret://iam/corporate-ca",
  "page_size": 100
}
```

`POST .../verify` 使用必填来源版本验证真实 OIDC discovery/JWKS 或 SCIM ServiceProviderConfig/ResourceTypes。SCIM 必须声明支持分页，ResourceTypes 会按严格 ListResponse 不变量有界收齐；Users/Groups 每个资源必须包含对应 core schema，后续页 `totalResults` 与首页不一致时立即 fail closed。`POST .../sync-preview` 和 `POST .../sync` 返回 `202 Accepted` 及作业 `Location`，作业通过现有 Outbox 由 `release-worker` 执行。只有 SCIM 来源支持 apply；OIDC 来源只支持连接验证和空快照预览。Worker 持久化每页游标，最终页才会在来源 ID 与本次 run marker 边界内停用缺失对象和清理来源成员关系。重复稳定标识、邮箱/规范用户名冲突、组织循环或缺失/冲突父组织会生成可分页查询的冲突记录，相关对象保留最后安全状态，不会自动猜测、覆盖本地字段或删除角色绑定。每个实际 apply batch 的业务变更、进度和无 PII/Secret 不可变审计在同一事务中提交；审计不可用时整批回滚并可恢复重试。冲突分页游标由独立 Secret-backed AES-256-GCM 密钥加密认证，并将路由、来源、schema 版本、filter 和页大小直接纳入 AEAD 附加认证数据，同时绑定有效期，禁止篡改或跨上下文重放。轮换时原子替换 Secret 并重启 API，旧游标立即 fail closed，客户端按默认 15 分钟短有效期契约从首页重新分页。

目录请求总超时可在 1–30 秒范围内调整，总页数上限为 10000，用户、组织、成员和层级关系总数上限为 100000。出站连接在解析后固定 IPv4/IPv6 地址并在拨号层校验目标 host，默认拒绝 loopback、link-local/metadata、unspecified、multicast 和私网地址，禁用环境代理与重定向。只有 `development`/`test` 可通过兼容变量 `XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_LOOPBACK_HTTP=true` 显式允许 loopback HTTP/HTTPS；企业私网必须经审核后显式设置 `XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_PRIVATE_NETWORKS=true`，且仍强制 TLS 1.2+、正确 ServerName 与受控 CA。具体变量与默认值见 [`.env.example`](.env.example)。

默认 Public API 监听 `127.0.0.1:8081`，只提供：

- `GET /metadata/{role}.json`：部署配置指定的默认产品与通道兼容路径；
- `GET /v1/products/{product}/channels/{channel}/metadata/{role}.json`：产品范围可信目录；
- `GET /v1/products/{product}/artifacts/{sha256}`：内容寻址制品下载与单段 Range 请求。

Public API 仍需只读对象存储凭据，并要求显式配置 `XMINDS_RELEASE_DEFAULT_PRODUCT_ID` 与 `XMINDS_RELEASE_DEFAULT_CHANNEL`；缺少任一项时服务拒绝启动。

Worker 依赖预先执行的数据库迁移、可用的 S3/MinIO 桶、经签名的 `root.json`、四类在线角色加密私钥和 32 字节主密钥文件。SCM Provider 凭据使用独立主密钥目录与当前 key ID，历史 key 仅用于轮换期解密，不能复用于目录签名。完整变量见 [`.env.example`](.env.example)，root 与在线密钥边界见[密钥仪式规范](docs/security/key-ceremony.md)。

## PostgreSQL 集成测试

集成测试只接受数据库名包含 `test` 的连接串，避免误清理非测试数据库：

```bash
export XMINDS_RELEASE_TEST_DATABASE_URL='postgres://xminds_release_test:xminds_release_test@127.0.0.1:55432/xminds_release_test?sslmode=disable'
make test-integration
```

制品端到端集成测试还需要一个隔离的 MinIO 测试桶：

```bash
export XMINDS_RELEASE_TEST_MINIO_URL='http://127.0.0.1:59000'
export XMINDS_RELEASE_TEST_MINIO_ACCESS_KEY='仅用于测试的访问密钥'
export XMINDS_RELEASE_TEST_MINIO_SECRET_KEY='仅用于测试的秘密密钥'
export XMINDS_RELEASE_TEST_MINIO_BUCKET='xminds-release-test'
make test-integration
```

集成测试产生的已校验内容寻址对象保持不可变；测试应使用专用桶，并按环境生命周期整体回收测试桶。

## 安全原则

- 安全默认、最小权限和职责分离；
- root 私钥不得进入在线服务、数据库、镜像或源码；
- 禁止全局跳过 TLS 验证；
- Token、Cookie、Authorization、License Key、密码和私钥不得进入普通日志；
- 所有状态修改必须认证、授权并生成不可变审计证据。

## 许可证

本项目按照仓库中的 [LICENSE](LICENSE) 授权。
