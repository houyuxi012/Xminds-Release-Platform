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

当前 API 运行时只开放存活、就绪和版本端点。产品、制品和 Release HTTP 适配器已经完成并强制从请求上下文获取已验证身份；在 API 组合根完成 OIDC/工作负载身份配置前不会挂载业务路由，避免暴露未受保护的管理接口。Worker 已挂载目录发布、目录撤销和审计导出处理器，所有签名材料与对象存储凭据必须在启动时显式注入，否则拒绝运行。

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
make verify
```

`make verify` 会执行格式、Go Vet、竞态测试、双二进制构建、仓库边界检查和 macOS 元数据污染检查。

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
- `GET /version`：构建版本信息。

Worker 依赖预先执行的数据库迁移、可用的 S3/MinIO 桶、经签名的 `root.json`、四类在线角色加密私钥和 32 字节主密钥文件。完整变量见 [`.env.example`](.env.example)，root 与在线密钥边界见[密钥仪式规范](docs/security/key-ceremony.md)。

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
