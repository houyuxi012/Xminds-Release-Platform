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
- 按产品分区的不可变审计哈希链、敏感字段递归脱敏，以及事务化审计导出 Outbox。

当前运行时只开放存活、就绪和版本端点。身份、授权与审计领域服务及 OpenAPI 契约已完成，后续业务 HTTP 适配器接入这些安全边界后才会开放管理端点，不会先暴露未受保护的占位接口。

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
```

默认管理 API 监听 `127.0.0.1:8080`，可访问：

- `GET /health/live`：进程存活检查；
- `GET /health/ready`：PostgreSQL 就绪检查；
- `GET /version`：构建版本信息。

Worker 目前保持安全关闭，直到具体领域作业处理器完成后才会进入消费循环。

## PostgreSQL 集成测试

集成测试只接受数据库名包含 `test` 的连接串，避免误清理非测试数据库：

```bash
export XMINDS_RELEASE_TEST_DATABASE_URL='postgres://xminds_release_test:xminds_release_test@127.0.0.1:55432/xminds_release_test?sslmode=disable'
make test-integration
```

## 安全原则

- 安全默认、最小权限和职责分离；
- root 私钥不得进入在线服务、数据库、镜像或源码；
- 禁止全局跳过 TLS 验证；
- Token、Cookie、Authorization、License Key、密码和私钥不得进入普通日志；
- 所有状态修改必须认证、授权并生成不可变审计证据。

## 许可证

本项目按照仓库中的 [LICENSE](LICENSE) 授权。
