# Xminds Release Platform

Xminds Release Platform 是面向企业软件交付场景的多产品可信发布平台。平台统一管理制品、Release、职责分离审批、TUF 风格可信目录、SCM 集成、分发端点、身份治理和审计证据。

## 当前状态

项目处于 P0 实施阶段。当前代码只包含独立工程骨架和安全启动保护；API 与 Worker 在配置模块完成前会明确报错并以非零状态退出，不会启动未受保护的占位服务。

P0 设计与实施基线：

- [P0 总体设计规格](docs/superpowers/specs/2026-08-13-xminds-release-platform-p0-design.md)
- [身份治理与统一日志补充规格](docs/superpowers/specs/2026-08-14-xminds-release-platform-p0-identity-log-baseline-design.md)
- [P0 实施计划](docs/superpowers/plans/2026-08-13-xminds-release-platform-p0-implementation.md)

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
internal/   模块化单体领域与平台能力
scripts/    构建、边界和交付检查
tests/      集成、契约、端到端和性能测试
docs/       架构、运维、安全、规格和实施计划
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
make build
make verify
```

`make verify` 会执行格式、Go Vet、竞态测试、双二进制构建、仓库边界检查和 macOS 元数据污染检查。

## 安全原则

- 安全默认、最小权限和职责分离；
- root 私钥不得进入在线服务、数据库、镜像或源码；
- 禁止全局跳过 TLS 验证；
- Token、Cookie、Authorization、License Key、密码和私钥不得进入普通日志；
- 所有状态修改必须认证、授权并生成不可变审计证据。

## 许可证

本项目按照仓库中的 [LICENSE](LICENSE) 授权。
