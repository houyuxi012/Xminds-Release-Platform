# PostgreSQL 认证会话真实环境验收实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 PostgreSQL 18 专用测试数据库中验证本地登录会话能够跨服务对象重建继续认证，退出仅撤销当前会话，撤销后的旧令牌立即失效且审计证据持久化。

**Architecture:** 集成测试为每个用例创建隔离测试数据库并执行完整迁移，使用真实 Argon2id 密码摘要、`PostgresRepository`、`LocalAuthService`、`SessionVerifier`、`GovernedPrincipalResolver` 与 PostgreSQL 审计仓库。所谓服务重启使用同一数据库上的全新 Repository/Service/Verifier 实例模拟，避免测试代码依赖 Docker 守护进程；Docker 容器重启由外层验收步骤执行，再运行同一测试确认 PostgreSQL 18 与迁移状态恢复。

**Tech Stack:** Go 1.26、PostgreSQL 18、pgx、chi 身份主体契约、Argon2id、不可变审计

**Spec:** `docs/superpowers/specs/2026-08-14-xminds-release-platform-p0-identity-log-baseline-design.md`

## Global Constraints

- 数据库连接串的数据库名必须包含 `test`，并为每个测试创建、清理独立数据库。
- Token、密码、密码摘要、Authorization 与 Secret 不得输出到测试日志或普通日志。
- 测试必须使用真实 PostgreSQL Repository，不以 mock 替代数据库状态变化。
- 退出只能撤销认证主体 `TokenID` 对应的当前本地会话；其他并行会话保持有效。
- 审计写入失败必须与会话撤销同事务回滚；现有单元测试继续承担该失败分支。
- 不修改或提交 `docs/superpowers` 与 `.superpowers`。
- 本批次不提交、不推送 Git，直至用户明确授权。

---

### Task 1: PostgreSQL 登录与服务重建会话验收

**Files:**
- Create: `tests/integration/iam_local_session_test.go`

**Interfaces:**
- Consumes: `iam.NewLocalAuthService`、`iam.NewSessionVerifier`、`iam.NewGovernedPrincipalResolver`、`iam.NewPostgresRepository`
- Produces: `TestIAMLocalSessionSurvivesServiceReconstruction`

- [x] **Step 1: 写真实 PostgreSQL 失败测试**

创建隔离数据库，写入一个 active 本地管理员及真实 Argon2id 摘要，调用 `LoginLocal` 获取不透明令牌；随后只保留数据库并重建 Repository、Verifier 与 governed resolver，断言旧服务对象不参与验证且新对象可解析同一用户、会话 ID、管理员角色与平台范围。

- [x] **Step 2: 在基线 HEAD 上运行并确认失败**

Run: 将测试文件放入由当前 HEAD 导出的临时只读基线副本，再运行：

```bash
XMINDS_RELEASE_TEST_DATABASE_URL='postgres://xminds_release_test:xminds_release_test@127.0.0.1:55432/xminds_release_test?sslmode=disable' \
go test ./tests/integration -run TestIAMLocalSessionSurvivesServiceReconstruction -count=1 -v
```

Expected: FAIL，因为基线尚未提供本批次当前会话/退出契约所需的完整接口或路由装配。

- [x] **Step 3: 在当前工作树运行测试**

Run: 使用同一连接串运行目标测试。

Expected: PASS，且测试日志不出现令牌或密码。

### Task 2: 当前会话撤销、并行会话隔离与审计验收

**Files:**
- Modify: `tests/integration/iam_local_session_test.go`

**Interfaces:**
- Consumes: `LocalAuthService.LogoutCurrentSession`、`SessionVerifier.Verify`
- Produces: `TestIAMLogoutRevokesOnlyCurrentPersistedSession`

- [x] **Step 1: 写并行会话撤销测试**

同一用户连续登录两次；使用第一枚令牌得到的 governed principal 执行退出，断言第一枚令牌被拒绝、第二枚令牌仍可验证、数据库中只有第一条会话写入 `revoked_at/revocation_reason`，并存在一条 `identity.session.logout` 成功审计事件。

- [x] **Step 2: 运行目标测试**

Run: 使用专用测试连接串运行 `TestIAMLogoutRevokesOnlyCurrentPersistedSession`。

Expected: PASS。

### Task 3: PostgreSQL 18 容器重启与全量门禁

**Files:**
- Modify: `docs/plans/2026-08-30-postgresql-auth-session-acceptance.md`（仅更新勾选状态）

**Interfaces:**
- Consumes: `compose.integration.yaml` 中 `postgres:18-alpine`
- Produces: 可重复的真实环境验收证据

- [x] **Step 1: 运行认证目标测试与全量集成测试**

Run: 设置 PostgreSQL/MinIO 专用测试变量后执行 `make test-integration`。

Expected: 所有真实数据库、对象存储测试通过，PostgreSQL 主版本断言为 18。

- [x] **Step 2: 重启 PostgreSQL 测试容器**

Run: `docker compose -f compose.integration.yaml restart postgres`，随后等待 healthcheck healthy。

Expected: 容器恢复 healthy，数据卷未重建。

- [x] **Step 3: 重启后重跑认证目标测试**

Run: 再次运行两个 `TestIAM...Session` 目标测试。

Expected: PASS，证明迁移与持久化认证状态在 PostgreSQL 服务重启后仍可用。

- [x] **Step 4: 最终边界检查**

Run: `git diff --check`、`git status --short -- docs/superpowers .superpowers`。

Expected: 无 whitespace 错误；禁止目录保持干净；无提交、无推送。
