# 真实 API 控制台联调验收实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 以 PostgreSQL 18、MinIO 和完整 `release-api` 进程为真实后端，完成本地管理员正式激活、MFA 登录、当前会话、产品列表和退出的浏览器直连验收，不拦截认证或产品请求。

**Architecture:** 使用仅允许 loopback 且数据库名包含 `test` 的运行时管理员 fixture 工具，在隔离测试数据库中生成一次性 pending 管理员与平台管理员绑定，再通过公开 MFA enrollment/activation HTTP 接口正式激活。Vite 开发服务器仅在开发期将 `/api` 代理到显式目标；独立 Playwright real profile 和内置 Browser 直接执行真实 API 流程，现有确定性 Mock E2E 保持不变。

**Tech Stack:** Go 1.26、PostgreSQL 18、MinIO、React 19、Ant Design 6.6.1、Vite 8、Playwright、TOTP/HMAC-SHA1

**Spec:** `docs/superpowers/specs/2026-08-14-xminds-release-platform-p0-identity-log-baseline-design.md`

## Global Constraints

- fixture 工具只允许 loopback PostgreSQL、数据库名包含 `test`、loopback API URL；任一条件不满足立即拒绝。
- 激活令牌、密码、TOTP seed、恢复码和 Bearer 令牌不得输出到 stdout/stderr、普通日志、URL 或仓库文件。
- 最终凭据只写入调用方指定的仓库外文件，必须以独占创建和 `0600` 权限保存，并在验收后删除。
- 管理员普通本地登录必须支持 MFA；前端不得因为不知道账户角色而隐藏 MFA 输入。
- 真实 E2E 禁止 `page.route`、MSW 或 fetch stub；现有 Mock E2E 保留用于完整业务流程的确定性回归。
- 不修改或提交 `docs/superpowers` 与 `.superpowers`。
- 本批次不提交、不推送 Git，直至用户明确授权。

---

### Task 1: 普通本地登录 MFA 输入

**Files:**
- Modify: `apps/release-console/src/pages/auth/LoginPage.tsx`
- Modify: `apps/release-console/src/test/app.behavior.test.tsx`

**Interfaces:**
- Consumes: `LocalLoginInput.mfaProof`
- Produces: 普通本地登录可选 MFA 动态验证码；应急登录仍强制必填

- [x] **Step 1: 写失败行为测试**

在 `mode=local` 下断言“用户名、密码、MFA 动态验证码（如已启用）”同时可见，MFA 输入非必填；`mode=fault` 切换应急入口后仍断言 MFA 必填。

- [x] **Step 2: 运行测试并确认失败**

Run: `cd apps/release-console && npm run test:run -- src/test/app.behavior.test.tsx`

Expected: FAIL，普通本地登录找不到 MFA 输入。

- [x] **Step 3: 实现单一 MFA 字段**

普通模式显示可选 MFA 输入，应急模式复用同一输入并增加 required 规则；提交时仍仅在非空时发送 `mfa_proof`。

- [x] **Step 4: 重跑行为测试**

Expected: PASS。

### Task 2: 安全的真实运行时管理员 fixture

**Files:**
- Create: `tests/support/runtime-admin-fixture/main.go`
- Create: `tests/support/runtime-admin-fixture/main_test.go`

**Interfaces:**
- Consumes: `--database-url`、`--api-url`、`--output`、`--repository-root`、`--username`、环境变量 `XMINDS_RELEASE_RUNTIME_FIXTURE_PASSWORD`
- Produces: 通过真实公开 HTTP 激活的管理员账户，以及仓库外 `0600` JSON 凭据文件

- [x] **Step 1: 写安全边界与 TOTP 失败测试**

断言拒绝非 loopback 数据库、数据库名不含 `test`、非 loopback API、已存在输出文件、仓库内输出、符号链接及非私有目录；使用 RFC 6238 SHA-1 向量验证 30 秒时间步 TOTP。

- [x] **Step 2: 运行测试确认入口尚不存在**

Run: `go test ./tests/support/runtime-admin-fixture -count=1`

Expected: FAIL，fixture 校验和执行函数不存在。

- [x] **Step 3: 实现最小 fixture**

在单一 PostgreSQL 事务中写入 pending local user、空密码材料 credential、平台 admin allow binding 与 `identity.local_user.test_bootstrap` 审计；令牌只保存 SHA-256。随后调用 `/auth/local/mfa-enrollments` 和 `/auth/local/activate`，使用 TOTP 激活，最后独占写入 `{username,password,totp_secret,display_name,totp_available_at}`。

- [x] **Step 4: 运行 fixture 单元测试**

Expected: PASS，且无 Secret 输出。

### Task 3: 本地工作负载 OIDC stub 与开发 API 代理

**Files:**
- Create: `tests/support/runtime-oidc-stub/main.go`
- Create: `tests/support/runtime-oidc-stub/main_test.go`
- Modify: `apps/release-console/vite.config.ts`

**Interfaces:**
- Consumes: `--listen`、`XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET`
- Produces: 仅用于启动期 discovery 的 loopback OIDC provider；开发服务器同源 `/api` 代理

- [x] **Step 1: 写 OIDC discovery 契约测试**

断言 issuer、`jwks_uri` 与空 JWKS 均使用同一 loopback origin；非 loopback listen 拒绝启动。

- [x] **Step 2: 实现 stub 与 Vite 开发代理**

stub 只提供 discovery/JWKS，不签发令牌；Vite 默认代理 `http://127.0.0.1:8080`，可由显式环境变量覆盖。

- [x] **Step 3: 运行 Go 测试、前端 typecheck 与 lint**

Expected: PASS。

### Task 4: 无 Mock 真实认证 E2E

**Files:**
- Create: `apps/release-console/playwright.real.config.ts`
- Create: `apps/release-console/tests/e2e/real-auth.spec.ts`
- Modify: `apps/release-console/package.json`

**Interfaces:**
- Consumes: `XMINDS_RELEASE_REAL_E2E_CREDENTIALS_FILE`、真实 `/api/v1/auth/*` 与 `/api/v1/products`
- Produces: `npm run e2e:real`

- [x] **Step 1: 创建 real profile**

profile 强制要求显式 loopback `XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET` 并传给 Vite dev server；测试读取仓库外 `0600` 凭据、在测试进程内生成当前 TOTP。缺少目标或凭据路径时拒绝启动，测试文件不得注册网络拦截。

- [x] **Step 2: 实现真实交互断言**

流程：检查显式目标 `/health/ready` → 访问 `/products` → 输入用户名/密码/MFA → 看到真实主体 → 通过 UI 创建唯一测试产品 → 返回列表重新读取产品 → 账户菜单退出 → 返回登录页。

- [x] **Step 3: 静态防漂移检查**

在 real test 中不允许 `page.route`；通过代码审查和真实后端请求日志/数据库审计共同证明未使用 Mock。

### Task 5: 完整运行时与 Browser 验收

**Files:**
- Modify: `docs/plans/2026-08-30-real-api-console-acceptance.md`（仅更新勾选状态）

**Interfaces:**
- Consumes: PostgreSQL 18 `55432`、MinIO `59000`、OIDC stub、API `18080/18081`、Vite `4173`
- Produces: 真实环境验收证据

- [x] **Step 1: 创建隔离数据库与仓库外 Secret 目录**

目录权限 `0700`，cursor key 文件权限 `0400`；数据库名 `xminds_release_runtime_test`，不复用其他项目数据。

- [x] **Step 2: 执行 migrate 并启动 OIDC/API**

等待 `/health/ready=200` 和 `/api/v1/auth/login-state={"mode":"local"}`。

- [x] **Step 3: 运行 fixture 与 real E2E**

Expected: fixture 正式激活成功；使用 `XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET=http://127.0.0.1:18080` 和仓库外凭据运行 `npm run e2e:real` PASS，并能重新读取本次创建的真实产品。

- [x] **Step 4: 使用内置 Browser 验证目标流程**

检查 URL/title、非空页面、无框架 overlay、console error/warn、桌面截图和至少一次真实登录/退出交互。

- [x] **Step 5: 最终回归与清理**

运行 Go/前端测试与 `git diff --check`；停止 API/OIDC/Vite，删除仓库外临时凭据、Secret 与隔离测试数据库，不删除 PostgreSQL/MinIO 测试卷。
