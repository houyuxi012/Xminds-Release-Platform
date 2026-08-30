# 控制台认证接入实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为管理控制台接入可验证的登录模式、本地/应急登录、当前会话角色范围、内存令牌生命周期与 401 失效处理，并在 SSO/fault 状态保持普通本地登录关闭。

**Architecture:** 后端新增最小公开登录状态资源和受统一认证中间件保护的当前会话资源；前端使用单一内存会话仓库持有令牌和主体，不写入 Web Storage。`local|configuring` 显示普通本地登录，`sso|fault` fail closed 并只暴露独立应急入口；完整 OIDC Authorization Code + PKCE/BFF 作为后续独立计划实施，不在前端拼接或回传令牌。

**Tech Stack:** Go 1.26、chi、OpenAPI 3.1、React 19、TypeScript 7、Ant Design 6.6.1、TanStack Query、Vitest、Playwright

**Spec:** `docs/superpowers/specs/2026-08-14-xminds-release-platform-p0-identity-log-baseline-design.md`

## Global Constraints

- SSO 未启用时使用本地登录；启用后普通本地登录关闭，故障时不得自动降级，仅独立应急入口可用。
- 访问令牌只能保存在页面内存中，不得写入 `localStorage`、`sessionStorage`、URL、日志或 DOM。
- 前端角色与范围必须来自服务端当前会话契约，不得根据账户类型猜测。
- 所有响应使用稳定 snake_case HTTP DTO；失败使用 RFC 9457 Problem Details。
- 不修改或提交 `docs/superpowers` 与 `.superpowers`。
- 本批次不提交、不推送 Git，直至用户明确授权。

---

### Task 1: 登录状态与当前会话 HTTP 契约

**Files:**
- Modify: `internal/iam/local_auth.go`
- Modify: `internal/iam/local_auth_http.go`
- Modify: `internal/iam/local_auth_http_test.go`
- Modify: `internal/iam/http_handler.go`
- Modify: `api/openapi.yaml`
- Modify: `api/openapi_test.go`
- Modify: `apps/release-api/main.go`

**Interfaces:**
- Consumes: `Repository.GetLoginState(context.Context, pgx.Tx)`、认证中间件写入的 `identity.Principal`
- Produces: `GET /api/v1/auth/login-state`、`GET /api/v1/auth/session`

- [x] **Step 1: 写登录状态失败测试**

```go
func TestPublicLoginStateExposesOnlySafeMode(t *testing.T) {
    handler := localAuthManagementHandler(newActiveLocalAuthHarness(t, UserKindLocal, false, LoginModeLocal).service)
    response := httptest.NewRecorder()
    handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-state", nil))
    if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"mode":"local"}` {
        t.Fatalf("response=%d body=%s", response.Code, response.Body)
    }
}
```

- [x] **Step 2: 运行测试并确认因路由不存在而失败**

Run: `go test ./internal/iam -run TestPublicLoginStateExposesOnlySafeMode -count=1`

Expected: FAIL，状态码为 404。

- [x] **Step 3: 实现最小登录状态读取与公开路由**

```go
type PublicLoginState struct {
    Mode LoginMode `json:"mode"`
}

func (service *LocalAuthService) GetPublicLoginState(ctx context.Context) (PublicLoginState, error) {
    state, err := service.loginState.GetLoginState(ctx, nil)
    if err != nil {
        return PublicLoginState{}, err
    }
    return PublicLoginState{Mode: state.Mode}, nil
}
```

- [x] **Step 4: 写当前会话失败测试**

```go
func TestCurrentSessionReturnsGovernedIdentityWithoutTokenMaterial(t *testing.T) {
    principal := identity.Principal{Subject: "release.operator", Kind: identity.PrincipalKindLocal, Governed: true, GovernedUserID: userID.String(), RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}}}
    // 请求受保护的 /api/v1/auth/session，断言 subject、kind、roles、role_scopes，且响应不含 token_id/access_token。
}
```

- [x] **Step 5: 运行测试并确认因会话路由不存在而失败**

Run: `go test ./internal/iam ./apps/release-api -run 'TestCurrentSession|TestManagementRoutesExposeCurrentSession' -count=1`

Expected: FAIL，状态码为 404。

- [x] **Step 6: 实现当前会话 DTO 与受保护路由**

```go
type CurrentSession struct {
    Subject        string               `json:"subject"`
    Kind           identity.PrincipalKind `json:"kind"`
    GovernedUserID string               `json:"governed_user_id,omitempty"`
    Roles          []identity.Role      `json:"roles"`
    RoleScopes     []identity.RoleScope `json:"role_scopes"`
}
```

响应只投影授权所需字段，禁止返回 `TokenID`、原始 Bearer、Identity Source Secret 或凭据字段。

- [x] **Step 7: 更新 OpenAPI 并运行契约测试**

Run: `go test ./api ./internal/iam ./apps/release-api -run 'OpenAPI|LoginState|CurrentSession' -count=1`

Expected: PASS。

### Task 2: 前端认证 API 与内存会话仓库

**Files:**
- Modify: `apps/release-console/src/api/types.ts`
- Modify: `apps/release-console/src/api/client.ts`
- Modify: `apps/release-console/src/api/client.test.ts`
- Create: `apps/release-console/src/auth/sessionStore.ts`
- Create: `apps/release-console/src/auth/sessionStore.test.ts`

**Interfaces:**
- Consumes: `GET /api/v1/auth/login-state`、`POST /api/v1/auth/local/login`、`POST /api/v1/auth/emergency/login`、`GET /api/v1/auth/session`
- Produces: `ApiClient.getLoginState()`、`ApiClient.loginLocal()`、`ApiClient.loginEmergency()`、`ApiClient.getCurrentSession()`、`sessionStore`

- [x] **Step 1: 写 API 与会话仓库失败测试**

```ts
it('本地登录不发送旧 Bearer 并转换会话 DTO', async () => {
  const result = await createApiClient({ getAccessToken: () => 'stale-token' }).loginLocal({
    username: 'release.operator',
    password: 'Strong-Password!',
  });
  expect(result.tokenType).toBe('Bearer');
  expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty('authorization');
});

it('到期时清空内存令牌与主体', () => {
  const store = createSessionStore({ now: () => Date.parse('2026-08-30T10:00:00Z') });
  store.authenticate(sessionFixture);
  store.expire(Date.parse('2026-08-30T10:30:00Z'));
  expect(store.getSnapshot().status).toBe('anonymous');
});
```

- [x] **Step 2: 运行测试并确认接口缺失**

Run: `cd apps/release-console && npm run test:run -- src/api/client.test.ts src/auth/sessionStore.test.ts`

Expected: FAIL，`loginLocal` 与 `createSessionStore` 不存在。

- [x] **Step 3: 实现无认证请求、DTO 解码与单一内存会话仓库**

```ts
export interface SessionStore {
  getSnapshot(): AuthSnapshot;
  subscribe(listener: () => void): () => void;
  authenticate(session: AuthenticatedSession): void;
  clear(reason?: SessionEndReason): void;
}
```

公共认证请求显式设置 `authenticated: false`；受保护请求遇到 401 调用唯一 `onUnauthorized` 回调。仓库使用 `setTimeout` 到期清理，且不访问任何 Web Storage API。

- [x] **Step 4: 运行前端 API 与仓库测试**

Run: `cd apps/release-console && npm run test:run -- src/api/client.test.ts src/auth/sessionStore.test.ts`

Expected: PASS。

### Task 3: 登录页、路由守卫与控制台身份展示

**Files:**
- Modify: `apps/release-console/src/auth/AuthProvider.tsx`
- Create: `apps/release-console/src/pages/auth/LoginPage.tsx`
- Modify: `apps/release-console/src/app/App.tsx`
- Modify: `apps/release-console/src/app/routes.tsx`
- Modify: `apps/release-console/src/layout/AppShell.tsx`
- Modify: `apps/release-console/src/styles.css`
- Modify: `apps/release-console/src/test/app.behavior.test.tsx`
- Modify: `apps/release-console/tests/e2e/console-flow.spec.ts`

**Interfaces:**
- Consumes: Task 2 `ApiClient` 和 `sessionStore`
- Produces: 认证初始化、普通/应急登录、会话守卫、真实主体展示、退出与 401 返回登录页

- [x] **Step 1: 写登录状态矩阵失败测试**

```tsx
it('SSO fault 时不显示普通本地登录并保留应急入口', async () => {
  render(<App initialEntries={['/']} />);
  expect(await screen.findByText('SSO 服务异常')).toBeVisible();
  expect(screen.queryByLabelText('用户名')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: '应急管理员登录' })).toBeVisible();
});
```

- [x] **Step 2: 运行测试并确认当前控制台绕过登录**

Run: `cd apps/release-console && npm run test:run -- src/test/app.behavior.test.tsx`

Expected: FAIL，页面直接显示控制台 Shell。

- [x] **Step 3: 实现认证 Provider、登录页与守卫**

生产入口必须先请求登录模式。`local|configuring` 显示普通本地表单；`sso` 显示“企业 SSO 已启用”并链接下一批 OIDC BFF 实施说明；`fault` 显示故障且不降级。应急入口使用 `/api/v1/auth/emergency/login`，MFA 字段必填。成功登录后读取 `/api/v1/auth/session`，再进入控制台。

- [x] **Step 4: 移除生产角色切换器并接入退出**

```tsx
<Dropdown menu={{ items: [{ key: 'logout', label: '退出登录' }], onClick: logout }}>
  <Button type="text">{principal.displayName}</Button>
</Dropdown>
```

测试专用 `initialRoles` 仅作为显式依赖注入保留，不出现在生产构建交互路径。

- [x] **Step 5: 更新端到端登录流程并运行全量验收**

Run: `cd apps/release-console && npm run lint && npm run typecheck && npm run test:run && npm run build && npm run e2e`

Expected: 所有命令 PASS，构建无超过既定预算的 chunk，端到端先完成本地登录再验证产品主流程。

- [x] **Step 6: 浏览器视觉与交互验收**

在内置 Browser/IAB 中验证 1440×900 与 1280×800：登录卡片、键盘焦点、错误 Request ID、白色侧栏、真实主体菜单、退出、401 返回登录页、`sso|fault` 不出现普通本地表单。记录与已确认 Ant Design Pro 白色控制台的差异并修复。
