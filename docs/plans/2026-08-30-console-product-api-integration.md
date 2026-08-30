# Console 产品真实 API 接入实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标：** 将控制台产品列表、产品详情和产品创建从演示数据切换到后端真实 HTTP API，保证请求、响应、错误和身份边界与 OpenAPI 契约一致。

**架构：** 前端仅在 `src/api` 边界理解后端 `snake_case` DTO，通过运行时解码转换为页面使用的领域模型。通用 HTTP 传输层统一注入 Bearer Token、解析 RFC 9457 Problem Details 并禁止缓存敏感响应；TanStack Query 负责查询状态、失效和重取。产品 Manifest 由表单显式收集，不在业务组件中硬编码隐含字段。

**技术栈：** React 19、TypeScript 7、TanStack Query 5、Ant Design 6.6.1、Ant Design Pro Components 3、Vitest Browser Mode、MSW 2。

**契约来源：** `api/openapi.yaml` 的 `ProductManifestV1`、`Product`、`ProductPage` 定义及已确认的 Ant Design Pro v6 原型。

## 全局约束

- 生产代码不得引用 `demoData`，开发模式不得伪造成功响应。
- 后端 DTO 以 OpenAPI 为唯一事实源，页面不直接依赖数据库字段或 Go 内部结构。
- Bearer Token 仅通过可注入凭据提供器读取；本批不将 Token 持久化到 `localStorage`。
- 错误必须保留 `status`、`code`、`request_id` 和服务端 `detail`，不将后端错误改写为模糊成功或通用失败。
- 保持已确认的白色导航、白色详情抽屉和 Ant Design Pro 信息层级。
- 不修改、不提交 `docs/superpowers` 和 `.superpowers`。

## 任务 1：建立 API 传输与产品契约测试

**文件：**

- 新建：`apps/release-console/src/api/client.test.ts`
- 修改：`apps/release-console/src/api/client.ts`
- 修改：`apps/release-console/src/api/types.ts`

**验收步骤：**

1. 先编写列表 DTO 解码、不透明游标编码、完整 Manifest 请求体、Bearer 头和 Problem Details 的失败测试。
2. 运行 `npm test -- src/api/client.test.ts` 并确认因能力未实现而失败。
3. 实现通用 HTTP 请求、响应契约解码与产品 API。
4. 重跑定向测试并确认通过。

## 任务 2：产品列表与详情接入 TanStack Query

**文件：**

- 修改：`apps/release-console/src/pages/products/ProductsPage.tsx`
- 修改：`apps/release-console/src/tests/console.behavior.test.tsx`

**验收步骤：**

1. 先将行为测试改为由真实 API DTO 驱动，覆盖加载、列表、详情和 RFC 9457 错误状态。
2. 确认旧的 `demoData` 实现无法通过新测试。
3. 使用 `useQuery` 接入列表，表格加载/空状态/错误状态与服务端事实一致。
4. 详情抽屉显示 Manifest 版本、制品类型、兼容性键、通道和完整 SHA-256 摘要。

## 任务 3：产品创建表单切换为完整 Manifest

**文件：**

- 修改：`apps/release-console/src/pages/products/ProductCreatePage.tsx`
- 修改：`apps/release-console/src/tests/app.behavior.test.tsx`

**验收步骤：**

1. 先编写成功创建和服务端校验错误测试，断言完整 `ProductManifestV1` 请求体。
2. 将简化字段替换为产品 ID、显示名称、制品类型、兼容性键和默认通道列表。
3. 成功后失效产品列表查询，失败时保留表单输入和请求 ID。

## 任务 4：静态质量门禁与真实浏览器验收

**验收命令：**

1. `npm run test:run`
2. `npm run typecheck`
3. `npm run lint`
4. `npm run build`
5. 在 Codex 内置浏览器中验证产品列表、详情抽屉、创建成功与 Problem Details 失败流程。

## 提交策略

本计划执行期间只保留工作区改动。待用户明确确认后，再单独执行提交和推送，提交范围不包含 `docs/superpowers` 与 `.superpowers`。
