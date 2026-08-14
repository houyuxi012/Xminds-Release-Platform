# Xminds Release Platform Ant Design Pro v6 原型优化执行计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 Open Design 项目中，将 Xminds Release Platform P0 管理控制台优化为 Ant Design Pro v6.6.0 风格的精致可交互网页原型，并保持既有业务流程与安全语义不变。

**Architecture:** 继续使用现有单文件交互原型 `xminds-release-console.html`，通过一次 Local Codex 设计改进任务统一设计 Token、ProLayout 页面框架、ProTable 数据页面、Release 核心流程和日志中心。任务完成后使用真实浏览器执行视觉与交互回归，不生成生产业务代码。

**Tech Stack:** Open Design、Local Codex、单文件 HTML/CSS/JavaScript 原型、Ant Design Pro v6.6.0 设计语言、Ant Design 6、ProComponents v3 交互模式、浏览器回归验证。

## Global Constraints

- 目标项目固定为 `xminds-release-platform-p0-console-local-codex-final`。
- 目标文件固定为 `xminds-release-console.html`。
- 设计基线固定为 Ant Design Pro v6.6.0、Ant Design 6、ProComponents v3。
- 保留 Xminds 品牌、中文业务术语和现有信息架构；侧栏、Logo 区和折叠控制区使用已确认的白色视觉。
- 核心验收流程固定为“创建 Release—提交审批—发布—查看结果”。
- 必须保留产品、制品、SCM 连接、分发端点和日志中心的关联页面与现有核心交互。
- 不新增租户、计费、License 生命周期、Telemetry 或灰度发布等业务能力；请求时 License 只读快照属于已确认日志字段。
- 不修改后端、数据库、API 或生产前端代码。
- Token、Cookie、Authorization、密码、密钥和请求敏感载荷必须保持脱敏。
- 状态表达必须同时使用文字与颜色；危险操作必须具备二次确认。

---

### Task 1: 确认目标项目与执行环境

**Files:**
- Read: Open Design project `xminds-release-platform-p0-console-local-codex-final`
- Read: Open Design artifact `xminds-release-console.html`
- Read: `docs/superpowers/specs/2026-08-14-xminds-release-platform-antd-pro-v6-prototype-design.md`

**Interfaces:**
- Consumes: 已确认的设计规格和现有 Open Design 项目。
- Produces: 可执行的 Local Codex 运行环境、明确的目标项目和目标文件。

- [ ] **Step 1: 查询 Open Design 可用执行器**

  要求 Local Codex 可用且已认证；不得切换到 Open Design Cloud 或 secure BYOK。

- [ ] **Step 2: 解析目标项目**

  确认项目 ID 精确为 `xminds-release-platform-p0-console-local-codex-final`，且项目名称为“Xminds Release Platform P0 管理控制台原型（Local Codex 最终）”。

- [ ] **Step 3: 读取当前原型上下文**

  检查 `xminds-release-console.html` 是否存在，并确认包含概览、产品、制品、Release、SCM 连接、分发端点、日志中心七类导航入口。

- [ ] **Step 4: 建立回归基线**

  记录当前可交互入口：导航切换、Release 创建/审批、详情抽屉、日志四页签、请求 ID 关联检索、Git 同步时间线、证据导出。

### Task 2: 执行 Ant Design Pro v6 视觉与交互改进

**Files:**
- Modify: Open Design project `xminds-release-platform-p0-console-local-codex-final/xminds-release-console.html`

**Interfaces:**
- Consumes: Task 1 的原型基线和已确认设计规格。
- Produces: 完整、可直接预览的 Ant Design Pro v6.6.0 风格交互原型。

- [ ] **Step 1: 启动唯一一次 Local Codex 设计改进任务**

  运行提示必须明确：

  - 直接改进当前 Open Design 项目中的 `xminds-release-console.html`，不得新建替代项目或第二份主原型。
  - 以 Ant Design Pro v6.6.0 为视觉基线，使用 ProLayout、PageContainer、ProTable、ProCard、StatisticCard、ProForm、StepsForm、Descriptions、Drawer、Modal、Tabs、Timeline、Alert、Result、Empty、Skeleton 等组件模式。
  - 使用 `#1677FF` 主色、`#F5F7FA` 工作区背景、白色内容表面、6 至 8px 圆角和 8px 主间距节奏。
  - 左侧导航展开宽度约 224px，顶栏高度约 56px，适配 1440px 和 1280px 桌面宽度。
  - 保留 Xminds 品牌和全部中文业务术语，侧栏与 Logo 区使用白色，不使用 Emoji 图标，不制作成无差异的通用后台模板。
  - 统一页面标题、面包屑、工具栏、搜索筛选、表格、分页、抽屉、弹窗和反馈样式。
  - Release 核心流程使用四步 StepsForm 风格；审批详情使用 Descriptions、Alert 和 Timeline；发布、拒绝、撤销等危险操作必须二次确认。
  - 日志中心保留操作日志、登录日志、应用请求日志和 Git 同步日志；保留脱敏、Request ID/Correlation ID 关联检索、Git 失败重试时间线和证据导出。
  - 保留所有既有交互，修复改造过程中发现的断链、遮挡、无反馈和错误状态问题。
  - 不加载真实 Ant Design 运行时，不依赖外部网络资源；通过原型内 CSS 与 JavaScript 准确模拟组件外观和行为。

- [ ] **Step 2: 轮询同一任务至终态**

  每 30 至 60 秒查询一次任务状态。任务处于排队或运行状态时不得重复启动、取消或用直接文件写入绕过设计任务。

- [ ] **Step 3: 确认任务成功产出**

  成功条件为任务状态明确返回成功，且返回本次任务对应的 Studio 或 Preview 链接；失败或取消不得使用旧链接冒充新结果。

### Task 3: 验证整体视觉与页面结构

**Files:**
- Test: Open Design preview for `xminds-release-console.html`

**Interfaces:**
- Consumes: Task 2 成功生成的原型链接。
- Produces: 视觉一致性和响应式布局验证结论。

- [ ] **Step 1: 验证总体框架**

  检查白色 Xminds 侧栏、浅色工作区、56px 顶栏、PageContainer 标题层级和 Ant Design Pro 风格导航选中态是否一致。

- [ ] **Step 2: 验证 Design Token**

  检查主色、文字层级、背景色、圆角、边框、阴影、间距和状态色是否全局统一；不得残留明显冲突的旧样式。

- [ ] **Step 3: 验证 1440px 与 1280px 布局**

  确认关键字段、主操作、筛选器和表格操作列不存在遮挡、溢出或不可点击区域。

- [ ] **Step 4: 验证边界状态**

  检查至少一种加载、空数据、操作成功、操作失败和危险确认反馈，确保状态不只依赖颜色表达。

### Task 4: 回归 Release 核心流程

**Files:**
- Test: Open Design preview for `xminds-release-console.html`

**Interfaces:**
- Consumes: Task 2 的交互原型。
- Produces: Release 核心流程回归结论。

- [ ] **Step 1: 从概览进入 Release**

  点击概览中的待审批或发布指标，确认进入带对应筛选条件的 Release 列表。

- [ ] **Step 2: 验证创建 Release 四步流程**

  依次操作“基本信息—选择制品—发布配置—确认提交”，确认当前步骤、已完成步骤、摘要信息和前后导航状态正确。

- [ ] **Step 3: 验证审批与发布详情**

  打开 Release 详情，检查描述信息、校验提示、状态时间线和审批动作；确认提交人不得审批自身提交的语义仍被清晰表达。

- [ ] **Step 4: 验证危险操作确认**

  触发发布、拒绝或撤销操作，确认弹窗明确展示对象、影响和后续结果，取消后状态不得变化。

### Task 5: 回归关联页面与日志中心

**Files:**
- Test: Open Design preview for `xminds-release-console.html`

**Interfaces:**
- Consumes: Task 2 的交互原型。
- Produces: 关联业务页面和日志中心回归结论。

- [ ] **Step 1: 验证数据页面**

  逐一进入产品、制品、SCM 连接和分发端点页面，检查筛选、表格、分页、详情抽屉和状态标签是否可用。

- [ ] **Step 2: 验证日志四页签**

  依次切换操作日志、登录日志、应用请求日志和 Git 同步日志，确认筛选项、列结构和示例数据随页签变化。

- [ ] **Step 3: 验证脱敏与关联查询**

  打开应用请求详情，确认 Authorization、Cookie、Token 等字段不可见或已脱敏；使用 Request ID 或 Correlation ID 触发跨类型关联查询并保持原筛选上下文。

- [ ] **Step 4: 验证 Git 同步详情**

  打开失败记录，检查拉取、校验、目录生成、状态回写和重试结果时间线，并验证重试操作具有明确反馈。

- [ ] **Step 5: 验证证据导出**

  触发导出操作，确认存在权限语义、异步处理中反馈和完成提示，且不得展示敏感原始载荷。

### Task 6: 完成验收与交付

**Files:**
- Read: `docs/superpowers/specs/2026-08-14-xminds-release-platform-antd-pro-v6-prototype-design.md`
- Read: `docs/superpowers/plans/2026-08-14-xminds-release-platform-antd-pro-v6-prototype.md`

**Interfaces:**
- Consumes: Task 3 至 Task 5 的验证结果。
- Produces: 可打开的最终原型链接和完整验收结论。

- [ ] **Step 1: 对照规格逐项检查**

  确认视觉系统、总体框架、全部页面、反馈状态、安全要求、非目标和验收标准均有对应验证结果。

- [ ] **Step 2: 确认没有进入业务代码实现**

  本次变更应仅存在于 Open Design 原型；工作区内除设计规格与执行计划外不得新增生产实现文件。

- [ ] **Step 3: 交付本次任务返回的最终链接**

  最终回复只使用本次成功任务返回的 Studio 或 Preview 链接，并说明已验证的核心流程与仍属于后续实现阶段的边界。
