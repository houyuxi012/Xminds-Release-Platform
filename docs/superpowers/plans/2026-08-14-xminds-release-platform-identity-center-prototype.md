# Xminds Release Platform 身份与用户中心交互原型实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 Xminds Release Platform P0 管理控制台原型中补齐用户、组织、权限、身份源和本地账户治理流程，并将左侧导航与全部右侧详情抽屉统一为白色。

**Architecture:** 保留现有 Open Design 单文件交互原型及 Ant Design Pro v6.6.0 视觉基线，在同一项目和同一制品中增量修改。新增“系统管理”导航域，通过用户中心、角色与权限、身份源配置三个页面形成闭环；身份事件继续关联现有日志中心。生成由 Local Codex 在 Open Design 项目内完成，随后使用真实浏览器逐项验收，不修改生产级前后端代码。

**Tech Stack:** Open Design 0.17.0+、Local Codex、HTML/CSS/JavaScript 交互原型、Ant Design Pro v6.6.0 视觉语言、浏览器交互验证

## Global Constraints

- 仅修改 Open Design 项目 `xminds-release-platform-p0-console-local-codex-final` 中的现有控制台制品。
- 不创建新的平行原型，不切换至 Open Design Cloud 或 secure BYOK。
- 继续使用 Local Codex；一个逻辑生成只允许一次启动请求，后续仅轮询同一运行。
- 原型确认前不得开始生产级前后端编码。
- 所有用户可见文案使用简体中文，技术标准名与既有产品英文名除外。
- 保持 Ant Design Pro v6.6.0 的布局、组件尺度、状态语义与交互反馈。
- 左侧导航、Logo 区、折叠控制区和全部右侧详情抽屉必须统一为浅色体系。
- 保持现有产品、制品、Release、SCM、分发端点和日志中心流程可用。
- SSO 未启用时使用本地登录；SSO 启用后禁止普通本地登录，仅保留受控应急管理员入口。
- OIDC 负责认证，目录同步优先表达 SCIM 2.0；不得将 OIDC 描述为完整组织目录协议。
- 外部同步属性只读，平台角色、产品范围和本地组织由平台管理。
- 不得展示完整密码、令牌、客户端密钥、恢复代码、Cookie 或 Authorization 值。
- 1280px 与 1440px 桌面视口均不得出现横向溢出。
- 当前目录不是 Git 仓库，不执行 Git 提交步骤；计划和规格文档直接保存在 `docs/superpowers`。

---

## 文件与制品结构

| 类型 | 路径或标识 | 职责 |
|---|---|---|
| 设计规格 | `docs/superpowers/specs/2026-08-14-xminds-release-platform-identity-center-prototype-design.md` | 已确认的范围、安全规则与验收标准 |
| 实施计划 | `docs/superpowers/plans/2026-08-14-xminds-release-platform-identity-center-prototype.md` | 本次原型生成与验证清单 |
| Open Design 项目 | `xminds-release-platform-p0-console-local-codex-final` | 现有原型项目，必须原位增量更新 |
| Open Design 制品 | `xminds-release-console.html` | 唯一需要更新的交互原型 |

### Task 1: 建立本次 Local Codex 原型工作流

**Files:**
- Read: `docs/superpowers/specs/2026-08-14-xminds-release-platform-identity-center-prototype-design.md`
- Read: `docs/superpowers/plans/2026-08-14-xminds-release-platform-identity-center-prototype.md`
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 已确认的身份模式、页面信息架构、白色详情抽屉规范和验收标准。
- Produces: 一个绑定现有项目、执行模式为 Local Codex、可持续轮询的 Open Design 运行。

- [ ] **Step 1: 收集并确认本次原型 Brief**

  使用简体中文 locale 建立一次新的 Open Design Brief，内容明确包含：白色详情抽屉、系统管理导航、用户中心、组织架构、角色与权限、身份源配置、本地账户、应急账户及日志关联。复用用户已确认的设计，不扩展生产编码范围。

- [ ] **Step 2: 校验 Local Codex 可用性**

  查询可用执行器，要求 Local Codex 处于可用且已认证状态。若不可用，停止本次生成并报告原因，不自动切换执行模式。

- [ ] **Step 3: 锁定现有项目与制品**

  选择项目 `xminds-release-platform-p0-console-local-codex-final`，确认目标制品为 `xminds-release-console.html`。不得创建新项目或新平行页面。

- [ ] **Step 4: 启动唯一生成运行**

  创建一个新的稳定请求标识，使用 `agent: codex` 启动一次更新。提示词必须要求在当前 Open Design 项目中直接修改现有制品，并包含 Local Codex 子运行边界，禁止子运行再次调用 Open Design 工作流。

- [ ] **Step 5: 轮询到终态**

  仅轮询同一运行；出现 Studio 地址时在应用内浏览器打开一次。运行处于排队或生成中时保持当前任务继续，直到成功、失败、取消或明确需要用户输入。

**Acceptance:** 运行成功返回当前项目的 Studio 或 Preview 地址，且没有切换执行模式、重复启动或创建新项目。

### Task 2: 统一右侧详情抽屉为白色

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 现有产品、制品、Release、SCM、分发端点和日志详情入口。
- Produces: 一套适用于所有现有与新增业务对象的白色详情抽屉视觉模式。

- [ ] **Step 1: 更新抽屉容器视觉**

  将抽屉标题区、内容区和底部操作区设为纯白背景；使用浅灰边框分区，移除深色面板和深色卡片背景。遮罩使用低透明度中性色。

- [ ] **Step 2: 保持统一布局**

  抽屉宽度按内容采用 760 至 840px，标题区展示对象名称、状态、来源与关闭入口；主体使用详情描述、页签、时间线、提示和紧凑表格；底部仅保留上下文操作。

- [ ] **Step 3: 覆盖全部入口**

  依次打开产品、制品、Release、SCM、分发端点、四类日志、用户和同步记录详情，确保没有遗留深色抽屉。

- [ ] **Step 4: 验证对比度和层级**

  检查正文、次要文本、禁用状态、标签、边框和危险操作在白色背景上的可读性，确保抽屉与页面主体可区分但不形成突兀深色块。

**Acceptance:** 所有右侧详情抽屉均为白色，视觉层级一致，关闭、页签和底部操作可用。

### Task 2A: 统一左侧导航为白色

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 现有导航分组、折叠状态、激活状态和权限可见性。
- Produces: 与顶栏、主内容区和白色详情抽屉一致的浅色导航体系。

- [ ] **Step 1: 更新导航容器**

  将侧栏、Logo 区和折叠控制区改为纯白背景；侧栏与主内容区之间增加浅灰右边框，移除深色背景和深色分隔。

- [ ] **Step 2: 更新菜单状态**

  默认菜单文字和图标使用深灰色；分组标题使用中灰色；当前菜单使用浅蓝背景与蓝色文字、图标；悬停菜单使用浅灰蓝背景。

- [ ] **Step 3: 验证折叠状态**

  在展开和折叠状态下分别检查 Logo、图标、激活标识、Tooltip 和折叠按钮，确保没有遗留深色块或低对比度文本。

- [ ] **Step 4: 验证导航行为无回归**

  逐项进入工作台、发布管理、集成与分发、可观测与治理、系统管理，确认菜单顺序、路由和权限可见性不变。

**Acceptance:** 左侧导航、Logo 区和折叠控制区全部为白色，默认、悬停、激活和折叠状态清晰，导航行为无回归。

### Task 3: 新增用户中心与组织架构

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 统一白色抽屉模式、现有产品清单、平台角色与日志中心关联能力。
- Produces: 用户管理、组织架构和本地账户三个可交互页签及用户详情流程。

- [ ] **Step 1: 新增系统管理导航**

  在左侧导航末尾新增“系统管理”分组，包含“用户中心”“角色与权限”“身份源配置”。保持现有导航折叠、激活和分组样式。

- [ ] **Step 2: 构建用户管理页签**

  展示用户总数、已启用、已停用、同步异常和应急账户指标；提供关键词、身份来源、组织、角色、产品范围、同步状态和账号状态筛选；列表至少包含外部同步用户、本地账户、已停用用户和应急管理员样例。

- [ ] **Step 3: 构建用户详情抽屉**

  用户行可点击并打开白色抽屉，页签包含“基本资料”“角色与产品范围”“登录记录”“操作日志”。外部来源字段显示只读，敏感字段始终脱敏。

- [ ] **Step 4: 构建组织架构页签**

  实现左侧组织树与右侧成员列表联动。外部同步组织带来源与只读标识；平台本地组织可展示负责人、成员、下级组织和继承授权摘要。

- [ ] **Step 5: 构建本地账户页签**

  展示普通本地账户与应急管理员，支持演示创建、停用、有效期、MFA 状态和轮换到期。SSO 启用状态下普通本地账户显示“登录已禁止”。

- [ ] **Step 6: 加入安全阻断交互**

  尝试停用最后一个可用应急管理员时阻止操作并展示原因；创建本地账户时展示一次性激活说明，不生成或显示真实密码和恢复代码。

**Acceptance:** 三个页签可切换，组织树与成员联动，用户详情可打开，外部字段只读，最后一个应急管理员无法被停用。

### Task 4: 新增角色与产品范围授权

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 用户、组织、产品、通道和现有平台角色语义。
- Produces: 面向用户或组织的角色绑定与产品范围授权交互。

- [ ] **Step 1: 展示平台角色清单**

  展示管理员、发布者、审批者、审计员和只读成员，列出职责、成员数量、适用范围和风险级别。内置角色不提供删除操作。

- [ ] **Step 2: 提供授权主体选择**

  支持选择单个用户或组织作为授权主体，并清楚标明身份来源、组织来源和当前有效状态。

- [ ] **Step 3: 提供作用域选择**

  支持全平台、指定产品、指定产品与通道三种范围；使用现有产品样例生成可选择项。组织授权展示成员影响数量。

- [ ] **Step 4: 展示变更影响预览**

  保存前显示新增、移除、继承和显式拒绝的权限摘要，并提示审批者不能审批自己创建的 Release。

- [ ] **Step 5: 完成二次确认和日志关联**

  高权限授权要求二次确认。保存成功后显示反馈，并提供“查看操作日志”入口跳转至日志中心相应记录。

**Acceptance:** 可完成一次用户授权和一次组织授权演示，作用域清晰，高权限变更有确认和审计反馈。

### Task 5: 新增身份源配置与同步流程

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: SSO 状态机、应急账户状态、组织与用户列表、日志中心。
- Produces: SSO 测试、启用、同步、冲突和故障的完整演示流程。

- [ ] **Step 1: 构建身份源状态页**

  展示 SSO 未启用、配置中、启用检查、已启用和故障状态；显示非敏感连接摘要、默认登录方式、最近同步和应急账户可用性。

- [ ] **Step 2: 构建启用前检查**

  依次演示连接测试、必填属性映射、同步范围预览和应急管理员检查。任一检查失败时禁用“启用 SSO”。

- [ ] **Step 3: 构建属性映射和同步策略**

  显示用户唯一标识、姓名、邮箱、组织和状态映射；将目录同步标记为 SCIM 2.0 或身份目录适配器，明确 OIDC 只用于登录认证。

- [ ] **Step 4: 构建同步运行交互**

  手动同步后显示阶段进度，完成后展示新增、更新、停用、冲突和失败数量；同步记录可打开白色详情抽屉查看对象差异、错误原因、请求 ID 和重试入口。

- [ ] **Step 5: 构建 SSO 启用与故障状态**

  启用 SSO 前展示影响说明并要求确认。启用后默认登录方式变为 SSO，普通本地账户禁止登录；故障状态显示支持信息和应急入口提示，不提供自动降级按钮。

- [ ] **Step 6: 构建禁用 SSO 流程**

  禁用操作要求重新认证、二次确认并展示本地登录恢复影响；操作结果进入日志中心。

**Acceptance:** 可演示连接测试、启用前检查、启用 SSO、目录同步、冲突详情、故障状态和受控禁用流程。

### Task 6: 扩展日志中心关联与安全呈现

**Files:**
- Modify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: 用户授权、身份源变更、目录同步、本地账户和应急登录事件。
- Produces: 可检索、可关联且经过脱敏的身份治理日志样例。

- [ ] **Step 1: 补充操作日志样例**

  增加角色授权、产品范围变更、启用或禁用 SSO、本地账户创建与停用记录，包含操作者、目标、结果、请求 ID 和变更摘要。

- [ ] **Step 2: 补充登录日志样例**

  增加 SSO 登录、本地登录被禁止、应急登录成功、MFA 失败和账号锁定记录。应急登录使用高风险标识。

- [ ] **Step 3: 补充同步日志样例**

  在现有日志中心保留 Git 同步日志，同时增加身份目录同步记录或通过操作日志关联入口展示，不混淆两种同步类型。

- [ ] **Step 4: 验证敏感信息脱敏**

  检查详情抽屉和导出反馈，不得出现完整密码、Bearer 值、Cookie、客户端密钥、恢复代码或可复用的会话标识。

- [ ] **Step 5: 验证跨页面跳转**

  从用户详情、授权成功反馈和同步详情跳转日志中心时，自动带入用户、请求 ID 或关联 ID 筛选，并可返回原上下文。

**Acceptance:** 身份治理事件可检索和关联，应急事件风险明确，敏感字段全部脱敏，现有四类日志流程不回归。

### Task 7: 完成浏览器验收与回归验证

**Files:**
- Read: `docs/superpowers/specs/2026-08-14-xminds-release-platform-identity-center-prototype-design.md`
- Verify: Open Design artifact `xminds-release-console.html`

**Interfaces:**
- Consumes: Tasks 2–6 的完整原型。
- Produces: 对视觉、交互、安全、响应式和既有流程的验收结论。

- [ ] **Step 1: 验证身份模式**

  演示 SSO 未启用、本地登录；演示 SSO 已启用、普通本地账户禁止登录；确认应急入口独立存在且不自动降级。

- [ ] **Step 2: 验证用户和组织流程**

  筛选不同身份来源用户，打开用户详情，切换四个详情页签；切换组织节点并验证成员列表变化；尝试停用最后一个应急管理员并确认被阻止。

- [ ] **Step 3: 验证授权与同步流程**

  完成一次用户角色授权、一次组织作用域授权、一次 SSO 启用检查和一次目录同步；检查成功、冲突、部分失败和重试状态。

- [ ] **Step 4: 验证白色抽屉覆盖率**

  打开产品、制品、Release、SCM、分发端点、操作日志、登录日志、应用请求日志、Git 同步日志、用户和同步记录详情，确认标题、主体和底部均为白色。

- [ ] **Step 5: 验证既有关键流程无回归**

  重新演示 Release 四步创建与审批，确认创建者不能自审批；检查 Git 同步失败时间线、请求日志脱敏和证据导出反馈仍可用。

- [ ] **Step 6: 验证响应式与控制台错误**

  在 1280px 和 1440px 宽度下检查无横向滚动、抽屉不遮挡关键操作、组织树与表格可用；确认浏览器控制台无错误。

- [ ] **Step 7: 对照验收清单记录结论**

  逐项核对规格第 12 节。发现问题时在同一 Open Design 项目中修正并重新验证，不创建平行制品。

**Acceptance:** 规格第 12 节全部通过，无敏感信息泄露、无关键流程回归、无横向溢出、无浏览器控制台错误。

## 完成标准

- Open Design 当前项目中的 `xminds-release-console.html` 已原位更新；
- Local Codex 运行成功并返回可访问的 Studio 或 Preview 地址；
- 新增用户中心、组织架构、角色与权限、身份源配置和本地账户流程；
- SSO 与本地登录状态符合确认方案；
- 所有右侧详情抽屉为白色；
- 左侧导航、Logo 区和折叠控制区为白色；
- 身份治理事件能够关联日志中心；
- 既有 Release、日志、Git 同步和证据导出流程无回归；
- 用户确认原型后，才允许另行编制生产实现计划并开始编码。
