# 泄露口令摘要语料工具链实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付只处理已审批摘要制品的离线构建与验证 CLI，并让 IAM 生产运行时以同一领域模块验证内容寻址语料发布目录。

**Architecture:** `internal/breachcorpus` 是格式、构建请求、稳定归并、技术清单和发布目录验证的唯一事实源；`scripts/breach-corpus` 只负责 CLI 适配，`internal/iam` 只负责把已验证集合适配为 `BreachChecker`。产物以目录整体原子发布，技术清单与审批证据通过清单 SHA-256 外部关联。

**Tech Stack:** Go 1.26、标准库 `flag`/`bufio`/`container/heap`/`crypto/sha256`/`encoding/json`、`golang.org/x/sys/unix`、现有 Makefile 与 Go 测试体系。

**Spec:** `docs/security/breached-password-corpus-toolchain-design.md`

## Global Constraints

- CLI 永不接受明文口令，只接受 40 位 SHA-1 或 64 位 SHA-256 十六进制摘要。
- 构建请求和技术清单的 `schema_version` 固定为 `1`，格式固定为 `xminds-breach-corpus/v1`。
- 单行上限为 4096 字节；单次最多 32 个输入；输入总量上限为 512 MiB；输出上限为 128 MiB。
- 输出摘要统一大写、按字典序严格递增、跨输入去重且不保留注释。
- 发布目录名固定为 `breach-corpus-sha256-<64位小写摘要>`，内部文件固定为 `corpus.txt` 和 `manifest.json`。
- 生产、预发和测试只接受 `XMINDS_RELEASE_IAM_BREACH_CORPUS_RELEASE_DIR`；旧单文件变量不保留兼容路径。
- development 内置语料只能由显式 development 环境单独启用。
- 文件系统错误、格式错误、清单错误、权限错误和摘要错误全部失败关闭。
- 不向日志、标准输出、标准错误、清单或审计证据写入口令、摘要行、下载凭据或源文件内容。
- 不新增外部依赖，不在 `docs/superpowers` 下新增或提交文件。

---

### Task 1: 固化设计、治理和部署文档

**Files:**
- Create: `docs/security/breached-password-corpus-toolchain-design.md`
- Create: `docs/deployment/breached-password-corpus-deployment.md`
- Modify: `docs/security/breached-password-corpus-governance.md`
- Modify: `README.md`
- Modify: `.env.example`

**Interfaces:**
- Consumes: 已确认的摘要输入、内容寻址目录、技术清单和部署验收设计。
- Produces: 后续代码和生产实施共同遵循的安全契约与操作步骤。

- [x] **Step 1: 编写工具链设计文档**

文档明确输入/输出边界、模块职责、命令、清单、原子发布、运行时校验、测试、风险和验收标准。

- [x] **Step 2: 编写独立部署实施文档**

文档明确真实 Linux UID/GID、只读挂载、制品传输、灰度、多副本一致性、监控、回滚和应急处理。

- [x] **Step 3: 更新治理、README 与配置文档**

将单文件语料契约收敛为：

```text
XMINDS_RELEASE_IAM_BREACH_CORPUS_RELEASE_DIR=/opt/xminds/breach-corpora/breach-corpus-sha256-<digest>
```

并链接设计、治理和部署文档。

- [x] **Step 4: 检查文档没有写入 `docs/superpowers`**

Run:

```bash
git status --short
git diff -- docs README.md .env.example
```

Expected: 本任务只出现 `docs/security`、`docs/deployment`、`docs/plans`、`README.md` 和 `.env.example` 的预期文档变更。

### Task 2: 定义共享领域类型和严格构建请求

**Files:**
- Create: `internal/breachcorpus/types.go`
- Create: `internal/breachcorpus/request.go`
- Create: `internal/breachcorpus/request_test.go`

**Interfaces:**
- Consumes: `io.Reader` 形式的严格 JSON 构建请求。
- Produces: `ReadBuildRequest(io.Reader) (BuildRequest, error)`、`ValidateInputs(BuildRequest, []Input) error`、`BuildRequest`、`SourceRequest`、`Input`、`Generator`、`Manifest`、`Result` 和稳定错误 `ErrInvalidRequest`。

- [x] **Step 1: 写严格请求解码失败测试**

```go
func TestReadBuildRequestRejectsUnknownFieldsDuplicateSourcesAndTrailingJSON(t *testing.T) {
    cases := []string{
        `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[],"unknown":true}`,
        `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[{"id":"a","version":"1","expected_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","license_review_ref":"LEGAL-1"},{"id":"a","version":"2","expected_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","license_review_ref":"LEGAL-2"}]}`,
        `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[]} {}`,
    }
    for _, raw := range cases {
        if _, err := ReadBuildRequest(strings.NewReader(raw)); !errors.Is(err, ErrInvalidRequest) {
            t.Fatalf("ReadBuildRequest() error = %v", err)
        }
    }
}
```

- [x] **Step 2: 运行测试确认 RED**

Run:

```bash
go test ./internal/breachcorpus -run TestReadBuildRequestRejects -count=1
```

Expected: FAIL，因为 `ReadBuildRequest` 和领域类型尚不存在。

- [x] **Step 3: 实现最小严格请求模型**

类型签名固定为：

```go
const (
    ManifestSchemaVersion = 1
    Format                 = "xminds-breach-corpus/v1"
    MaximumLineBytes       = 4096
    MaximumInputCount      = 32
    MaximumTotalInputBytes = int64(512 << 20)
    MaximumCorpusBytes     = int64(128 << 20)
)

type SourceRequest struct {
    ID               string `json:"id"`
    Version          string `json:"version"`
    ExpectedSHA256   string `json:"expected_sha256"`
    LicenseReviewRef string `json:"license_review_ref"`
}

type BuildRequest struct {
    SchemaVersion int             `json:"schema_version"`
    CorpusVersion string          `json:"corpus_version"`
    Sources       []SourceRequest `json:"sources"`
}

type Input struct {
    SourceID string
    Path     string
}

func ReadBuildRequest(reader io.Reader) (BuildRequest, error)
func ValidateInputs(request BuildRequest, inputs []Input) error
```

解码器使用 `DisallowUnknownFields`，并在首个对象后要求 EOF；所有标识、版本、许可证引用和摘要采用有界格式验证。

- [x] **Step 4: 运行请求测试确认 GREEN**

Run:

```bash
go test ./internal/breachcorpus -run 'TestReadBuildRequest|TestValidateInputs' -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交领域契约**

```bash
git add internal/breachcorpus/types.go internal/breachcorpus/request.go internal/breachcorpus/request_test.go
git commit -m "Define breach corpus build contracts"
```

### Task 3: 实现摘要解析和规范化集合

**Files:**
- Create: `internal/breachcorpus/parser.go`
- Create: `internal/breachcorpus/parser_test.go`

**Interfaces:**
- Consumes: `io.Reader` 摘要流。
- Produces: `Parse(io.Reader) (*Set, Counts, error)`、`NormalizeLine(string) (string, Algorithm, bool, error)`、`Set.ContainsPassword(string) bool` 和 `ErrInvalidCorpus`。

- [x] **Step 1: 写格式、边界和口令命中失败测试**

```go
func TestParseNormalizesSupportedDigestsAndMatchesPasswords(t *testing.T) {
    raw := "# comment\n844eba1a7a7bebadaad266bf2db5b9429d441818\n6CE0335CCB0E6AD50693A435D4BF0659DB2D69D53D84631661774AC86E8F5722\n"
    set, counts, err := Parse(strings.NewReader(raw))
    if err != nil {
        t.Fatal(err)
    }
    if counts.SHA1Entries != 1 || counts.SHA256Entries != 1 || !set.ContainsPassword("Known-SHA1-Breached-Password!") || !set.ContainsPassword("Known-SHA256-Breached-Password!") {
        t.Fatalf("unexpected counts or membership: %+v", counts)
    }
}
```

另建独立测试分别拒绝空语料、非十六进制、错误长度和超过 4096 字节的行。

- [x] **Step 2: 运行解析测试确认 RED**

Run:

```bash
go test ./internal/breachcorpus -run 'TestParse|TestNormalizeLine' -count=1
```

Expected: FAIL，因为解析 API 尚不存在。

- [x] **Step 3: 实现最小解析器**

```go
type Algorithm string

const (
    SHA1   Algorithm = "sha1"
    SHA256 Algorithm = "sha256"
)

type Counts struct {
    SHA1Entries      uint64 `json:"sha1_entries"`
    SHA256Entries    uint64 `json:"sha256_entries"`
    UniqueEntries    uint64 `json:"unique_entries"`
    DuplicateEntries uint64 `json:"duplicate_entries"`
    RejectedEntries  uint64 `json:"rejected_entries"`
}

type Set struct {
    sha1   map[string]struct{}
    sha256 map[string]struct{}
}

func Parse(reader io.Reader) (*Set, Counts, error)
func NormalizeLine(line string) (digest string, algorithm Algorithm, ignored bool, err error)
func (set *Set) ContainsPassword(password string) bool
```

`Parse` 使用 4096 字节扫描上限，空行和注释忽略，其他行必须完整解码为 20 或 32 字节。

- [x] **Step 4: 运行解析测试确认 GREEN**

Run:

```bash
go test ./internal/breachcorpus -run 'TestParse|TestNormalizeLine' -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交解析器**

```bash
git add internal/breachcorpus/parser.go internal/breachcorpus/parser_test.go
git commit -m "Add shared breach corpus parser"
```

### Task 4: 实现确定性有界构建和内容寻址发布

**Files:**
- Create: `internal/breachcorpus/builder.go`
- Create: `internal/breachcorpus/merge.go`
- Create: `internal/breachcorpus/builder_test.go`

**Interfaces:**
- Consumes: `BuildRequest`、`[]Input`、绝对输出根、`Generator` 和 UTC 时钟。
- Produces: `Build(context.Context, BuildRequest, []Input, string, Generator, func() time.Time) (Result, error)`，发布目录内包含 `corpus.txt` 与 `manifest.json`。

- [x] **Step 1: 写稳定输出和跨输入去重失败测试**

```go
func TestBuildIsStableAcrossInputOrderAndDeduplicates(t *testing.T) {
    first := buildFixture(t, []sourceFixture{{id: "b", lines: []string{sha256Digest, strings.ToLower(sha1Digest)}}, {id: "a", lines: []string{sha1Digest}}})
    second := buildFixture(t, []sourceFixture{{id: "a", lines: []string{sha1Digest}}, {id: "b", lines: []string{strings.ToLower(sha1Digest), sha256Digest}}})
    if first.CorpusSHA256 != second.CorpusSHA256 || first.Counts.UniqueEntries != 2 || first.Counts.DuplicateEntries != 1 {
        t.Fatalf("unstable build: first=%+v second=%+v", first, second)
    }
}
```

另建独立测试验证输入摘要不一致、非普通文件、符号链接、总量超限、输出超限、目标已存在和失败后无正式发布目录。

- [x] **Step 2: 运行构建测试确认 RED**

Run:

```bash
go test ./internal/breachcorpus -run TestBuild -count=1
```

Expected: FAIL，因为 `Build` 尚不存在。

- [x] **Step 3: 实现有界 run 与多路归并**

固定接口：

```go
type Generator struct {
    Name    string `json:"name"`
    Version string `json:"version"`
    Commit  string `json:"commit"`
}

type Result struct {
    ReleaseDirectory string
    CorpusSHA256     string
    ManifestSHA256   string
    Counts           Counts
    CorpusBytes      int64
}

func Build(
    ctx context.Context,
    request BuildRequest,
    inputs []Input,
    outputRoot string,
    generator Generator,
    clock func() time.Time,
) (Result, error)
```

实现要求：在输出根内创建 `0700` 隐藏临时目录；临时 run 文件为 `0600`；每个 run 在固定内存预算内排序去重；用 `container/heap` 执行稳定多路归并；写入时流式计算输出摘要和容量；正常失败清理临时目录。

- [x] **Step 4: 实现清单与原子目录发布**

清单使用无 map 的结构体并按来源 ID 排序：

```go
type Manifest struct {
    SchemaVersion int              `json:"schema_version"`
    Format        string           `json:"format"`
    CorpusVersion string           `json:"corpus_version"`
    GeneratedAt   string           `json:"generated_at"`
    Generator     Generator        `json:"generator"`
    Sources       []SourceEvidence `json:"sources"`
    Corpus        CorpusEvidence   `json:"corpus"`
}
```

同步两个文件和临时目录，设置只读权限，将临时目录重命名为 `breach-corpus-sha256-<digest>`，同步输出根并拒绝覆盖。

- [x] **Step 5: 运行构建测试确认 GREEN**

Run:

```bash
go test ./internal/breachcorpus -run TestBuild -race -count=1
```

Expected: PASS，且测试临时目录中不存在未清理的正式半成品。

- [ ] **Step 6: 提交构建器**

```bash
git add internal/breachcorpus/builder.go internal/breachcorpus/merge.go internal/breachcorpus/builder_test.go
git commit -m "Build deterministic breach corpus releases"
```

### Task 5: 实现发布目录和部署边界验证

**Files:**
- Create: `internal/breachcorpus/verifier.go`
- Create: `internal/breachcorpus/verifier_unix.go`
- Create: `internal/breachcorpus/verifier_test.go`

**Interfaces:**
- Consumes: 绝对发布目录和 `VerifyOptions`。
- Produces: `VerifyRelease(string, VerifyOptions) (*Release, error)`、`VerificationMode`、`OwnershipExpectation` 和稳定错误 `ErrInvalidRelease`。

- [x] **Step 1: 写篡改、权限和目录身份失败测试**

```go
func TestVerifyReleaseRejectsTamperedManifestWritableFilesAndMismatchedDirectory(t *testing.T) {
    release := validReleaseFixture(t)
    manifest := filepath.Join(release, ManifestFileName)
    raw, err := os.ReadFile(manifest)
    if err != nil {
        t.Fatal(err)
    }
    if err := os.Chmod(manifest, 0o600); err != nil {
        t.Fatal(err)
    }
    if err := os.WriteFile(manifest, append(raw, '\n'), 0o600); err != nil {
        t.Fatal(err)
    }
    if _, err := VerifyRelease(release, VerifyOptions{Mode: ArtifactMode}); !errors.Is(err, ErrInvalidRelease) {
        t.Fatalf("VerifyRelease() error = %v", err)
    }
}
```

拆分测试覆盖：语料/清单符号链接、可写文件、父目录组/其他可写、目录摘要不一致、未知清单字段、错误计数、非规范化排序和部署 UID/GID 不一致。

- [x] **Step 2: 运行验证测试确认 RED**

Run:

```bash
go test ./internal/breachcorpus -run TestVerifyRelease -count=1
```

Expected: FAIL，因为验证 API 尚不存在。

- [x] **Step 3: 实现安全打开和严格验证**

```go
type VerificationMode string

const (
    ArtifactMode   VerificationMode = "artifact"
    DeploymentMode VerificationMode = "deployment"
)

type OwnershipExpectation struct {
    OwnerUID uint32
    GroupGID uint32
}

type VerifyOptions struct {
    Mode                VerificationMode
    ExpectedOwnership   *OwnershipExpectation
    EffectiveServiceUID uint32
}

type Release struct {
    Manifest Manifest
    Set      *Set
    Result   Result
}

func VerifyRelease(releaseDirectory string, options VerifyOptions) (*Release, error)
```

`VerifyRelease` 对目录、`corpus.txt` 和 `manifest.json` 分别执行非跟随打开及身份复核；artifact 模式验证格式、摘要、计数、只读权限和不可写父目录；deployment 模式额外要求精确 UID/GID。运行时传入真实有效服务 UID，并拒绝服务 UID 拥有发布目录或文件。

- [x] **Step 4: 运行验证测试确认 GREEN**

Run:

```bash
go test ./internal/breachcorpus -run TestVerifyRelease -race -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交验证器**

```bash
git add internal/breachcorpus/verifier.go internal/breachcorpus/verifier_unix.go internal/breachcorpus/verifier_test.go
git commit -m "Verify breach corpus release boundaries"
```

### Task 6: 实现 `breach-corpus` CLI

**Files:**
- Create: `scripts/breach-corpus/main.go`
- Create: `scripts/breach-corpus/main_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `build`、`verify` 子命令和 `internal/breachcorpus` 公共 API。
- Produces: `run([]string, io.Writer, io.Writer, func() time.Time) int`、稳定退出码和 `bin/breach-corpus`。

- [x] **Step 1: 写参数、退出码和非敏感输出失败测试**

```go
func TestRunRejectsPlaintextShapedInputAndDoesNotEchoContent(t *testing.T) {
    var stdout, stderr bytes.Buffer
    code := run([]string{"build", "--input", "password=Secret123!"}, &stdout, &stderr, time.Now)
    if code != 2 {
        t.Fatalf("run() code = %d", code)
    }
    if strings.Contains(stdout.String()+stderr.String(), "Secret123!") {
        t.Fatal("CLI echoed untrusted input content")
    }
}
```

分别测试：缺少子命令返回 `2`；格式/摘要/权限失败返回 `1`；成功只输出规范化 JSON 摘要；deployment 模式缺少 UID/GID 返回 `2`。

- [x] **Step 2: 运行 CLI 测试确认 RED**

Run:

```bash
go test ./scripts/breach-corpus -count=1
```

Expected: FAIL，因为 CLI 尚不存在。

- [x] **Step 3: 实现最小 CLI 适配**

```go
func main() {
    os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(arguments []string, stdout, stderr io.Writer, clock func() time.Time) int
```

`build` 使用可重复 `--input source-id=/absolute/path`；`verify` 支持 `--mode artifact|deployment`；标准输出编码 `Result`，标准错误只输出稳定中文错误类别。

- [x] **Step 4: 将工具纳入构建和格式检查**

修改：

```make
GO_FILES := $(shell find apps internal scripts tests -type f -name '*.go' 2>/dev/null)
```

并在 `build` 中增加：

```make
GOCACHE="$(GOCACHE)" $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/breach-corpus ./scripts/breach-corpus
```

- [x] **Step 5: 运行 CLI 与构建验证确认 GREEN**

Run:

```bash
go test ./scripts/breach-corpus -race -count=1
make fmt-check
make build
```

Expected: PASS，并生成 `bin/breach-corpus`。

- [ ] **Step 6: 提交 CLI**

```bash
git add scripts/breach-corpus Makefile
git commit -m "Add breach corpus governance CLI"
```

### Task 7: 让 IAM 运行时加载完整发布目录

**Files:**
- Modify: `internal/iam/password_security.go`
- Modify: `internal/iam/password_security_test.go`
- Modify: `internal/iam/runtime_config.go`
- Modify: `internal/iam/runtime_config_test.go`
- Modify: `apps/release-api/main.go`
- Modify: `apps/release-api/main_test.go`

**Interfaces:**
- Consumes: `breachcorpus.VerifyRelease` 和环境变量 `XMINDS_RELEASE_IAM_BREACH_CORPUS_RELEASE_DIR`。
- Produces: `NewReleaseBreachChecker(string) (*FileBreachChecker, error)` 和 `LocalAuthRuntimeConfig.BreachCorpusReleaseDirectory`。

- [ ] **Step 1: 写配置收敛失败测试**

```go
func TestLoadLocalAuthRuntimeConfigRequiresReleaseDirectoryAndRejectsLegacyCorpusPath(t *testing.T) {
    env := validLocalAuthEnvironment(t)
    env["XMINDS_RELEASE_IAM_BREACH_CORPUS"] = filepath.Join(t.TempDir(), "breaches.txt")
    if _, err := LoadLocalAuthRuntimeConfig(env, "production"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
        t.Fatalf("legacy corpus path error = %v", err)
    }
}
```

再测试绝对内容寻址发布目录成功、development 内置语料与发布目录不能同时配置、非 development 不能启用内置语料。

- [ ] **Step 2: 写运行时清单失败测试**

测试 `NewReleaseBreachChecker` 对有效发布目录命中 SHA-1/SHA-256，并拒绝清单缺失、清单篡改、服务 UID 拥有产物及可写父目录。

- [ ] **Step 3: 运行 IAM 测试确认 RED**

Run:

```bash
go test ./internal/iam ./apps/release-api -run 'Breach|Corpus|LocalAuthRuntimeConfig' -count=1
```

Expected: FAIL，因为新配置字段和发布目录构造器尚不存在。

- [ ] **Step 4: 重构 IAM 适配器**

`FileBreachChecker` 仅保存 `*breachcorpus.Set`；`NewReleaseBreachChecker` 调用共享验证器并传入真实 `os.Geteuid()`。删除 IAM 内重复的解析、文件限制和摘要编码逻辑；`NewDevelopmentBreachChecker` 使用共享 `Parse` 读取嵌入语料。

- [ ] **Step 5: 收敛运行配置和应用启动**

将配置字段固定为：

```go
type LocalAuthRuntimeConfig struct {
    BreachCorpusReleaseDirectory string
    UseDevelopmentBreachCorpus   bool
}
```

生产路径只读取 `XMINDS_RELEASE_IAM_BREACH_CORPUS_RELEASE_DIR`，显式拒绝旧变量非空；`apps/release-api/main.go` 调用 `iam.NewReleaseBreachChecker`。

- [ ] **Step 6: 运行 IAM 测试确认 GREEN**

Run:

```bash
go test ./internal/iam ./apps/release-api -race -count=1
```

Expected: PASS。

- [ ] **Step 7: 提交运行时集成**

```bash
git add internal/iam/password_security.go internal/iam/password_security_test.go internal/iam/runtime_config.go internal/iam/runtime_config_test.go apps/release-api/main.go apps/release-api/main_test.go
git commit -m "Require verified breach corpus releases"
```

### Task 8: 完成治理文档、总体验证和生产门禁记录

**Files:**
- Modify: `docs/security/breached-password-corpus-governance.md`
- Modify: `docs/security/breached-password-corpus-toolchain-design.md`
- Modify: `docs/deployment/breached-password-corpus-deployment.md`
- Modify: `README.md`
- Modify: `.env.example`
- Modify: `docs/plans/2026-08-30-breached-password-corpus-toolchain.md`

**Interfaces:**
- Consumes: 最终 CLI、运行时配置、测试命令和真实验证结果。
- Produces: 与实现一致的客户可交付文档和明确未完成的生产环境门禁。

- [ ] **Step 1: 更新所有用户可见文档**

README 给出：

```bash
make build
bin/breach-corpus build --request ... --input source-id=/absolute/input.txt --output-root /absolute/output
bin/breach-corpus verify --release-dir /absolute/output/breach-corpus-sha256-<digest>
```

`.env.example` 只保留 `XMINDS_RELEASE_IAM_BREACH_CORPUS_RELEASE_DIR`。

- [ ] **Step 2: 执行聚焦测试**

Run:

```bash
go test ./internal/breachcorpus ./internal/iam ./scripts/breach-corpus ./apps/release-api -race -count=1
```

Expected: PASS。

- [ ] **Step 3: 执行仓库完整验证**

Run:

```bash
make verify
```

Expected: Go 格式、vet、竞态测试、二进制构建、边界、macOS 元数据、Console lint/typecheck/test/build 全部通过。

- [ ] **Step 4: 检查敏感内容和计划占位符**

Run:

```bash
rg -n 'plaintext_password|Secret123!|BEGIN (RSA|OPENSSH|PRIVATE) KEY|TODO|TBD' internal/breachcorpus scripts/breach-corpus docs/security docs/deployment docs/plans README.md .env.example
```

Expected: 不存在凭据、私钥、永久待办或未完成占位符；测试中的固定非生产字符串如被命中，必须确认不会进入运行时输出。

- [ ] **Step 5: 检查最终差异和用户排除目录**

Run:

```bash
git status --short
git diff --check
git diff --stat
git diff -- docs/superpowers
```

Expected: `git diff --check` 无输出，`docs/superpowers` 无变更，差异仅包含本工具链范围。

- [ ] **Step 6: 记录真实环境验收边界**

本地测试通过后仍将以下项目保留为生产部署门禁，不宣称已经完成：

- 真实 Linux `root`/部署账户/服务 UID/GID 校验；
- 容器或 Kubernetes 只读挂载；
- 单副本灰度与控制测试；
- 多副本版本和 SHA-256 一致性；
- 回滚演练及审计系统证据。

- [ ] **Step 7: 提交文档和最终验证记录**

```bash
git add README.md .env.example docs/security docs/deployment docs/plans/2026-08-30-breached-password-corpus-toolchain.md
git commit -m "Document breach corpus operations"
```
