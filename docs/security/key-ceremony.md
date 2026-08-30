# 可信目录密钥仪式与运行控制规范

## 1. 背景与目标

Xminds Release Platform 使用 Ed25519 对 root、targets、snapshot、timestamp、revocation 五角色元数据进行签名。本规范用于建立初始信任根、隔离离线 root 私钥、登记在线角色公钥、交接加密密钥材料，并定义轮换、吊销、恢复和审计要求。

目标如下：

- root 私钥始终离线保存，不进入 API、Worker、数据库、对象存储、镜像、源码和普通日志；
- 在线 Provider 只允许加载 targets、snapshot、timestamp、revocation 密钥；
- 所有私钥文件采用 AES-256-GCM 信封加密，主密钥文件权限固定为 `0600`；
- 每次仪式由至少两名不同职责人员共同执行、复核并形成不可变审计记录；
- root envelope、bootstrap anchor 和每个角色公钥均可独立校验。

## 2. 角色与职责

| 角色 | 主要职责 | 禁止事项 |
|---|---|---|
| 密钥保管人 A | 保管 root 加密私钥介质的一部分和恢复材料 | 单人完成签发或导出主密钥 |
| 密钥保管人 B | 独立复核命令、摘要、版本和到期时间 | 与保管人 A 共用账户或凭据 |
| 平台安全管理员 | 提供在线角色公钥、阈值和轮换计划 | 接触 root 明文私钥 |
| 发布平台管理员 | 部署在线加密密钥和 root envelope | 修改或绕过 root 信任锚 |
| 审计人员 | 核对参与人、输入摘要、输出摘要和交接记录 | 修改仪式证据 |

## 3. 安全前提

1. 在断网、全盘加密、受控启动介质的专用工作站执行 root 仪式。
2. 使用硬件随机源生成 32 字节主密钥；不得使用口令、UUID、时间戳或源码常量替代。
3. 工作目录必须位于加密介质，禁止云盘同步、自动备份、剪贴板同步和终端录屏。
4. 操作前关闭 shell history，操作后执行介质卸载和内存清理流程。
5. `internal/catalog/testdata/ngep-golden` 中的私钥关联材料只用于消费兼容测试，严禁用于任何环境的真实签发。

> 生产阻断项：现有 NGEP 消费端测试锚点的确定性私钥材料存在于消费端测试代码中，因此该锚点不具备生产信任强度。上线前必须通过受控配置/信任存储向客户端预置本仪式生成的新 bootstrap anchor；不能把黄金向量 root 当作初始生产 root，也不能仅依赖已暴露旧私钥签发的在线轮换。

## 4. 在线角色公钥输入

root envelope 只包含在线角色公钥，不接触在线角色私钥。输入文件必须包含且仅包含四个在线角色，每个角色配置公钥列表和阈值：

```json
{
  "targets": {
    "keys": [{"key_id": "targets-production-2026", "public_key": "BASE64URL_ED25519_PUBLIC_KEY"}],
    "threshold": 1
  },
  "snapshot": {
    "keys": [{"key_id": "snapshot-production-2026", "public_key": "BASE64URL_ED25519_PUBLIC_KEY"}],
    "threshold": 1
  },
  "timestamp": {
    "keys": [{"key_id": "timestamp-production-2026", "public_key": "BASE64URL_ED25519_PUBLIC_KEY"}],
    "threshold": 1
  },
  "revocation": {
    "keys": [{"key_id": "revocation-production-2026", "public_key": "BASE64URL_ED25519_PUBLIC_KEY"}],
    "threshold": 1
  }
}
```

`public_key` 必须是 32 字节 Ed25519 公钥的无填充 Base64URL。相同 `key_id` 不得跨角色复用。生产环境在线私钥优先由 KMS/HSM 生成和托管；使用本地加密 Provider 时，应在另一场受控在线密钥仪式中调用 `signing.WriteEncryptedKeyFile` 生成独立文件，且不得把 root 私钥复制到在线目录。

## 5. 初始 root 生成步骤

### 5.1 生成主密钥

```bash
umask 077
openssl rand 32 > root-master.key
chmod 0600 root-master.key
```

分别计算并由两名保管人记录输入文件摘要：

```bash
shasum -a 256 root-master.key online-keys.json
```

主密钥摘要只能用于同一仪式内双人核对，不得提交到代码仓库或普通工单。

### 5.2 生成加密私钥、root envelope 和 bootstrap anchor

```bash
go run ./scripts/root-key \
  --master-key-file ./root-master.key \
  --online-keys-file ./online-keys.json \
  --private-key-file ./root-private.json \
  --root-envelope-file ./root.json \
  --key-id root-production-2026 \
  --version 1 \
  --expires 2027-08-14T00:00:00Z \
  > bootstrap-anchor.json
```

工具采用独占创建，不覆盖已有输出。输出权限如下：

| 文件 | 内容 | 权限/分发范围 |
|---|---|---|
| `root-master.key` | 32 字节主密钥 | `0600`，双人分离保管，绝不进入在线环境 |
| `root-private.json` | AES-256-GCM 加密 root 私钥 | `0600`，仅离线签发工作站和恢复介质 |
| `root.json` | 已签 root envelope | `0644`，可部署到可信目录 |
| `bootstrap-anchor.json` | key ID、公钥、公钥摘要、root 版本、envelope 摘要 | 可通过独立可信通道预置到客户端 |

stdout 只输出 bootstrap 公钥材料，工具不会把私钥字节写到 stdout 或 stderr。

### 5.3 双人复核

1. 核对 `root.json` 的 `_type=root`、版本、UTC 到期时间和五角色阈值。
2. 核对 `bootstrap-anchor.json` 的 `root_envelope_digest` 与以下结果一致：

   ```bash
   shasum -a 256 root.json
   ```

   `root.json` 文件包含末尾换行，而 bootstrap 摘要对应 canonical envelope 字节、不含末尾换行。正式交接清单应同时记录两种摘要并明确语义。

3. 在隔离验证机使用 bootstrap 公钥验证 root envelope 的 Ed25519 签名。
4. 确认 `root-private.json` 权限为 `0600`，内容只有版本、key ID、公钥、nonce 和 ciphertext 等加密信封字段。
5. 确认在线部署包不包含 `root-master.key`、`root-private.json` 或任何 root 解密材料。

## 6. 在线部署控制

- Worker 只挂载在线角色加密文件和独立在线主密钥文件；运行账户只读，文件权限为 `0600`。
- 在线密钥引用不得使用 `root`、`root-*` 或 `root_*`；本地 Provider 会在代码层拒绝加载。
- root envelope 作为公开不可变元数据部署，私钥不随 envelope 部署。
- targets、snapshot、timestamp、revocation 分别使用不同 key ID 和独立私钥。
- 任何签名调用都必须记录角色、key ID、Release、请求 ID、结果和时间，但不得记录 payload 原文、私钥、主密钥或密文。

## 7. 轮换与吊销

### 7.1 在线角色轮换

1. 生成新在线私钥和公钥，旧私钥保持只读。
2. 在离线工作站生成包含新旧公钥的下一版本 root envelope。
3. 按旧阈值和新阈值分别签署 root transition，客户端验证并接受后再切换在线 key ref。
4. 发布新 targets/snapshot/timestamp/revocation，确认所有 Endpoint 一致后冻结旧在线私钥。
5. 对泄露或失效 key ID 签发 revocation，并保留所有历史目录版本。

### 7.2 root 轮换

root 轮换必须同时满足旧 root 阈值和新 root 阈值，并在 `root_transition` 中绑定上一 root 版本、envelope 摘要、旧/新 key ID 集合与签名集合。若旧 root 已疑似泄露，不得依赖旧 root 单独建立新信任，必须通过带外可信通道重新预置 bootstrap anchor。

### 7.3 紧急吊销

- 立即停止受影响 Provider 和发布 Worker；
- 冻结相关对象、审计和密钥使用证据；
- 使用未受影响的 revocation 角色签发新 revocation 和 timestamp；
- 若 root 或 revocation 私钥泄露，启动带外信任重建，不进行普通在线轮换；
- 吊销不回退任何元数据版本。

## 8. 备份与恢复

- root 主密钥和加密私钥至少保存两份离线介质，分别置于不同物理安全域；
- 恢复演练至少每半年执行一次，只验证解密、签名和摘要，不生成可发布版本；
- 备份恢复必须验证 key ID、公钥摘要和 root envelope 摘要，任何不一致均失败关闭；
- 介质报废采用符合组织密码介质销毁规范的物理销毁或密码擦除，并生成审计证据。

## 9. 验收清单

- [ ] 两名不同职责人员完成并签署操作记录；
- [ ] root 主密钥与加密私钥均为 `0600`，且未进入在线环境；
- [ ] root envelope 包含 root、targets、snapshot、timestamp、revocation 五角色；
- [ ] 所有 key ID 唯一，Ed25519 公钥长度和 Base64URL 编码有效；
- [ ] bootstrap anchor 已通过独立可信通道预置；
- [ ] 在线 Provider 无法加载 root key ref；
- [ ] 签名、轮换、吊销和恢复操作均可审计且不泄露敏感材料；
- [ ] 黄金测试锚点未用于任何真实环境。
