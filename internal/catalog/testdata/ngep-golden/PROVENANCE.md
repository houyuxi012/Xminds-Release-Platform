# NGEP 可信目录黄金向量来源说明

## 来源

- 来源仓库：`houyuxi012/Enterprise-Portal`
- 来源提交：`1e6386db508856f34e0e82cb4a7d4f9d1a3b2d18`
- 消费端协议实现：`Next-Gen Enterprise Portal/backend/modules/platform_update/domain/catalog_schemas.py`
- 消费端测试向量生成逻辑：`Next-Gen Enterprise Portal/backend/tests/test_update_catalog_service.py`
- 对应测试：`test_metadata_threshold_and_role_digest_mismatch_are_rejected`、`test_metadata_expiry_and_revocation_are_rejected`、`test_metadata_wire_contract_rejects_duplicate_keys_and_signature_aliases`

本目录仅冻结协议 JSON，不复制 Python 实现。五角色有效链由消费端 `_build_chain` 在固定时间 `2026-08-14T12:00:00Z` 生成；异常向量分别冻结摘要不匹配、过期、重复 JSON 键、无效签名和目标撤销场景。所有文件保留末尾换行，下面的 SHA-256 对应仓库内实际字节。

## 文件校验值

| 文件 | SHA-256 |
|---|---|
| `valid-root.json` | `0a694aedb9d29801e9c85423b1aeb64c072005f6a9b330d83de3f0e851e836a1` |
| `valid-targets.json` | `9a27e9aed3eb2a0f4906f8590443cfcdc60ff91f7043061280b769ed0012f3e2` |
| `valid-snapshot.json` | `ec32c85e28693794a73d32bd9d5d1b7ea605299c99c5e48054f4dae4db15e061` |
| `valid-timestamp.json` | `98c6903c554a0c4da0bea3c94bb4104826385341b7ebac705fa33a7441be9544` |
| `valid-revocation.json` | `7a3df0d48040850dfbb357e9848f86d6ec7bc480797b5eeef13c7e7615b53120` |
| `digest-mismatch-snapshot.json` | `8e85fe0b4c6fbe5a6a86842f48232ab9de1e7d2ae8658f80a9cbff9a39ca8778` |
| `expired-root.json` | `e9c669e76a44eedaa3fa94d1d4b6dc645d9ff4e85564159cd5c31fc7248ce13c` |
| `duplicate-key-root.json` | `2ea309446e91828735f8b21bac58850e294addb2246f2f245fbf58618f25d1b9` |
| `invalid-signature-targets.json` | `7f67cd825366450883654103f51c5448042e67205f5cfc59cfe760f8ebe3e87e` |
| `revoked-target-revocation.json` | `7d1a03b450f7f888233d03fedaa75af2da3c253694bc9fa875705a06d3cd8e02` |
