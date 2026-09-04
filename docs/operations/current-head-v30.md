# Current-head v30 静态模式头

状态：`STATIC VERIFIED / NOT PRODUCTION EXECUTED`。本版本加入管理员需求全流程只读查询；本机合成演练的动态结果另行记录，不构成生产执行或授权。

<!-- BEGIN CURRENT_HEAD_V30_CONTRACT -->

## 精确模式头

IAM48 增加基于当前 Session、权限标记和工作区的管理员读取校验。Demand16、Trust24、Matching11 提供需求、审核、资金、匹配和安全流程的有限事实投影，数据库继续使用固定程序、FORCE RLS 和受限执行权限。平台管理员可以查看平台需求；组织管理员只能查看本组织。接口不能修改业务状态，也不返回举报正文、敏感证据、候选私密画像或凭据。

| 组件 | current / head | 依赖 | manifest / combined SHA-256 |
| --- | ---: | --- | --- |
| PostgreSQL | `18` | — | image digest 由容器合同独立固定 |
| IAM | `48 / 48` | — | `5fea6646f1c2dc755a9a0b51adbe7f9c121e0a3b19d7a87f36dd78adff5af551` / `616cda6eac1e9f853be019f5790584e16826c295be08d10201f947e923a5ba3f` |
| Profile | `5 / 5` | 最低 IAM46 | `005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8` |
| Demand | `16 / 16` | IAM48 | `4802d0ba44c05a059f3dfdbe0911e7be05cfd5d8508c8ced48a0a3f22bc1290f` |
| Trust | `24 / 24` | IAM48 + Demand16 | `9574f3df40b95a3b1a0fdfd778a11edc969c27dc7879efca78aa75515cbdef24` / `119f603be0862e7f35bc533005e7fef82f7bd6384eb2ab7966b04e75a5dfa199` |
| Matching | `11 / 11` | IAM48 + Profile5 + Demand16 + Trust24 | `c7cc2c975f85723a5f4f3c7aa45fe6ebdf6f0fc0df140a06d111aad33eceffbb` |
| Taxonomy | `2 / 2` | — | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

Trust24 对 Demand16 固定的 dependency digest 为 `3362a606f35221c61cfb302ee54ce13bea450a44a02b33217606003a89c569ce`。

数据库 backup/restore pin：

```text
18|48|48|5|5|16|16|24|24|11|11|2|2
```

新增迁移 SQL 摘要：IAM48 `cb93aa215e7a062ad36a8ad0c64d64921d7918aead43c4b34a8552cb36acfeaa`；Demand16 `bb779b254f8cdf985b3e70f36bc04963ff79c563a649382e2651597b65e4f07a`；Trust24 `9a92b456fa7b09313d985139f372cfd42662f7889fe8c083ec48e0a61b906a77`；Matching11 `f3856143930d9271b85536b37b494455f4b962d5b027030aecc2353742215ec2`。

## 历史与连续性

全部历史迁移 SQL 原始字节保持不变。v29 文档、verifier、schema-pins 和版本化 operations 资产由 v30 固定摘要保存。`fixtures/current-head-v30/` 保存此前 IAM47、Demand15、Trust23、Matching10 的完整 manifest，检查新增 manifest 仍保留一致前缀。

`matching_continuity_counts` 覆盖 Matching v1-v11 的 27 张 durable domain tables。本次只增加查询程序、策略和索引，不增加业务表。`deploy/postgres-core-facts-v30.sql` 仅输出模式元数据、密钥标识符和聚合数量。

恢复要求独立验证项目、六组件精确 head/合同、空业务目标、事务 restore 和恢复后事实一致。版本化入口为 `deploy/postgres-operations-v30.compose.yaml`；演练 basename 示例为 `v30-iam48-profile5-demand16-trust24-matching11-taxonomy2-drill01`。

## 校验

```bash
python -B scripts/verify_current_head_v30.py
python -B -m unittest tests.deployment.test_current_head_v30_contract tests.deployment.test_postgres_operations_v30 -v
```

成功输出 `{"status":"CURRENT_HEAD_V30_STATIC_VERIFIED"}` 只代表源码静态闭环。数据库迁移、真实业务、备份恢复和生产部署需分别记录实际执行结果。

<!-- END CURRENT_HEAD_V30_CONTRACT -->

```json
{"current_head_v30":{"claim":"STATIC_ONLY","execution":"NOT_PRODUCTION_EXECUTED"},"production_authorized":false}
```

## 本机动态验收（2026-09-04）

`desire-workflow-20260904-verified` 已从 IAM46/Profile5/Demand15/Trust22/Matching9/Taxonomy2 前向升级到上述精确模式头，官方迁移回执为 `SCHEMA_READY`，API、Matching runtime、Web 健康检查通过。升级前已保存本机数据库备份。首次尝试发现 IAM48 在执行器的迁移断言登记中遗漏，已补齐并增加覆盖实际目录所有描述符的回归；IAM48 的失败事务回滚后通过同一官方入口继续完成，没有改写历史迁移。

平台管理员与组织管理员各读取宠物喂食演练的 29 条历史记录、5 位具名参与者，`limit=2` 的 15 页与一次完整读取完全相同。42 份真实响应通过前端契约，6 次普通需求方/创作者管理读取均为 404。浏览器已核对阶段、退回原因、前后版本及按环节/人员筛选。详情见[管理员使用说明](admin-demand-timeline.md)及仓库的 `tests/pet-feed/REPORT.md`。

这是本机合成沙盒验证；上述静态声明与生产、备份恢复执行边界仍保持原意。
