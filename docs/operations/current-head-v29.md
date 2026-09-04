# Current-head v29 静态模式头

状态：`STATIC VERIFIED / NOT PRODUCTION EXECUTED`。本次修复 CI 暴露的 Profile 候选鉴权查询性能问题，并同步精确数据库依赖；不声明生产迁移或恢复已经执行。

<!-- BEGIN CURRENT_HEAD_V29_CONTRACT -->

## 精确模式头

IAM47 将 Profile 派生匹配的十处候选 UUID 文本比较改为带严格规范格式校验的 UUID 比较，使现有 UUID 索引可用于候选过滤。无效或非规范字符串仍不能获得候选权限。会话、操作、用途、授权状态和 selector 绑定条件保持不变，逐人鉴权、500 人上限及失败原子性继续生效。

Trust23 与 Matching10 仅同步 IAM47 和下游精确依赖元数据；Profile5、Demand15、Taxonomy2 及既有 API/event/domain 契约保持不变。

| 组件 | current / head | 依赖 | manifest / combined SHA-256 |
| --- | ---: | --- | --- |
| PostgreSQL | `18` | — | image digest 由容器合同独立固定 |
| IAM | `47 / 47` | — | `257c438e1d44b385b47505e04f0eca001b41e5121a7f996f3f7e0d8b81d913da` / `abc9924571cecb3027ec29ee7fdf34596bf8682d8b41c62d033964ec3094400f` |
| Profile | `5 / 5` | 最低 IAM46 | `005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8` |
| Demand | `15 / 15` | IAM45 migration dependency | `32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73` |
| Trust | `23 / 23` | IAM47 + Demand15 | `0576a8872e2c9783e345d521f151b3d6f9bd7e1d9ee125ee1ef3810e01a05e47` / `96ff2fd0b3e32143b4570fff008948d13fbe5f537a746712878bd2cca77255fa` |
| Matching | `10 / 10` | IAM47 + Profile5 + Trust23 | `83547a319fb2d1e5cc88131570fc889ac795b0dd30643e9bca565058226f2cb6` |
| Taxonomy | `2 / 2` | — | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

Trust23 对 Demand15 固定的 dependency digest 为
`ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf`。

数据库 backup/restore pin：

```text
18|47|47|5|5|15|15|23|23|10|10|2|2
```

新增迁移 SQL 摘要：IAM47 `f850fbb7dab65b3e4ba95d2e60b77f626924f303b02141fcb8c6eee4e9417d29`；Trust23 `3ceeeea5a90812f29c56f293f4388f55694f1469a80c40763a6e28b16102c9b5`；Matching10 `54f807a3d210095a79164ad8dc2724686c61decde510e47fc3f7d6f606d45ec6`。

## 历史与连续性

所有已有迁移 SQL 原始字节保持不变。v28 的文档、verifier、schema-pins fixture 和版本化 operations 资产由 v29 固定摘要保存。`fixtures/current-head-v29/` 保存 IAM46、Trust22、Matching9 manifest，验证新的 manifest 具有完全一致的历史前缀。

`matching_continuity_counts` 覆盖 Matching v1-v10 的 27 张 durable domain tables；本次不增加业务表。`deploy/postgres-core-facts-v29.sql` 继续只输出模式元数据、密钥标识符和聚合数量。

恢复仍要求独立验证项目、六组件精确 head/合同、空业务目标、事务 restore 和恢复后事实一致。版本化入口为 `deploy/postgres-operations-v29.compose.yaml`，演练 basename 示例为 `v29-iam47-profile5-demand15-trust23-matching10-taxonomy2-drill01`。

## 校验

```bash
python -B scripts/verify_current_head_v29.py
python -B -m unittest tests.deployment.test_current_head_v29_contract tests.deployment.test_postgres_operations_v29 -v
```

成功输出 `{"status":"CURRENT_HEAD_V29_STATIC_VERIFIED"}` 只代表源码静态闭环。数据库迁移、真实业务、备份恢复和生产部署须分别记录实际执行结果。

<!-- END CURRENT_HEAD_V29_CONTRACT -->

```json
{"current_head_v29":{"claim":"STATIC_ONLY","execution":"NOT_PRODUCTION_EXECUTED"},"production_authorized":false}
```
