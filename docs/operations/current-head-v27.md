# Current-head v27 静态模式头

> 状态：`STATIC VERIFIED / NOT PRODUCTION EXECUTED`
>
> v27 只声明当前源码、迁移、容器入口与恢复校验的静态一致性。它没有声称 fresh-volume、
> 存量生产升级、backup/restore 动态演练、真实 OIDC/供应商联调、桌面/移动视觉 QA 或生产授权已经完成。

<!-- BEGIN CURRENT_HEAD_V27_CONTRACT -->

## 精确模式头

当前版本只接受以下精确组合：

| 组件 | current / head | 依赖 | manifest / combined SHA-256 |
| --- | ---: | --- | --- |
| PostgreSQL | `18` | — | image digest 由容器合同独立固定 |
| IAM | `46 / 46` | — | `faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5` / `14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d` |
| Profile | `5 / 5` | IAM46 | `005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8` |
| Demand | `15 / 15` | IAM45 migration dependency | `32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73` |
| Trust | `22 / 22` | IAM46 + Demand15 | `3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8` / `68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6` |
| Matching | `3 / 3` | IAM46 | `b6c4169edcaf4c7cb771fde614ef72c3d90d56b4d2f4d5a0a633f8b634adbf18` |
| Taxonomy | `2 / 2` | — | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

Trust22 对 Demand15 固定的 dependency digest 是
`ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf`；对 IAM46 固定的 dependency
contract 是 IAM combined digest `14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d`。

数据库 backup/restore pin 为：

```text
18|46|46|5|5|15|15|22|22|3|3|2|2
```

v27 fixture `tests/deployment/fixtures/current-head-v27/schema-pins.json` 固定上述版本、依赖、
head SQL 与合同摘要。IAM46、Profile5、Demand15、Trust22、Matching3 都是前向迁移；v26 的
IAM43/Profile3/Demand13/Trust19/Taxonomy2 文档、verifier、fixtures 与 operation 资产继续按原字节
作为冻结历史，不得被重写或重标为 v27 动态证据。

## 本版本实际闭合的运行边界

v27 把 Matching 从“有迁移但未进入当前运维头”推进为正式的独立 schema component：

- `matching.schema_compatibility` 同 IAM、Profile、Demand、Trust、Taxonomy 一起进入 schema head 查询；
- `matching_meta.schema_contracts` 的 IAM 依赖、API、event、rule、input manifest、run input、candidate、
  disclosure 与 migration manifest 全部进入 backup/restore contract pin；
- IAM46 提供 Creator authority 与 Profile eligibility resolver；Profile5 提供不可变的派生匹配输入捕获；
- Demand15 通过固定 workload allowlist 交付匹配请求，并由受限 coordinator 完成或无选择关闭；
- Trust22 对 IAM46/Demand15 做 migration-honest dependency repin；
- Matching3 提供耐崩溃 worker/coordinator、确定性结果、候选选择/复核分配和显式零候选关闭。

这些闭合不授权任意 SQL 表写入。生产角色仍通过固定函数、独立凭据、租约/栅栏、幂等 receipt 与
权限 marker 工作；API 进程不持有 Matching worker/coordinator 写权限，Matching runtime 也不持有
Demand schema owner 权限。

## 隐私安全的连续性事实

`deploy/postgres-core-facts-v27.sql` 只输出 aggregate count、schema metadata 与密钥标识符，不输出：

- Creator、reviewer、selector 或 candidate 标识；
- 邀请披露内容、金额、评分、排序解释或输入/结果 canonical bytes；
- receipt 的 safe response、payload hash 或 authorization marker；
- Profile/Demand/Trust 的正文或受限文本。

`matching_continuity_counts` 对 Matching v1-v3 的 27 张 durable domain tables 各保留一个总数：rule bundle/
selector、attempt/run/input/result/candidate/job、invitation/disclosure/response/withdrawal、selection 及三类 intent/
completion record、selector/reviewer assignment、authority/hold evidence、source inbox 与 command receipts。
backup 前后以及 isolated restore 后以完整单行 JSON byte comparison 验证连续性。

Profile4/5 新增的五张 capture/derived snapshot 表和 Demand15 新增的 runtime policy、delivery/claim、
completion/zero-close receipt 表也进入 continuity facts。`demand.matching_runtime_policy` 是迁移写入的 singleton，
因此它参加事实比较但不参加“空业务目标”求和。

## 空目标与恢复安全

restore 必须满足全部条件：

1. Compose project 名匹配 `desire-restore-verify-[a-z0-9]{8,32}`；
2. 数据库名只能是 `desire_restore_verify`；
3. PostgreSQL client/server major 都是 18；
4. 六个 schema component 的 current/head 与合同完全等于 v27 pin；
5. IAM/Profile/Demand/Trust/Matching/Taxonomy、audit/outbox/inbox 的业务 durable rows 总和为零；
6. Matching 的全部 27 张 durable domain tables 各自进入 empty-target gate；
7. dump 与 facts 文件都是 regular `0600` 文件，manifest 仅含两条 SHA-256；
8. restore 后重新校验 schema contracts 并逐字比较 facts。

restore target 中由迁移建立的 schema metadata、contract singleton、key policy 或 Demand Matching runtime policy
不属于业务数据，不能为了让总数“看起来为零”而删除。

## 静态验证

从仓库根目录运行：

```bash
python -B scripts/verify_current_head_v27.py
python -B -m unittest tests.deployment.test_current_head_v27_contract -v
python -B -m unittest tests.deployment.test_postgres_operations_v27 -v
```

成功时 verifier 只输出：

```json
{"status":"CURRENT_HEAD_V27_STATIC_VERIFIED"}
```

verifier 只读已签入文件，不启动 Docker、不连接数据库、不生成或修改 secret，也不把静态通过升级为
production authorization。

## 绑定 v27 的 backup / restore 操作

先完成私有服务器 secret、镜像、迁移与健康检查；为本次演练创建权限 `0700` 的专用目录。然后显式叠加
基础 operations compose 和 v27 config overlay：

```bash
compose_v27_operations() {
  docker compose \
    --env-file "$PWD/secrets/private-server/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/deploy/private-server-real-oidc.compose.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    -f "$PWD/deploy/postgres-operations-v27.compose.yaml" \
    "$@"
}

export DESIRE_DATABASE_BACKUP_DIR="$PWD/backups/internal-sandbox"
export DESIRE_DATABASE_BACKUP_BASENAME="v27-iam46-profile5-demand15-trust22-matching3-taxonomy2-drill01"

compose_v27_operations --profile database-backup run --rm database-backup

COMPOSE_PROJECT_NAME=desire-restore-verify-20260829 \
  compose_v27_operations --profile database-restore-verify up \
  --abort-on-container-exit --exit-code-from database-restore-replay
```

不要把 `database-restore-target` 指向正常 `desire` 数据库或正常 Compose project。演练结束后的 isolated volume
清理仍是显式 host-side 操作；清理前先保存命令、时间、镜像 digest、artifact SHA-256 与退出状态。

## 尚未完成的发布门禁

- v27 fresh-volume 与真实存量升级动态执行；
- v27 逻辑 backup / isolated restore 实际演练、PITR、加密离机备份与恢复告警；
- 真实 OIDC、邮件/通知等 provider 联调；
- 不同角色的完整桌面/移动浏览器视觉与可用性 QA；
- 生产变更窗口、回滚决定、运营签字与上线授权。

历史 v25 synthetic runtime evidence 和 v26 静态证据不能填补上述门禁。

<!-- END CURRENT_HEAD_V27_CONTRACT -->

```json
{"current_head_v27":{"claim":"STATIC_ONLY","execution":"NOT_PRODUCTION_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```
