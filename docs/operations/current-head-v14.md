# Current-head v14 发布资产

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页是当前 IAM38 / Profile3 / Demand10 / Trust8 / Taxonomy2 头部的发布合同入口。它只发布
静态、可复核的运行资产，不代表动态演练已经发生，不批准生产使用、真人参与、真实资金或私网入口。
仓库中的 one-shot state: `NOT_CONSUMED`；发布这些文件没有运行容器、创建目录、生成证据或占用
任何 v14 坐标。

<!-- BEGIN CURRENT_HEAD_V14_CONTRACT -->

## 1. 固定头部与摘要

PostgreSQL 与五域头部固定为：

```text
18|38|38|3|3|10|10|8|8|2|2
```

字段顺序只能是 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head。数据库 operations 的十段 `EXPECTED_CONTRACTS` 按顺序固定为：

```text
908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|38|10|908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a|6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

每一段的语义如下；相同的 IAM combined 摘要在第 1、6 段分别固定 source IAM 与 Trust 的 IAM
依赖，不能省略或合并：

| 段 | 语义 | 固定值 |
| --- | --- | --- |
| 1 | IAM combined contract | `908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e` |
| 2 | Profile manifest | `4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa` |
| 3 | Demand manifest | `7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4` |
| 4 | Trust required IAM schema | `38` |
| 5 | Trust required Demand schema | `10` |
| 6 | Trust required IAM combined contract | `908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e` |
| 7 | Trust required Demand dependency | `27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113` |
| 8 | Trust combined contract | `8907369e35172587753295403dc101227c21671960539c51364f8e00f1e4978a` |
| 9 | Trust manifest | `6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722` |
| 10 | Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

IAM current manifest bytes 另固定为
`19102ab51f5f41c05c3abe07ab7c812d8d829508beec2bd7c3a637b4d1f3a331`；它不是
`EXPECTED_CONTRACTS` 中额外的第十一段。

Trust8 必须直接依赖 IAM38 与 Demand10；不得把 Trust7 的 dependency pin、manifest 或 combined
摘要写成 current。`scripts/verify_current_head_v14.py` 会只读核对当前 manifest bytes、版本序列、
Trust runner 常量、备份脚本和本页，不调用 Docker。

## 2. 唯一 v14 坐标

| 坐标 | 固定值 |
| --- | --- |
| Compose project | `desire-supply-e2e-ten-account-v14` |
| image tag | `e2e-ten-account-v14-iam38-demand10-trust8` |
| input root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v14` |
| bundle name | `internal-sandbox-bundle-iam38-demand10-trust8` |
| deployment ID | `sandbox-e2e-ten-account-v14` |
| release ID | `release-e2e-ten-account-v14-iam38-demand10-trust8` |
| ingress / OIDC / app / data subnet | `172.16.233.0/24` / `172.16.234.0/24` / `172.16.235.0/24` / `172.16.236.0/24` |
| evidence root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v14/e2e-evidence` |
| backup leaf | `/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v14drill01` |
| backup basename | `v14-iam38-profile3-demand10-trust8-taxonomy2-drill01` |
| restore project / subnet | `desire-restore-verify-v14drill01` / `172.16.237.0/24` |

这些值是未来单次获批演练的不可变坐标。当前没有证明 project、image、目录、端口或 CIDR 的 live
absence，也没有授权创建它们。任何一次实际预检或创建开始后，失败的坐标不得清理后复用；新的尝试
必须获得新授权和全新坐标。

## 3. 当前静态门禁

从仓库根只运行只读验证：

```bash
python3 -B scripts/verify_container_stack.py
python3 -B scripts/verify_current_head_v14.py
python3 -B -m unittest \
  tests.deployment.test_current_head_v14_runbook \
  tests.deployment.test_postgres_operations_v14 \
  tests.deployment.test_private_server_release_candidate_evidence_v2 -v
python3 -B scripts/verify_docs.py
git diff --check
```

新 gate 成功只输出 `{"status":"CURRENT_HEAD_V14_STATIC_VERIFIED"}`。旧
`scripts/verify_container_stack.py` 仍是历史与基础 container 合同 validator，不能删除、重写或
用 v14 gate 冒充其历史证明。上述静态命令不消费 `RUN_CURRENT_HEAD_V14_ONCE`。

## 4. 未来 one-shot 运行边界

只有在独立批准 artifact 固定 source snapshot、全部坐标、五个 Docker Hub production refs 三轮
HEAD 门禁、宿主网络 absence 和操作者后，才可进入一次性运行。顺序保持：fresh build → migrate exact
apply → 同一 migrate container exact-skip replay → taxonomy/credential/identity one-shots → ten-account
journey → 两轮只重启 persistent services 的 restart proof → retained backup → isolated restore → restore
migration replay。不得把任一步失败当作可重试的部署脚本。

主部署 helper 使用 base 与本轮 IPAM overlay；它不属于数据库 operations 的三层 helper：

```bash
compose_v14() {
  docker compose \
    --project-name "$DESIRE_E2E_PROJECT" \
    --env-file "$DESIRE_E2E_INPUT_ROOT/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$DESIRE_E2E_INPUT_ROOT/compose.ipam.yaml" \
    "$@"
}
```

实际 one-shot 必须证明 migration 首轮 applied 精确为 IAM `0..38`、Profile `1..3`、Demand
`1..10`、Trust `1..8`、Taxonomy `1..2`，skipped 全空；同容器 replay 与 restore replay 则 applied
全空、skipped 精确为同一版本集合。五个初始化服务不能因 backup 或 restore 被重新创建或再次消费。

## 5. v14 PostgreSQL backup / restore

`deploy/postgres-backup-restore.sh` 与 `deploy/postgres-operations.compose.yaml` 是冻结的 v13/基础资产。
v14 新增完整克隆 `deploy/postgres-backup-restore-v14.sh`，只替换 heads 和 reviewed contract pins；
`deploy/postgres-operations-v14.compose.yaml` 只能把既有同名
`postgres-backup-restore-script` config 的 file source 指向该 v14 脚本。不得复制 service、改变
command/environment/network/volume/secret，或修改旧脚本。

未来 source backup 与 isolated restore 只能通过以下恰好三层 Compose helper：

```bash
compose_v14_operations() {
  docker compose \
    --project-name "$DESIRE_E2E_PROJECT" \
    --env-file "$DESIRE_E2E_INPUT_ROOT/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    -f "$PWD/deploy/postgres-operations-v14.compose.yaml" \
    "$@"
}
```

该 helper 不接受 `--build`、`--pull`、`run --rm`、`down`、`rm` 或 compose IPAM 第四层。source
backup 只能连接已证明未重建的 v14 source project；restore 必须改用 fresh restore project，并由
`DESIRE_DATABASE_RESTORE_SUBNET=172.16.237.0/24` 固定隔离网络。backup basename 只能是
`v14-iam38-profile3-demand10-trust8-taxonomy2-drill01`。任何 backup artifact 已存在、权限不为
0600、facts 前后变化、pins 不符、restore target 非空、manifest 不符或 replay 非 exact skip 都必须
BLOCKED。

下面只是未来批准后使用的命令形状，不是本轮执行记录：

```bash
export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v14"
export DESIRE_E2E_INPUT_ROOT="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v14"
export DESIRE_IMAGE_TAG="e2e-ten-account-v14-iam38-demand10-trust8"
export DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v14drill01"
export DESIRE_DATABASE_BACKUP_BASENAME="v14-iam38-profile3-demand10-trust8-taxonomy2-drill01"
export DESIRE_DATABASE_RESTORE_SUBNET="172.16.237.0/24"
```

不得运行这些 export 后的 Compose lifecycle，除非 one-shot authority 已由独立 artifact 建立且全部
absence proof 在同一 observation 中通过。本页提交时这些变量没有被导出，backup/restore 也没有运行。

## 6. Release-candidate evidence v2

当前 schema 与工具为
`deploy/private-server-release-candidate-evidence-v2.schema.json` 和
`scripts/private_server_release_candidate_evidence_v2.py`。候选 scope 固定为
`RUN_CURRENT_HEAD_V14_ONCE`、`INTERNAL_SANDBOX`、`synthetic_only`、
`production_authorized=false`。字段必须使用 `trust_applicant_discovery_deferral`，不得使用旧字段；
其 implementation status 保持 `DEFERRED_NOT_IMPLEMENTED`，不会伪造 applicant discovery 已完成。

当前状态片段保持：

```json
{"one_shot_v14":{"claim":"NOT_VERIFIED"},"overall_status":"BLOCKED"}
```

v2 仍永久 fail-closed。它可以核对关闭形状与当前冻结 bytes，但 `PASSED`、`VERIFIED`、accepted 和
`UNCONSUMED_VERIFIED` 仍是未验证的 caller claim。工具不读取受保护 receipts，也不证明 Docker、
目录、端口、网络或镜像的 live absence；因此 `EVIDENCE_PROVENANCE_NOT_VERIFIED` 永远存在，
任何下游都不得把 v2 artifact 或成功退出升级为 readiness、批准或生产授权。人工批准必须是独立 artifact。
仓库当前不生成候选实例。

该候选证据不授权本页后续的非 v14 私服激活；私网入口仍须使用独立、未消费的 project/tag/input/
CIDR 和批准记录，不能直接消费本页坐标。

## 7. v13 与 v1 历史边界

旧 v13 runbook 正文、旧 backup/operations、旧 v1 schema 与
`scripts/private_server_release_candidate_evidence.py` 都保持冻结。v1 固定的是当时的 manifest
bytes；当前 manifest 已追加 IAM38 与 Trust8，所以用 current manifest 验证旧 v1 `VERIFIED` 声明
必须得到诚实的 `MISMATCH`，不能改写 v1 expected hash 使它变绿。部署测试使用 byte-exact 的冻结
v13 manifest fixtures 验证旧合同，同时另测 current appended manifest 的 MISMATCH。

<!-- END CURRENT_HEAD_V14_CONTRACT -->

本页成为 current pointer 不会删除或改写任何历史动态证据。只有独立操作者在未来明确批准并完整消费
一次 one-shot 后，才可另行记录动态结果；静态发布本身不能把 `NOT_EXECUTED` 改成 GREEN。
