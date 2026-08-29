# Current-head v15 发布资产

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页是 IAM38 / Profile3 / Demand10 / Trust9 / Taxonomy2 当前头部的静态发布合同入口。它不代表
动态演练已经发生，不批准生产使用、真人参与、真实资金或私网入口。仓库中的
one-shot state: `NOT_CONSUMED`；发布这些文件没有运行容器、创建目录、生成证据或占用任何 v15 坐标。

<!-- BEGIN CURRENT_HEAD_V15_CONTRACT -->

## 1. 固定头部与摘要

PostgreSQL 与五域头部固定为：

```text
18|38|38|3|3|10|10|9|9|2|2
```

字段顺序只能是 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head。数据库 operations 的十段 `EXPECTED_CONTRACTS` 按顺序固定为：

```text
908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|38|10|908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9|8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 段 | 语义 | 固定值 |
| --- | --- | --- |
| 1 | IAM combined contract | `908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e` |
| 2 | Profile manifest | `4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa` |
| 3 | Demand manifest | `7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4` |
| 4 | Trust required IAM schema | `38` |
| 5 | Trust required Demand schema | `10` |
| 6 | Trust required IAM combined contract | `908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e` |
| 7 | Trust required Demand dependency | `27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113` |
| 8 | Trust combined contract | `43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9` |
| 9 | Trust manifest | `8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171` |
| 10 | Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

IAM current manifest bytes 另固定为
`19102ab51f5f41c05c3abe07ab7c812d8d829508beec2bd7c3a637b4d1f3a331`；它不是
`EXPECTED_CONTRACTS` 的第十一段。Trust9 的 API contract 与 0009 SQL bytes 分别固定为
`a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` 与
`6cbab8db4ccbb5c9fe2a5b5af161327289da80a3de4c159407de9f1cb13093db`。

Trust9 直接依赖 IAM38 与 Demand10；不得把 Trust8 的 manifest 或 combined 摘要写成 current。
Trust9 同时新增独立 purpose `TRUST_REPORT_CURSOR`，carrier file 固定为
`key-trust-report-cursor-v1`，active key ID 固定为 `trust-report-cursor-2026-01`；因此未来 v15
bundle 的关闭 inventory 是 11 个数据库 credential + 25 个 key carrier = 36 个 secret，不能沿用
v14 的 35-secret 结果。
`scripts/verify_current_head_v15.py` 只读核对 current manifest bytes、版本序列、Trust runner 常量、
备份脚本、本页和冻结 v14 fixture，不调用 Docker。

## 2. 唯一 v15 坐标

| 坐标 | 固定值 |
| --- | --- |
| Compose project | `desire-supply-e2e-ten-account-v15` |
| image tag | `e2e-ten-account-v15-iam38-demand10-trust9` |
| input root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v15` |
| bundle name | `internal-sandbox-bundle-iam38-demand10-trust9` |
| deployment ID | `sandbox-e2e-ten-account-v15` |
| release ID | `release-e2e-ten-account-v15-iam38-demand10-trust9` |
| ingress / OIDC / app / data subnet | `172.29.27.0/24` / `172.29.28.0/24` / `172.29.29.0/24` / `172.29.30.0/24` |
| evidence root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v15/e2e-evidence` |
| backup leaf | `/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v15drill01` |
| backup basename | `v15-iam38-profile3-demand10-trust9-taxonomy2-drill01` |
| restore project / subnet | `desire-restore-verify-v15drill01` / `172.29.31.0/24` |

这些只是未来单次获批演练的候选不可变坐标。当前没有证明 project、image、目录、端口或 CIDR 的
live absence，也没有授权创建它们。任何实际预检或创建开始后，失败坐标不得清理后复用；新尝试必须
获得新授权和全新坐标。

## 3. 当前静态门禁

从仓库根只运行只读验证：

```bash
python3 -B scripts/verify_container_stack.py
python3 -B scripts/verify_current_head_v14.py
python3 -B scripts/verify_current_head_v15.py
python3 -B -m unittest \
  tests.deployment.test_current_head_v14_runbook \
  tests.deployment.test_postgres_operations_v14 \
  tests.deployment.test_current_head_v15_runbook \
  tests.deployment.test_postgres_operations_v15 -v
python3 -B scripts/verify_docs.py
git diff --check
```

v15 gate 成功只输出 `{"status":"CURRENT_HEAD_V15_STATIC_VERIFIED"}`。v14 gate、基础 container
validator 和它们的历史语义继续保留；静态命令不消费 `RUN_CURRENT_HEAD_V15_ONCE`。

## 4. 未来 one-shot 运行边界

只有独立批准 artifact 固定 source snapshot、全部坐标、生产镜像 refs、宿主网络 absence 和操作者后，
才可进入一次性运行。顺序保持 fresh build → migrate exact apply → 同一 migrate container exact-skip
replay → taxonomy/credential/identity one-shots → ten-account journey → 两轮只重启 persistent services
的 restart proof → retained backup → isolated restore → restore migration replay。不得把失败当作可重试部署。

未来首轮 applied 必须精确为 IAM `0..38`、Profile `1..3`、Demand `1..10`、Trust `1..9`、
Taxonomy `1..2`，skipped 全空；同容器 replay 与 restore replay 的 applied 全空、skipped 精确为同一
版本集合。初始化服务不能因 backup 或 restore 被重新创建或再次消费。

## 5. v15 PostgreSQL backup / restore

`deploy/postgres-backup-restore-v14.sh` 与 `deploy/postgres-operations-v14.compose.yaml` 是冻结的历史
资产。v15 的 `deploy/postgres-backup-restore-v15.sh` 只能是 v14 脚本的完整克隆，并且只替换 heads
与 reviewed contract pins；`deploy/postgres-operations-v15.compose.yaml` 只能重绑同名 config 的
file source，不能复制 service 或改变 command、environment、network、volume、secret。

未来 backup 与 isolated restore 只能使用恰好三层 helper：

```bash
compose_v15_operations() {
  docker compose \
    --project-name "$DESIRE_E2E_PROJECT" \
    --env-file "$DESIRE_E2E_INPUT_ROOT/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    -f "$PWD/deploy/postgres-operations-v15.compose.yaml" \
    "$@"
}
```

该 helper 不接受 `--build`、`--pull`、`run --rm`、`down`、`rm` 或 IPAM 第四层。source backup
只能连接未重建的 v15 source project；restore 必须使用 fresh restore project 与固定隔离网络。
backup basename 只能是 `v15-iam38-profile3-demand10-trust9-taxonomy2-drill01`。任何 artifact 已存在、
权限不为 0600、facts 前后变化、pins 不符、restore target 非空、manifest 不符或 replay 非 exact skip
都必须 BLOCKED。

下面只是未来授权后的命令形状，不是执行记录：

```bash
export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v15"
export DESIRE_E2E_INPUT_ROOT="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v15"
export DESIRE_IMAGE_TAG="e2e-ten-account-v15-iam38-demand10-trust9"
export DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v15drill01"
export DESIRE_DATABASE_BACKUP_BASENAME="v15-iam38-profile3-demand10-trust9-taxonomy2-drill01"
export DESIRE_DATABASE_RESTORE_SUBNET="172.29.31.0/24"
```

本页提交时没有导出这些变量，没有运行 backup/restore，也没有创建或消费坐标。

## 6. 证据与授权边界

仓库没有 v15 动态 evidence 生成器，也没有 v15 候选实例。当前静态声明保持：

```json
{"one_shot_v15":{"claim":"NOT_VERIFIED"},"overall_status":"BLOCKED","production_authorized":false}
```

`RUN_CURRENT_HEAD_V15_ONCE` 只是未来 authority 的 scope 名，不是本页授予的 authority。
`production_authorized=false`；任何静态 gate 成功都不能升级 readiness、批准或生产授权。

## 7. v14 历史边界

[current-head-v14.md](/operations/current-head-v14.md)、`scripts/verify_current_head_v14.py`、v14 backup
脚本与 overlay 全部继续保留。Trust9 append 后，v14 verifier 必须读取 byte-exact 的
`tests/deployment/fixtures/current-head-v14/trust-manifest.json` 和冻结 Trust8 SQL，而不能把 current
Trust9 manifest 或 runner 冒充 Trust8。v14 与 v15 gates 都只读，且都不会消费 one-shot。

<!-- END CURRENT_HEAD_V15_CONTRACT -->

本页成为 current pointer 不会删除或改写历史动态证据。只有独立操作者在未来明确批准并完整消费一次
one-shot 后，才可另行记录动态结果；静态发布本身不能把 `NOT_EXECUTED` 改成 GREEN。
