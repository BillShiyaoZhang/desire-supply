# Current-head v17 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM38 / Profile3 / Demand11 / Trust11 / Taxonomy2 的数据库模式与应用契约当前头。
它不新增或复用运行坐标，不代表迁移、容器、部署或动态演练已经执行，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V17_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|38|38|3|3|11|11|11|11|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|38|11|908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|583e4a03efec12b06c75710d0a6ccd7b79be18cb93f4faf58c207d228065c48d|6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| Trust API contract | `a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` |
| Trust 0011 SQL | `6add361aeeca276b6b0a2d3ba4b7f27dd92e57335b076d0b985b5b8a936393ac` |
| Trust manifest | `6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7` |
| Trust combined contract | `583e4a03efec12b06c75710d0a6ccd7b79be18cb93f4faf58c207d228065c48d` |
| Trust required IAM / Demand schema | `38 / 11` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v17/`。该目录不是运行结果，只允许静态校验
Demand11 / Trust11 manifest 与 Trust runner pin。

## Trust Officer 完成历史闭环

Trust11 新增内部投影 `trust_api.list_my_completed_case_assignments_v1`。它只允许当前仍有效的
`TRUST_OFFICER` 会话，并通过 IAM 的 `READ_ASSIGNED_CASE` 权限重新解析当前 actor。数据库 RLS 同时要求：

- 历史分配的 officer 是当前 actor；
- 分配用途为 `CASE_TRIAGE`，且不是 hold 分配；
- 案件已决定，outcome 的 decision assignment 与历史分配相同；
- outcome 的决定人也是当前 actor。

投影项只允许三个 party-safe 字段：

```text
case_id,decided_at,outcome_code
```

它不返回 reporter、owner、organization、demand、report、assignment、evidence、reason/action、note、
authority 或受限正文。任务发现把这些记录映射为
`TRUST_CASE / COMPLETED / VIEW_TRUST_CASE_HISTORY`；Web 的“我的任务与历史”只展示该安全任务摘要，
不会把投影扩展成公开 Trust HTTP 查询面。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v17.py
python3 -B -m unittest tests.deployment.test_current_head_v17_contract -v
```

成功只输出 `{"status":"CURRENT_HEAD_V17_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用 Docker，
不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v16 冻结边界

[Current-head v16 静态模式头](/operations/current-head-v16.md) 继续保持 Trust10 历史 pin：
`18|38|38|3|3|11|11|10|10|2|2`。其 Demand11、Trust10 manifest 与 Trust runner pin 已冻结到
`tests/deployment/fixtures/current-head-v16/`；v16 verifier 读取这些 byte-exact fixture，Trust11 不得被
冒充为 v16 结果。v16 的静态声明没有被提升为动态执行或生产授权。

```json
{"current_head_v17":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V17_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
