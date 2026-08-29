# Current-head v16 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM38 / Profile3 / Demand11 / Trust10 / Taxonomy2 的数据库模式与应用契约当前头，
不新增或复用运行坐标，不修改 v15 的 image、bundle、release、backup/restore 或 one-shot pin，也不代表
迁移、容器、部署或动态演练已经执行。`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V16_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|38|38|3|3|11|11|10|10|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|38|11|908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e|d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| Demand 0011 SQL | `b9564fb7a9fbf9b7163a388e06431b4df11a3a01751a927c89c20377a07bcb3a` |
| Demand manifest | `870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898` |
| Trust required Demand schema | `11` |
| Trust required Demand contract | `cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87` |
| Trust 0010 SQL | `97f7b3bee6772277e19b1239711bc4ea907b4bb5598a8ffd3e2fc82c21e9c2e2` |
| Trust manifest | `d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683` |
| Trust combined contract | `364f22de931a0d3df11fedcdb20f3eaf84690a6649e99c9683af39b86547b93e` |

## Operations Reviewer 历史闭环

Demand11 新增 `GET /v1/app/review-history`。该读取仅允许当前 `OPERATIONS_REVIEWER`，数据库与服务端
均绑定当前 actor，只返回本人 `COMPLETED` 且结论为 `NEEDS_CHANGES` 或 `VERIFIED` 的记录，并按
`reviewed_at DESC, review_id DESC` 使用签名 cursor 稳定分页。

返回项只允许以下九个字段：

```text
review_id,demand_id,demand_version_id,decision,reason_codes,required_field_codes,budget_health_code,risk_code,reviewed_at
```

该投影不得包含正文、组织、owner、reviewer、duty、authority、原始 hash 或 note。任务发现把这些终态
记录映射为 `DEMAND_REVIEW / COMPLETED / VIEW_DEMAND_REVIEW_HISTORY`，Web 只通过独立历史面板读取和展示
该安全投影。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v16.py
python3 -B -m unittest tests.deployment.test_current_head_v16_contract -v
```

成功只输出 `{"status":"CURRENT_HEAD_V16_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用 Docker，
不运行迁移，不创建 evidence，不消费 v15 one-shot，也不把 `NOT EXECUTED` 升级成动态成功。

## v15 冻结边界

[Current-head v15 发布资产](/operations/current-head-v15.md) 继续保持历史 pin：
`18|38|38|3|3|10|10|9|9|2|2`。其 Demand10、Trust9 manifest 与 Trust runner pin 已复制到
`tests/deployment/fixtures/current-head-v15/`，v15 gate 读取这些 byte-exact fixture；Demand11 / Trust10
不得被冒充为 v15 运行结果。v15 的 runtime release、部署和备份资产没有在本版本中改写。

```json
{"current_head_v16":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V16_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
