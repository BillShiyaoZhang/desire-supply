# Current-head v19 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM40 / Profile3 / Demand11 / Trust13 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V19_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|40|40|3|3|11|11|13|13|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
981c425483ce3c89e6e376c8bc1fd8269a36499c8fd89890e8feeac5d94a1ae8|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|40|11|981c425483ce3c89e6e376c8bc1fd8269a36499c8fd89890e8feeac5d94a1ae8|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|d843e20a45397931a572688cd86ccef9fe43b92a2577d3c8559d519fb0de2480|c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM 0040 SQL | `5bf84831502fb295279666a2df5e660f977995bf8c0e8a86f3a321808909cad7` |
| IAM manifest | `e9e571dcb16928c21ab26b9dca5cacc299f9cc5427dd18383af87867ccca5c40` |
| IAM combined contract | `981c425483ce3c89e6e376c8bc1fd8269a36499c8fd89890e8feeac5d94a1ae8` |
| Demand manifest / dependency | `870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898` / `cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87` |
| Trust API contract | `a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` |
| Trust 0013 SQL | `d5d714824f8b20d1bbbcaed2bd0ee7e8f38ef42c5aa749189c7fa6bf407bf00e` |
| Trust manifest / combined | `c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8` / `d843e20a45397931a572688cd86ccef9fe43b92a2577d3c8559d519fb0de2480` |
| Trust required IAM / Demand schema | `40 / 11` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v19/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

## 邀请入驻的正式接受闭环

IAM40 是 forward-only 扩展：它不新建或改写业务表，只升级 `AcceptAccessInvitation` 的两个既有
resolver 和必要的窄 RLS。此前 IAM39 建立的 `PENDING_ENROLLMENT` User 只有在当前 Session、
AuthTransaction、verified contact 与 exact invitation 全部保持同一条 `ENROLLMENT` 证据链时，
才可进入既有邀请接受事务。目标仍必须精确为 `DEMAND_OWNER`，initial admin 继续关闭。

pending 分支只开放完成该确切邀请所需的政策确认和接受路径；它不授予通用 workspace、管理或 Demand
authority。Membership / Role authority、User 激活与后续 Session rotation 仍必须由既有原子接受流程
产生。任何另一邀请、另一联系人、普通 LOGIN、过期事务、错 provider subject 或非确切 Session 都继续
zero authority，并以关闭结果结束。

receipt replay 也必须重新认证同一 actor、Session family 和 invitation-bound ENROLLMENT 事务，不能先
读取 command receipt 再绕过身份复核。ACTIVE User 的既有 STEP_UP 接受路径保持不变；IAM40 不能把普通
登录提升成邀请证据，也不能把一次邀请的证明复用于另一邀请。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v18.py
python3 -B scripts/verify_current_head_v19.py
python3 -B -m unittest tests.deployment.test_current_head_v19_contract -v
```

v19 校验成功只输出 `{"status":"CURRENT_HEAD_V19_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v18 冻结边界

[Current-head v18 静态模式头](/operations/current-head-v18.md) 继续保持
`18|39|39|3|3|11|11|12|12|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v18/`；v19 的 IAM40、Trust13 或接受闭环声明不得写回或
冒充 v18 结果。v18 的 `STATIC VERIFIED / NOT EXECUTED` 声明也没有被提升为动态执行或生产授权。

```json
{"current_head_v19":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V19_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
