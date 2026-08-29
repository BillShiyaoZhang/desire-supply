# Current-head v21 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM42 / Profile3 / Demand11 / Trust15 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V21_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|42|42|3|3|11|11|15|15|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|42|11|f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|d88bb1f0e5cc9a50e7a3eac5597202a073414c42d780a7b769267ba80c14b0ca|09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM API / event | `26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c` / `6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934` |
| IAM 0042 SQL | `1d0c1391f08ba47f0af29d9941634a4f522c0d0c48e0c5747edbed16e4b02f44` |
| IAM manifest / combined | `9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d` / `f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e` |
| Demand manifest / dependency | `870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898` / `cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87` |
| Trust API contract | `a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` |
| Trust 0015 SQL | `253bbd89b53d7cc91eeaddc3cd6fa3a770b53f7640cdb445a032a12d016d3dbd` |
| Trust manifest / combined | `09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c` / `d88bb1f0e5cc9a50e7a3eac5597202a073414c42d780a7b769267ba80c14b0ca` |
| Trust required IAM / Demand schema | `42 / 11` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v21/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

## ORG_ADMIN 公开名称更正边界

IAM42 是 forward-only 扩展，只新增 `UpdateOrganizationPublicName` public-name correction 命令，不扩大直接表写权限。
调用者必须是当前组织的 ORG_ADMIN，具有最近 MFA，并同时提交当前强 `If-Match`、一个
`Idempotency-Key` 和固定原因 `PUBLIC_NAME_CORRECTION`。目标组织必须与授权组织完全相同。

`canonical public_name` 长度为 1–160 个 Unicode code point，并通过 Cc / Cf / NFC 三项边界：
必须已经是 NFC、首尾无 Unicode 空白，且不含任何 Cc 控制字符或 Cf 格式字符。应用、HTTP、PostgreSQL、Web intent、
响应 parser 与匿名邀请预览使用同一关闭语义。名称不变被拒绝；过期版本只返回
`412 PRECONDITION_FAILED` 与 `current ETag`，不产生 receipt、audit 或 outbox 写入。

原有五条组织管理命令与本命令组成 six-command idempotency family。同一 actor 的同一原始键只可
标识其中一条命令；active 与 retained key candidate 都参与精确查找。成功写入在一个事务内更新名称和
`aggregate_version`，完成 receipt，并各写一条 audit 与 outbox；receipt replay 返回已提交的同一安全响应。

`OrganizationPublicNameChanged` 是失效通知并保持 audit/event name privacy：event payload 只有 `organization_id`，audit 与 outbox
都不保存旧名或新名。anonymous invitation preview 在读取时取得当前公开名称，因此未接受邀请不会冻结旧名。

内部沙箱 bootstrap v6 在调用旧图证明前保存现有 `custom public_name`，只在受保护的事务本地兼容上下文中
临时代入默认名，并在返回前恢复原名称且不改变版本。REPLAY / VERIFY 不得覆盖合法更正后的名称。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v20.py
python3 -B scripts/verify_current_head_v21.py
python3 -B -m unittest tests.deployment.test_current_head_v21_contract -v
```

v21 校验成功只输出 `{"status":"CURRENT_HEAD_V21_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v20 冻结边界

[Current-head v20 静态模式头](/operations/current-head-v20.md) 继续保持
`18|41|41|3|3|11|11|14|14|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v20/`；v21 的 IAM42、Trust15、公开名称更正或 bootstrap v6
声明不得写回或冒充 v20 结果。v20 的 `STATIC VERIFIED / NOT EXECUTED` 声明也没有被提升为动态执行或生产授权。

```json
{"current_head_v21":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V21_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
