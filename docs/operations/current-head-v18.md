# Current-head v18 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM39 / Profile3 / Demand11 / Trust12 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V18_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|39|39|3|3|11|11|12|12|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
fdfb00e353ce823f6ef5695e47ec32443c219387413ade908d502925e5248258|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|39|11|fdfb00e353ce823f6ef5695e47ec32443c219387413ade908d502925e5248258|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|3e0af93a1411bc45ca8877f44dbe517f575eb50ce810f11019ea5d583fc4b1aa|5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM 0039 SQL | `b3ce89a429f87ff294ebfd5892f1731ca96b46f3bcaccd17711c9f5a9d8ab737` |
| IAM manifest | `a1b8c6973476ca7f3769a258a1950a17b7e17a9a94f9ea7461979f9b6e37f33f` |
| IAM combined contract | `fdfb00e353ce823f6ef5695e47ec32443c219387413ade908d502925e5248258` |
| Demand manifest / dependency | `870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898` / `cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87` |
| Trust API contract | `a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` |
| Trust 0012 SQL | `064f9feabd497bafcb410b8f926033775d2645e23438c0439e8ecf9981076a3d` |
| Trust manifest / combined | `5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc` / `3e0af93a1411bc45ca8877f44dbe517f575eb50ce810f11019ea5d583fc4b1aa` |
| Trust required IAM / Demand schema | `39 / 11` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v18/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

## 邀请约束的 Demand Owner 首次入驻

IAM39 只为一个封闭场景开放匿名 OIDC `ENROLLMENT`：浏览器必须携带已签发且未过期的
`ORGANIZATION_MEMBERSHIP` 邀请；邀请必须指向确切 Organization、确切 recipient contact/version，
且目标角色必须精确为 `DEMAND_OWNER`，不能是 initial admin。Provider issuer、subject、已验证邮箱绑定、
邀请 ID 与版本任一不一致都必须拒绝。

回调事务只创建 `PENDING_ENROLLMENT` User、ExternalIdentity、已验证 ContactPoint 绑定和 invitation-bound
Session。它不创建 Membership、`user_role_grants` 或 `membership_role_grants`，因此接受邀请之前没有
Organization 权限、角色权限、workspace 权限或 Demand 写权限。只有完成现有政策接受和邀请接受后，
User 才能变为 ACTIVE，并由既有流程创建对应 Membership / Role authority。

匿名 `ORG_ADMIN` 入驻继续关闭；没有确切邀请的普通未知身份登录也继续关闭。已登录既有用户的
ORG_ADMIN invitation step-up 不属于匿名 enrollment，仍走原有受认证流程。

恢复边界同样保持无权限：如果首次提交已经落库但浏览器丢失 HTTP response，或数据库提交后的
commit acknowledgement 丢失，新的确切邀请流程只能恢复同一个仍为 `PENDING_ENROLLMENT` 的 User，
并创建 fresh Session；不得复制 User、ExternalIdentity、Membership 或 Role。恢复必须再次匹配同一
provider subject、recipient contact 和 invitation，任何 ACTIVE/SUSPENDED 身份或绑定漂移都拒绝。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v17.py
python3 -B scripts/verify_current_head_v18.py
python3 -B -m unittest tests.deployment.test_current_head_v18_contract -v
```

v18 校验成功只输出 `{"status":"CURRENT_HEAD_V18_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v17 冻结边界

[Current-head v17 静态模式头](/operations/current-head-v17.md) 继续保持
`18|38|38|3|3|11|11|11|11|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v17/`；v18 的 IAM39、Trust12 或 enrollment 声明不得写回或
冒充 v17 结果。v17 的 `STATIC VERIFIED / NOT EXECUTED` 声明也没有被提升为动态执行或生产授权。

```json
{"current_head_v18":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V18_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
