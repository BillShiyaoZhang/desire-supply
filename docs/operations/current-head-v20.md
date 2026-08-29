# Current-head v20 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM41 / Profile3 / Demand11 / Trust14 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V20_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|41|41|3|3|11|11|14|14|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
b46a3a5592eb68af01b3a87cb86fb4970f9678ec54f8beffb3e9c6c926a032dd|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898|41|11|b46a3a5592eb68af01b3a87cb86fb4970f9678ec54f8beffb3e9c6c926a032dd|cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87|f56404d56f8af5dc08ea7cd5e92d2c6f7719c56a3dae3bde89f140b604691980|7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM 0041 SQL | `74a2fc9ce455ad737df2086f04af3f0de5b659e3902fb71d6c0007c0e185a415` |
| IAM manifest | `dc54ab65fffba8e55cc4dbd82c7c0effe044820a5387952d23893275f5ad74ac` |
| IAM combined contract | `b46a3a5592eb68af01b3a87cb86fb4970f9678ec54f8beffb3e9c6c926a032dd` |
| Demand manifest / dependency | `870f2b9d9862f75f4e7eaf01cc9f1d5f788b72fbf4f7ccf9056dfeff35969898` / `cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87` |
| Trust API contract | `a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25` |
| Trust 0014 SQL | `d65a1823192164fa174875d8e76051549fb4f8ff22fdc97ab742c8d00eb3f4e2` |
| Trust manifest / combined | `7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca` / `f56404d56f8af5dc08ea7cd5e92d2c6f7719c56a3dae3bde89f140b604691980` |
| Trust required IAM / Demand schema | `41 / 11` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v20/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

## 接受第二权限后的完整本人快照

IAM41 是 forward-only 扩展。ACTIVE invitee 通过 `AcceptAccessInvitation` 接受 second authority 时，
事务必须在 COMMIT 前通过固定、无参数且按 actor / command receipt / exact invitation 绑定的读取程序
取得 full canonical MeDto。
返回体必须同时包含该用户原有的 User role、所有 ACTIVE Membership 及其 role、全部适用政策要求，
以及本次新满足的权限和政策要求；不能只拼装本次邀请刚创建的最小 authority。

新增权限同时是 User 授权缓存的失效边界。ACTIVE User 的 `aggregate_version` 必须在同一事务精确
增加一次，返回 MeDto 的 `entity_tag` 与新版本一致，后续 `/v1/me` 的 authorization ETag 因而不能
继续命中接受前的旧权限快照。receipt replay 返回已提交的同一完整响应，不在重放时重建另一份快照。

IAM40 的 `PENDING_ENROLLMENT` 路径保持：provider-only 身份在接受 exact invitation 前仍是
zero authority；接受时激活 User、创建精确 Membership / Role authority 并执行 Session rotation。
该路径已有的 User 版本增加不能因 IAM41 再增加第二次。普通登录、错误 invitation、错误 actor、错误 receipt、
非当前政策 bundle 或越界 RLS 都继续 fail closed。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v19.py
python3 -B scripts/verify_current_head_v20.py
python3 -B -m unittest tests.deployment.test_current_head_v20_contract -v
```

v20 校验成功只输出 `{"status":"CURRENT_HEAD_V20_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v19 冻结边界

[Current-head v19 静态模式头](/operations/current-head-v19.md) 继续保持
`18|40|40|3|3|11|11|13|13|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v19/`；v20 的 IAM41、Trust14、full canonical MeDto 或
authorization ETag 声明不得写回或冒充 v19 结果。v19 的 `STATIC VERIFIED / NOT EXECUTED` 声明也
没有被提升为动态执行或生产授权。

```json
{"current_head_v20":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V20_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
