# MVP 数据字典与可见性

完整可运行对象见 `samples/*.json`。所有日期用 `YYYY-MM-DD`，金额为对应 `currency` 的常规货币单位，强度/熟练度/证据可信度均为 0～4。新增字段先写入项目复盘，批次结束后再进入下一规则版本。

## 共同规则

- `id` 使用无含义随机 ID；不得编码姓名、组织名、手机号或邮箱。
- `consent_version` 记录参与说明版本，不存签名图片或身份。
- `evidence_ref`、`funding_evidence_ref` 只指向受控外部存储，不含可识别 URL。
- 标签必须来自 `config/taxonomy-v1.yaml`；暂时无法表达时记录 `BAD_TAXONOMY`，不临时造标签改变当次结果。

## 创作者对象

| 路径 | 类型 | 可见性 | 含义 |
| --- | --- | --- | --- |
| `id/status/consent_version` | string | 运营/匹配 | 随机标识、active/paused/withdrawn、同意版本 |
| `interests.problem_types/domains/tasks` | string[] | 可经本人确认后分享 | 主动偏好 |
| `interests.intensity` | 0..4 | 运营/匹配 | 想做的强度，不是能力分 |
| `skills[]` | object[] | 可经本人确认后分享 | `tag/proficiency/evidence_type/evidence_trust/evidence_ref` |
| `availability` | object | 匹配；摘要可分享 | `available_from/weekly_hours/duration_weeks/timezone` |
| `collaboration` | object | 可分享 | 语言、工作方式、反馈频率、团队偏好 |
| `compensation.minimum_project` | number | **私密，仅过滤** | 不向需求方或候选说明输出 |
| `boundaries` | object | 运营/匹配 | 禁止领域/任务、可处理数据级别 |
| `location.region/conflicts` | string/string[] | 运营/匹配 | 合规限制与匿名组织冲突 |
| `ai` | object | 摘要可分享 | 允许/依赖 AI、人工复核、禁止情形 |

## 需求对象

| 路径 | 类型 | 可见性 | 含义 |
| --- | --- | --- | --- |
| `id/pilot_id/status/consent_version` | string | 运营/匹配 | 批次与状态 |
| `client_org_id` | string | 运营/冲突过滤 | 匿名组织 ID |
| `decision_authority_confirmed/funding_commitment` | bool | 运营/门槛 | 两项都为 true 才可匹配 |
| `funding_evidence_ref` | string | **仅运营** | 外部证据位置引用 |
| `problem` | object | 可分享 | 背景、领域、目标用户、期望结果 |
| `scope` / `acceptance` | object | 可分享 | 交付、非范围、标准、验收角色和期限 |
| `skills` / `matching` | object | 可分享 | 必需/可选技能与偏好标签 |
| `schedule` | object | 可分享 | 起止、预计天数、每周投入、持续周数 |
| `budget` / `payment.plan` | object | 可分享约定范围 | 金额、币种、直接成本和里程碑比例 |
| `risk` | object | 按需披露 | 不确定性、紧急度、依赖、数据处理 |
| `ai` / `collaboration` / `location` | object | 可分享 | AI、语言、工作方式和地区约束 |

## 候选反馈对象

`responses.json` 是对象数组：

```json
[{"creator_id": "creator-random-id", "code": "ACCEPT", "note": "可选事实说明"}]
```

`code` 必须来自 `reason-codes-v1.yaml` 的 `candidate_response`。`OTHER` 必须有 `note`。私密、可识别或带评价性的原话不放入这里。

## 结果对象

| 路径 | 类型 | 含义 |
| --- | --- | --- |
| `project_id/pilot_id/demand_id/creator_ids` | string/string[] | 匿名关联键 |
| `status` | enum | `completed/exited/failed` |
| `signed/real_payment` | bool | 是否签约与产生真实付款 |
| `planned_*/actual_*` | date | 计划/实际起止 |
| `milestones[]` | object[] | `id/amount/accepted/paid/paid_on_terms` |
| `scope_changes/dispute` | number/bool | 变更和争议 |
| `demand_clarity_improved` | bool | 双方复盘后的方向性判断 |
| `creator_preference_confirmed` | bool[] | 各创作者是否认为匹配符合真实偏好 |
| `willing_to_use_again` | object | `demand` 布尔值、`creators` 布尔数组 |
| `service_fee_accepted` | bool | 需求方是否接受已说明的合理服务费 |
| `operator_hours` | object | 招募、访谈、匹配、协调、争议小时数 |
| `failure_primary/secondary` | string/string[] | 来自项目失败原因代码；完成可为 null |
| `safety_events` | object[] | 只记录最小必要事实和受控事件引用 |

## SQLite 记录

- `entities` 可随参与者纠正而更新。
- `recommendations` 只追加，保存输入快照、所有过滤/分项、预算和规则版本。
- `decisions` 只追加，保存实际邀请、候选反馈、最终选择和覆盖原因。
- `outcomes` 以 `project_id` 更新，允许完成退出访谈后补齐结果。

对数据主体执行删除时，历史快照也在范围内；详见 `data-protection.md`，不要只删除当前资料行。
