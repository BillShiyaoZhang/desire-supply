// These are presentation choices, never authorization. The caller passes only
// capabilities already established for the selected server workspace.
const DESTINATIONS = [
  ["tasks", "待办", "从需要你处理的事情开始。", "工作", null, "inbox"],
  ["profiles", "我的画像", "整理你的能力、意愿和合作条件。", "工作", "profileScope", "person"],
  ["demands", "我的需求", "明确目标，跟进审核与合作进度。", "工作", "demandScope", "document"],
  ["review", "需求审核", "领取一项需求，核对内容并给出结论。", "工作", "canReviewDemands", "check"],
  ["funding", "资金确认", "核对合成证据，完成独立确认。", "工作", "canReviewFunding", "wallet"],
  ["matching", "合作匹配", "查看候选、邀请与合作意向。", "协作", "canUseMatching", "people"],
  ["matching-review", "匹配审核", "核对匹配结果，处理分配给你的审核。", "工作", "canReviewMatching", "people"],
  ["trust", "举报与处理", "提交问题，查看处理进展。", "协作", "canUseTrust", "shield"],
  ["appeal", "申诉与复核", "查看处理结果，提出或复核申诉。", "协作", "canUseAppeal", "review"],
  ["organization", "组织管理", "管理组织信息、成员和邀请。", "管理", "canAdminOrganization", "building"],
  ["accounts", "账号管理", "查看账号状态，处理职责与访问权限。", "管理", "canAdminAccounts", "person"],
  ["timeline", "需求全流程", "按需求查看各阶段进度与操作记录。", "管理", "canInspectDemands", "timeline"],
  ["security", "账号与安全", "查看登录会话，管理账号安全。", "个人", null, "lock"],
];

export function buildWorkspaceNavigation(capabilities) {
  return DESTINATIONS.filter(([, , , , capability]) => !capability || capabilities[capability] === true)
    .map(([id, label, description, group, , icon]) => ({
      id,
      label: id === "matching" && capabilities.isCreator ? "合作邀请"
        : id === "trust" && capabilities.isTrustOfficer ? "信任与安全"
          : id === "appeal" && capabilities.isAppealReviewer ? "申诉复核" : label,
      description,
      group: (id === "trust" && capabilities.isTrustOfficer) || (id === "appeal" && capabilities.isAppealReviewer) ? "工作" : group,
      icon,
    }));
}

export function resolveWorkspaceView(requested, navigation, pendingOwner) {
  const available = new Set(navigation.map((item) => item.id));
  // A recovering child stays mounted and must remain reachable even after a
  // refresh. Never strand an unknown write inside an invisible module.
  const recoveryView = {
    ORGANIZATION: "organization", TRUST: "trust", APPEAL: "appeal", SESSION: "security",
    MATCHING: available.has("matching") ? "matching" : "matching-review",
  }[pendingOwner];
  if (recoveryView && available.has(recoveryView)) return recoveryView;
  return available.has(requested) ? requested : "tasks";
}

export function workspaceViewForTarget(elementId) {
  if (elementId.startsWith("review-")) return "review";
  if (elementId.startsWith("finance-")) return "funding";
  if (elementId.startsWith("trust-")) return "trust";
  if (elementId.startsWith("appeal-")) return "appeal";
  return "tasks";
}
