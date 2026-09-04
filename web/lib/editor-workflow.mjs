const WORKFLOWS = {
  CREATOR_PROFILE: [
    { id: "strengths", title: "兴趣与专长", description: "让合适的问题找到你。先介绍感兴趣的领域与可以提供的技能。", paths: ["/interests", "/skills"] },
    { id: "working", title: "参与方式", description: "说明何时、何地以及如何参与合作。", paths: ["/availability", "/collaboration", "/location"] },
    { id: "boundaries", title: "合作边界", description: "明确报酬预期和不能接受的工作条件。", paths: ["/compensation", "/boundaries"] },
    { id: "responsibility", title: "责任与约束", description: "补充利益冲突与 AI 使用约束，为合作建立清晰预期。", paths: ["/conflicts", "/ai"] },
  ],
  DEMAND: [
    { id: "outcome", title: "目标与成果", description: "说清需要解决的问题、交付范围，以及如何判断完成。", paths: ["/problem", "/scope", "/acceptance"] },
    { id: "team", title: "寻找合作者", description: "定义所需技能、匹配条件与协作方式。", paths: ["/skills", "/matching", "/collaboration", "/location"] },
    { id: "plan", title: "时间与预算", description: "安排工期、合成预算和里程碑，让执行计划可核对。", paths: ["/schedule", "/budget", "/milestone_plan"] },
    { id: "responsibility", title: "风险与授权", description: "确认数据风险、AI 使用规则和必要授权。", paths: ["/risk", "/ai", "/declarations"] },
  ],
};

/** Group only server-authorized paths. Unknown future paths remain reachable. */
export function buildEditorWorkflow(resourceType, editablePaths) {
  const remaining = new Set(editablePaths);
  const steps = (WORKFLOWS[resourceType] ?? []).flatMap((step) => {
    const paths = step.paths.filter((path) => remaining.delete(path));
    return paths.length ? [{ ...step, paths }] : [];
  });
  const otherPaths = [...remaining];
  for (let offset = 0; offset < otherPaths.length; offset += 4) {
    steps.push({
      id: `additional-${offset / 4 + 1}`,
      title: "补充信息",
      description: "核对当前内容允许编辑的其他信息。",
      paths: otherPaths.slice(offset, offset + 4),
    });
  }
  return [...steps, {
    id: "review",
    title: resourceType === "CREATOR_PROFILE" ? "复核与发布" : "复核与提交",
    description: resourceType === "CREATOR_PROFILE"
      ? "核对各部分内容，保存草稿后再发布画像。"
      : "核对各部分内容，保存草稿后再提交审核。",
    paths: [],
  }];
}
