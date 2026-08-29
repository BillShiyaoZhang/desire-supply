import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createAtomicRefreshCoordinator } from "../lib/workbench-refresh.mjs";

const root = new URL("../", import.meta.url);

test("task discovery loads only after workspace objects and owns a separate atomic refresh slice", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const loadStart = client.indexOf("const loadWorkspaceObjects = useCallback(");
  const loadEnd = client.indexOf("\n\n  const loadWorkspace = useCallback", loadStart);
  const load = client.slice(loadStart, loadEnd);
  const refreshStart = client.indexOf("const refreshCurrentAccountTasks = useCallback(");
  const refreshEnd = client.indexOf("\n\n  const refreshReviewWorkspaceAfterAssignmentWrite", refreshStart);
  const refresh = client.slice(refreshStart, refreshEnd);
  const reviewRefreshStart = client.indexOf("const refreshReviewWorkspaceAfterAssignmentWrite = useCallback(");
  const reviewRefreshEnd = client.indexOf("\n\n  const loadWorkspaceObjects", reviewRefreshStart);
  const reviewRefresh = client.slice(reviewRefreshStart, reviewRefreshEnd);
  const clearStart = client.indexOf("const clearWorkspaceObjects = useCallback(");
  const clearEnd = client.indexOf("\n\n  const enterSignedOut", clearStart);
  const clear = client.slice(clearStart, clearEnd);

  assert.ok(
    loadStart >= 0
    && loadEnd > loadStart
    && refreshStart >= 0
    && refreshEnd > refreshStart
    && reviewRefreshStart >= 0
    && reviewRefreshEnd > reviewRefreshStart,
  );
  assert.match(client, /tasks: "\/v1\/app\/tasks"/);
  assert.match(refresh, /taskRefreshCoordinator\.run<CurrentAccountTaskDiscovery>/);
  assert.match(refresh, /requestWorkspaceJson\([\s\S]*ENDPOINTS\.tasks/);
  assert.match(refresh, /parseCurrentAccountTaskDiscovery/);
  assert.match(refresh, /isValid: \(\) => taskWorkspaceIdRef\.current === workspaceId/);
  assert.match(refresh, /commit: setTaskDiscovery/);
  assert.match(refresh, /onError:[\s\S]*setTaskError/);
  assert.doesNotMatch(refresh, /setTaskDiscovery\(null\)|setProfiles|setDemands|clearWorkspaceObjects|setSelected\(/);
  assert.match(reviewRefresh, /Promise\.all\(\[/);
  assert.match(reviewRefresh, /ENDPOINTS\.demands/);
  assert.match(reviewRefresh, /ENDPOINTS\.reviewQueue/);
  assert.match(reviewRefresh, /ENDPOINTS\.tasks/);
  assert.match(reviewRefresh, /parseEditorCollection/);
  assert.match(reviewRefresh, /parseEditorReviewQueueEnvelope/);
  assert.match(reviewRefresh, /parseCurrentAccountTaskDiscovery/);
  assert.match(reviewRefresh, /workspaceObjectGenerationRef\.current !== generation/);
  assert.match(reviewRefresh, /taskWorkspaceIdRef\.current !== workspaceId/);
  const allAt = reviewRefresh.indexOf("await Promise.all");
  for (const commit of ["setDemands(", "setReviewQueue(", "setTaskDiscovery("]) {
    assert.ok(reviewRefresh.indexOf(commit) > allAt, `${commit} must happen only after every staged read parses`);
  }
  assert.ok(load.indexOf("setProfiles(profileResult.items)") < load.indexOf("taskWorkspaceIdRef.current = workspace.workspace_id"));
  assert.ok(load.indexOf("setDemands(demandResult.items)") < load.indexOf("refreshCurrentAccountTasks(workspace.workspace_id, false)"));
  assert.match(load, /pendingRef\.current === null && logoutIntentRef\.current === null/);
  assert.match(clear, /taskRefreshCoordinator\.invalidate\(\)/);
  assert.match(clear, /taskWorkspaceIdRef\.current = null/);
  assert.match(clear, /setTaskDiscovery\(null\)/);
  assert.match(clear, /setTaskError\(null\)/);
});

test("a failed first read is distinct from a verified empty response and refresh failure retains the old snapshot", async () => {
  const coordinator = createAtomicRefreshCoordinator();
  let visible = null;
  let error = null;
  const firstFailure = new Error("task service unavailable");
  const run = (load) => coordinator.run({
    load,
    commit: (snapshot) => { visible = snapshot; },
    onSuccess: () => { error = null; },
    onError: (caught) => { error = caught; },
    setBusy() {},
  });

  assert.deepEqual(await run(async () => { throw firstFailure; }), { ok: false, error: firstFailure });
  assert.equal(visible, null);
  assert.equal(error, firstFailure);

  const verifiedEmpty = {
    schema_version: "current-account-task-discovery-v1",
    items: [],
    has_more: false,
  };
  assert.deepEqual(await run(async () => verifiedEmpty), { ok: true, snapshot: verifiedEmpty });
  assert.equal(visible, verifiedEmpty);
  assert.equal(error, null);

  const refreshFailure = new Error("refresh failed");
  assert.deepEqual(await run(async () => { throw refreshFailure; }), { ok: false, error: refreshFailure });
  assert.equal(visible, verifiedEmpty);
  assert.equal(error, refreshFailure);
});

test("workspace generation invalidation prevents a late task response from replacing the current workspace", async () => {
  const coordinator = createAtomicRefreshCoordinator();
  let activeWorkspace = "workspace-a";
  let resolveOld;
  const oldLoad = new Promise((resolve) => { resolveOld = resolve; });
  const commits = [];
  const oldRun = coordinator.run({
    isValid: () => activeWorkspace === "workspace-a",
    load: () => oldLoad,
    commit: (snapshot) => commits.push(snapshot),
    onSuccess() {},
    onError: (error) => assert.fail(String(error)),
    setBusy() {},
  });
  activeWorkspace = "workspace-b";
  coordinator.invalidate();
  const current = { schema_version: "current-account-task-discovery-v1", items: [], has_more: false };
  const newRun = coordinator.run({
    isValid: () => activeWorkspace === "workspace-b",
    load: async () => current,
    commit: (snapshot) => commits.push(snapshot),
    onSuccess() {},
    onError: (error) => assert.fail(String(error)),
    setBusy() {},
  });
  assert.deepEqual(await newRun, { ok: true, snapshot: current });
  resolveOld({ schema_version: "current-account-task-discovery-v1", items: ["stale"], has_more: false });
  assert.deepEqual(await oldRun, { ok: false, stale: true });
  assert.deepEqual(commits, [current]);
});

test("task panel exposes accessible grouped, loading, empty, error, stale, and has-more states", async () => {
  const [client, css] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
  ]);
  const panelStart = client.indexOf("function CurrentAccountTaskPanel(");
  const panelEnd = client.indexOf("\n\nfunction ReviewQueueGroup", panelStart);
  const panel = client.slice(panelStart, panelEnd);
  assert.ok(panelStart >= 0 && panelEnd > panelStart);
  for (const phrase of [
    "我的任务与历史",
    "待处理",
    "等待中",
    "已完成",
    "刷新任务与历史",
    "任务读取未完成",
    "保留上一次已验证的任务快照",
    "没有把读取失败伪造成",
    "当前账号暂无待处理、等待中或已完成",
    "服务端还有更多历史记录",
  ]) assert.match(client, new RegExp(phrase));
  assert.match(panel, /aria-busy=\{busy\}/);
  assert.match(panel, /aria-labelledby="current-account-tasks-title"/);
  assert.match(panel, /role="alert"/);
  assert.match(panel, /role="status"/);
  assert.match(panel, /<ol>/);
  assert.match(panel, /<time dateTime=\{task\.updated_at\}>/);
  assert.match(panel, /<button[\s\S]*onClick=\{\(\) => onOpen\(task\)\}/);
  assert.doesNotMatch(panel, /href=|resource_path|JSON\.stringify|<pre|<textarea|<input/);
  for (const className of [
    "current-account-tasks",
    "task-discovery-error",
    "task-discovery-progress",
    "task-discovery-empty",
    "task-discovery-groups",
    "task-discovery-group--waiting",
    "task-discovery-group--completed",
    "task-discovery-card",
    "task-discovery-action",
    "task-discovery-more",
  ]) assert.match(css, new RegExp(`\\.${className}`));
  assert.match(css, /@media \(max-width: 980px\)[\s\S]*task-discovery-groups/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*current-account-tasks/);
  assert.match(css, /@media \(forced-colors: active\)[\s\S]*current-account-tasks/);
});

test("task actions use loaded objects or focusable role workbenches and never navigate the API path", async () => {
  const [client, resolver, trust, appeal] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/current-account-task-destination.mjs", root), "utf8"),
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
  ]);
  const openStart = client.indexOf("function openCurrentAccountTask(");
  const openEnd = client.indexOf("\n\n  const replaceResource", openStart);
  const open = client.slice(openStart, openEnd);
  assert.ok(openStart >= 0 && openEnd > openStart);
  assert.match(open, /profiles\.find\(\(item\) => item\.object_id === task\.resource_id\)/);
  assert.match(open, /demands\.find\(\(item\) => item\.object_id === task\.resource_id\)/);
  assert.match(open, /void openResource\(resource, true\)/);
  assert.match(open, /resolveCurrentAccountTaskDestination\(task\)/);
  for (const destination of [
    "appeal-workbench-title",
    "review-history-title",
    "review-queue-title",
    "finance-funding-title",
    "finance-funding-queue-title",
    "trust-workbench-title",
    "trust-case-history-title",
  ]) assert.match(resolver, new RegExp(destination));
  assert.match(open, /destination\.focus\(\{ preventScroll: true \}\)/);
  assert.match(open, /destination\.scrollIntoView/);
  assert.match(open, /不需要粘贴资源编号/);
  assert.doesNotMatch(open, /resource_path|location\.|window\.|href|fetch\(|requestJson|requestWorkspaceJson|performWrite/);
  assert.match(client, /id="review-queue-title" tabIndex=\{-1\}/);
  assert.match(client, /task\.next_action === "VIEW_DEMAND_REVIEW_HISTORY"/);
  assert.match(client, /id="finance-funding-queue-title" tabIndex=\{-1\}/);
  assert.match(trust, /id="trust-workbench-title" tabIndex=\{-1\}/);
  assert.match(appeal, /id="appeal-workbench-title" tabIndex=\{-1\}/);
});

test("Finance detail tasks recheck session, authority, exact task, assigned queue and detail without writes", async () => {
  const [client, resolver] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/current-account-task-destination.mjs", root), "utf8"),
  ]);
  const recoveryStart = client.indexOf("async function openRevalidatedFinanceCurrentAccountTask(");
  const recoveryEnd = client.indexOf("\n\n  async function recoverMissingCurrentAccountTaskResource", recoveryStart);
  const recovery = client.slice(recoveryStart, recoveryEnd);
  const openStart = client.indexOf("function openCurrentAccountTask(");
  const openEnd = client.indexOf("\n\n  const replaceResource", openStart);
  const open = client.slice(openStart, openEnd);

  assert.ok(recoveryStart >= 0 && recoveryEnd > recoveryStart && openStart >= 0 && openEnd > openStart);
  assert.match(recovery, /resolveFinanceTaskDetailAction\(task\)/);
  assert.match(recovery, /requestJson\(ENDPOINTS\.session\)[\s\S]*parseSessionBootstrap/);
  assert.match(recovery, /requestJson\(ENDPOINTS\.workspaces\)[\s\S]*parseWorkspaceDiscovery/);
  assert.match(recovery, /refreshedSession\.session\.session_id !== sessionId/);
  assert.match(recovery, /candidate\.workspace_id === workspace\.workspace_id/);
  assert.match(recovery, /refreshedWorkspace\.workspace_kind !== "PLATFORM"/);
  assert.match(recovery, /!refreshedWorkspace\.role_codes\.includes\("FINANCE_OPERATOR"\)/);
  assert.match(recovery, /loadWorkspaceObjects\(refreshedWorkspace, false, false\)/);
  assert.match(recovery, /refreshCurrentAccountTasks\(refreshedWorkspace\.workspace_id, false\)/);
  assert.match(recovery, /resolveRevalidatedFinanceTaskQueueItem\([\s\S]*taskResult\.snapshot[\s\S]*snapshot\.financeFundingQueue/);
  assert.match(recovery, /TASK_FINANCE_ASSIGNMENT_NO_LONGER_AVAILABLE/);
  assert.match(recovery, /`\$\{ENDPOINTS\.financeFundingReviews\}\/\$\{revalidated\.task\.resource_id\}`/);
  assert.match(recovery, /parseFinanceFundingReviewEnvelope\(response\.value\)/);
  assert.match(recovery, /resolveFinanceTaskDetail\([\s\S]*revalidated\.task[\s\S]*revalidated\.queue_item[\s\S]*review[\s\S]*response\.etag/);
  assert.match(recovery, /TASK_FINANCE_DETAIL_DRIFTED/);
  assert.match(recovery, /destination\?\.dataset\.fundingReviewId !== exactReview\.funding_review_id/);
  assert.doesNotMatch(recovery, /resource_path|performWrite|createFinanceFunding(?:Claim|Confirm|Finding|Release)Intent|method:\s*"(?:POST|PUT|PATCH|DELETE)"/);

  assert.match(open, /resolveFinanceTaskDetailAction\(task\)[\s\S]*openRevalidatedFinanceCurrentAccountTask\(task\)/);
  assert.match(client, /task\.next_action === "CONTINUE_FINANCE_REVIEW"\) return "打开当前资金确认"/);
  assert.match(client, /task\.next_action === "WAIT_FOR_FINANCE_CONFIRMATION"\) return "查看当前资金确认"/);
  assert.match(client, /task\.resource_kind === "FINANCE_FUNDING_REVIEW"\) return "前往资金确认队列"/);
  assert.match(resolver, /FINANCE_FUNDING_REVIEW:CLAIM_FINANCE_REVIEW", FINANCE/);
  assert.match(resolver, /FINANCE_FUNDING_REVIEW:CONTINUE_FINANCE_REVIEW", FINANCE_DETAIL/);
  assert.match(resolver, /FINANCE_FUNDING_REVIEW:WAIT_FOR_FINANCE_CONFIRMATION", FINANCE_DETAIL/);
  assert.match(client, /data-funding-review-id=\{review\.funding_review_id\}[\s\S]*id="finance-funding-title"[\s\S]*tabIndex=\{-1\}/);
});

test("a missing resource task performs one generation-safe closed recheck with actionable failure", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const recoveryStart = client.indexOf("async function recoverMissingCurrentAccountTaskResource(");
  const recoveryEnd = client.indexOf("\n\n  function openCurrentAccountTask", recoveryStart);
  const recovery = client.slice(recoveryStart, recoveryEnd);
  const loadStart = client.indexOf("const loadWorkspaceObjects = useCallback(");
  const loadEnd = client.indexOf("\n\n  const loadWorkspace = useCallback", loadStart);
  const load = client.slice(loadStart, loadEnd);

  assert.ok(recoveryStart >= 0 && recoveryEnd > recoveryStart);
  assert.match(recovery, /requestJson\(ENDPOINTS\.workspaces\)/);
  assert.match(recovery, /parseWorkspaceDiscovery/);
  assert.match(recovery, /candidate\.workspace_id === workspace\.workspace_id/);
  assert.match(recovery, /workspaceObjectGenerationRef\.current !== ownedGeneration/);
  assert.match(recovery, /loadWorkspaceObjects\(refreshedWorkspace, false, false\)/);
  assert.match(recovery, /await refreshCurrentAccountTasks\(refreshedWorkspace\.workspace_id, false\)/);
  assert.match(recovery, /if \(!taskResult\.ok\)[\s\S]*"stale" in taskResult/);
  assert.match(recovery, /resolveRevalidatedCurrentAccountTaskResource\([\s\S]*taskResult\.snapshot[\s\S]*snapshot\.profiles[\s\S]*snapshot\.demands/);
  assert.match(recovery, /TASK_DESTINATION_NO_LONGER_AVAILABLE/);
  assert.match(recovery, /请使用顶部“刷新权限与对象”/);
  assert.match(recovery, /没有猜测权限或直接读取任务路径/);
  assert.doesNotMatch(recovery, /task\.resource_path|requestWorkspaceJson\(|location\.|window\.|href|performWrite/);
  assert.match(load, /const loadGeneration = workspaceObjectGenerationRef\.current/);
  assert.equal((load.match(/workspaceObjectGenerationRef\.current !== loadGeneration/g) ?? []).length, 2);
  assert.match(load, /refreshTasksAfterLoad && pendingRef\.current === null/);
});

test("successful resource task navigation focuses and scrolls the exact editor heading", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const openStart = client.indexOf("async function openResource(");
  const openEnd = client.indexOf("\n\n  async function openAccount", openStart);
  const open = client.slice(openStart, openEnd);
  const editorStart = client.indexOf("function ResourceEditor(");
  const editor = client.slice(editorStart);

  assert.ok(openStart >= 0 && openEnd > openStart && editorStart >= 0);
  assert.match(open, /focusAfterOpen/);
  assert.match(open, /requestAnimationFrame/);
  assert.match(open, /resourceReadEpochRef\.current !== readEpoch/);
  assert.match(open, /resourceEditorTitleRef\.current/);
  assert.match(open, /destination\?\.dataset\.resourceId !== resource\.object_id/);
  assert.match(open, /destination\.focus\(\{ preventScroll: true \}\)/);
  assert.match(open, /destination\.scrollIntoView\(\{ block: "start", behavior: "auto" \}\)/);
  assert.match(client, /titleRef=\{resourceEditorTitleRef\}/);
  assert.match(editor, /aria-labelledby="resource-editor-title"/);
  assert.match(editor, /data-resource-id=\{resource\.object_id\}/);
  assert.match(editor, /id="resource-editor-title"/);
  assert.match(editor, /ref=\{titleRef\}/);
  assert.match(editor, /tabIndex=\{-1\}/);
});

test("Appeal tasks recheck workspace plus exact kind, ID, and action before a read-only detail handoff", async () => {
  const [client, appeal] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
  ]);
  const recoveryStart = client.indexOf("async function openRevalidatedAppealCurrentAccountTask(");
  const recoveryEnd = client.indexOf("\n\n  async function openRevalidatedFinanceCurrentAccountTask", recoveryStart);
  const recovery = client.slice(recoveryStart, recoveryEnd);
  const taskReadStart = appeal.indexOf("const openTaskAppeal = useCallback(");
  const taskReadEnd = appeal.indexOf("\n\n  const readOwn", taskReadStart);
  const taskRead = appeal.slice(taskReadStart, taskReadEnd);

  assert.ok(recoveryStart >= 0 && recoveryEnd > recoveryStart && taskReadStart >= 0 && taskReadEnd > taskReadStart);
  assert.match(client, /resolveAppealTaskReadKind\(task\)/);
  assert.match(recovery, /requestJson\(ENDPOINTS\.session\)[\s\S]*parseSessionBootstrap/);
  assert.match(recovery, /requestJson\(ENDPOINTS\.workspaces\)/);
  assert.match(recovery, /refreshedSession\.session\.session_id !== sessionId/);
  assert.match(recovery, /candidate\.workspace_id === workspace\.workspace_id/);
  assert.match(recovery, /loadWorkspaceObjects\(refreshedWorkspace, false, false\)/);
  assert.match(recovery, /refreshCurrentAccountTasks\(refreshedWorkspace\.workspace_id, false\)/);
  assert.match(recovery, /resolveRevalidatedCurrentAccountTask\(task, taskResult\.snapshot\)/);
  assert.match(recovery, /appeal_id: refreshedTask\.resource_id/);
  assert.match(recovery, /next_action: refreshedTask\.next_action/);
  assert.match(recovery, /session_id: sessionId/);
  assert.match(recovery, /workspace_id: refreshedWorkspace\.workspace_id/);
  assert.doesNotMatch(recovery, /resource_path|performWrite|method:\s*"(?:POST|PUT|PATCH|DELETE)"/);
  assert.match(client, /taskTarget=\{appealTaskTarget\}/);
  assert.match(client, /VIEW_APPEAL_REVIEW_HISTORY: "查看我的已完成申诉复核"/);
  assert.match(client, /task\.next_action === "VIEW_APPEAL_REVIEW_HISTORY"\) return "查看我的申诉复核历史"/);

  assert.match(taskRead, /isAppealTaskTargetCurrent\(candidate/);
  assert.match(taskRead, /rejectNonRecoveryIfLocked\(\)/);
  assert.match(taskRead, /loadOwn\(candidate\.appeal_id\)/);
  assert.match(taskRead, /loadAssigned\(candidate\.appeal_id\)/);
  assert.match(taskRead, /commit: adoptOwn/);
  assert.match(taskRead, /commit: adoptAssigned/);
  assert.doesNotMatch(taskRead, /performWrite|createAppeal|resource_path/);
  assert.match(appeal, /target\.session_id !== context\.sessionId/);
  assert.match(appeal, /target\.workspace_id !== context\.workspaceId/);
  assert.match(appeal, /destination\?\.dataset\.appealId !== appealId/);
  assert.match(appeal, /data-appeal-id=\{ownAppeal\.appeal_id\}/);
  assert.match(appeal, /data-appeal-id=\{assignedAppeal\.appeal\.appeal_id\}/);
  assert.match(appeal, /taskTarget\.read_kind === "HISTORY"[\s\S]*focusReviewHistoryTask\(taskTarget\)/);
});

test("workspace task rechecks cannot erase a child write latch acquired during their reload", async () => {
  const [client, appeal] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
  ]);
  const loadStart = client.indexOf("const loadWorkspaceObjects = useCallback(");
  const loadEnd = client.indexOf("\n\n  const loadWorkspace = useCallback", loadStart);
  const load = client.slice(loadStart, loadEnd);
  const recoveryStart = load.indexOf("if (recoverBrowserState)");
  const resetBranchStart = load.indexOf(
    "    } else {\n      if (pendingRef.current !== null)",
    recoveryStart,
  );
  const resetBranchEnd = load.indexOf("\n    taskWorkspaceIdRef.current", resetBranchStart);
  const resetBranch = load.slice(resetBranchStart, resetBranchEnd);

  assert.ok(
    loadStart >= 0
    && loadEnd > loadStart
    && recoveryStart >= 0
    && resetBranchStart >= 0
    && resetBranchEnd > resetBranchStart,
  );
  assert.match(resetBranch, /if \(pendingRef\.current !== null\) \{\s*throw new ApiError\(409, "WRITE_OUTCOME_PENDING", null, null, null\);\s*\}/);
  assert.doesNotMatch(resetBranch, /pendingRef\.current\s*=\s*null/);
  assert.match(resetBranch, /sessionStorage\.removeItem\(PENDING_KEY\)/);

  for (const owner of ["ORGANIZATION", "TRUST", "APPEAL"]) {
    assert.match(
      client,
      new RegExp(`writeLocked=\\{busy \\|\\| logoutIntent !== null \\|\\| \\(pendingOwner !== null && pendingOwner !== "${owner}"\\)\\}`),
    );
  }
  assert.match(appeal, /const result = await reviewerRefreshCoordinator\.run\(/);
  assert.match(appeal, /!result\.ok && "stale" in result && origin === "INITIAL"[\s\S]*setInitialRefreshStarted\(false\)/);
});
