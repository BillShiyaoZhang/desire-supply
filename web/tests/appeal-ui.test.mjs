import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("ProductClient exposes applicant and independent reviewer Appeal workspaces through one global latch", async () => {
  const [product, appeal, route] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
    readFile(new URL("app/v1/app/[...path]/route.ts", root), "utf8"),
  ]);
  assert.match(product, /import \{ AppealWorkbench, type AppealTaskTarget \} from "\.\/appeal-workbench"/);
  assert.match(product, /role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(product, /role_codes\.includes\("APPEAL_REVIEWER"\)/);
  assert.match(product, /const claimAppealWrite = useCallback/);
  assert.match(product, /setPendingOwner\("APPEAL"\)/);
  assert.match(product, /writeLocked=\{busy \|\| logoutIntent !== null \|\| \(pendingOwner !== null && pendingOwner !== "APPEAL"\)\}/);
  assert.match(route, /export const GET = handle/);
  assert.match(route, /export const POST = handle/);
  assert.match(route, /export const PUT = handle/);

  for (const phrase of [
    "申诉申请人与独立复核", "按 Trust 结论或 Appeal ID 读取我的申诉", "打开申诉", "保存申请草稿",
    "提交申诉", "独立复核队列", "领取复核", "按 Appeal ID 读取活动分配", "释放复核分配",
    "保存复核草稿", "发布申诉决定", "不可回显", "不可变 Trust 来源", "statement_recorded",
    "review_note_recorded", "我的已完成申诉复核", "fresh 读取终态详情", "has_more=true",
    "party-safe 字段", "高级诊断：按 opaque ID 恢复申诉", "高级诊断：按 Appeal ID 读取活动分配",
  ]) assert.match(appeal, new RegExp(phrase));
  assert.equal((appeal.match(/>领取复核<\/button>/g) ?? []).length, 1);
  assert.doesNotMatch(appeal, /appeal_reviewer_01|applicant_user_id|reviewer_user_id|assignment_id/);
});

test("Appeal writes accept receipt-safe results and bind every success to a fresh authorized read", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");
  for (const symbol of [
    "createAppealOpenIntent", "createAppealApplicationDraftIntent", "createAppealSubmitIntent",
    "createAppealReviewClaimIntent", "createAppealReviewReleaseIntent", "createAppealReviewDraftIntent",
    "createAppealDecisionIntent", "parseAppealCommandEnvelope", "parseAppealOwnEnvelope",
    "parseAppealQueueEnvelope", "parseAppealAssignedEnvelope",
  ]) assert.match(appeal, new RegExp(symbol));
  assert.match(appeal, /const committed = parseAppealCommandEnvelope\(result\.value\)/);
  assert.match(appeal, /result\.etag !== null/);
  assert.match(appeal, /expectedAppealEvent\(record\.intent\.path\)/);
  assert.match(appeal, /fresh\.appeal_id !== committed\.appeal_id/);
  assert.match(appeal, /fresh\.aggregate_version < committed\.aggregate_version/);
  assert.match(appeal, /assignment\/release[\s\S]*await refreshReviewerWork\(\)/);
  assert.doesNotMatch(appeal, /parseAppealOwnEnvelope\(result\.value\)|parseAppealAssignedEnvelope\(result\.value\)/);
});

test("Appeal pending recovery is exclusive and reviewer refreshes commit one handled snapshot", async () => {
  const [appeal, snapshotLoader] = await Promise.all([
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
    readFile(new URL("lib/appeal-reviewer-snapshot.mjs", root), "utf8"),
  ]);

  assert.match(appeal, /const \[reviewerSnapshot, setReviewerSnapshot\] = useState<AppealReviewerSnapshot \| null>\(null\)/);
  assert.match(appeal, /loadConsistentAppealReviewerSnapshot\(\{\s*loadAssignments,\s*loadHistory: loadReviewHistory,\s*loadQueue/);
  assert.match(snapshotLoader, /const \[queueProjection, assignmentProjection, historyProjection\] = await Promise\.all\(\[/);
  assert.match(snapshotLoader, /return assertAppealReviewerSnapshotDisjoint\(snapshot\)/);
  assert.match(snapshotLoader, /attempt === 1/);
  assert.match(appeal, /setReviewerSnapshot\(snapshot\)/);
  assert.doesNotMatch(appeal, /setQueue\(|setAssignments\(/);

  assert.match(appeal, /const \[reviewerRefreshCoordinator\] = useState\(createAtomicRefreshCoordinator\)/);
  assert.match(appeal, /const coordinatedRefreshReviewerWork = useCallback\([\s\S]*reviewerRefreshCoordinator\.run\(\{/);
  assert.match(appeal, /load: loadReviewerSnapshot,\s*isValid: \(\) => isReadGenerationValid\(origin\),\s*validate: options\.validate,\s*commit: \(snapshot\) => \{\s*if \(options\.deferCommit\) return;\s*commitReviewerSnapshot\(snapshot\);\s*options\.afterCommit\?\.\(snapshot\)/);
  assert.match(appeal, /const manuallyRefreshReviewerWork = useCallback\(async \(\) => \{[\s\S]*await coordinatedRefreshReviewerWork\("MANUAL"\)/);
  assert.match(appeal, /useEffect\(\(\) => \{[\s\S]*coordinatedRefreshReviewerWork\("INITIAL"\)/);
  assert.match(appeal, /setBusy: \(value\) => \{\s*setRefreshing\(value\)/);
  assert.match(appeal, /onError: \(caught\) => \{[\s\S]*setError\(failure\(caught\)\)/);
  assert.match(appeal, /onClick=\{\(\) => void manuallyRefreshReviewerWork\(\)\}/);
  assert.doesNotMatch(appeal, /onClick=\{\(\) => void refreshReviewerWork\(\)\}/);

  assert.match(appeal, /busy: busy \|\| reading \|\| refreshing \|\| !recoveryChecked/);
  assert.match(appeal, /<fieldset[\s\S]*aria-disabled=\{actionLocked\}[\s\S]*disabled=\{actionLocked\}/);
  const pendingPanelAt = appeal.indexOf("WRITE OUTCOME UNKNOWN");
  const lockedScopeAt = appeal.indexOf('className={actionLocked ? "pending-write-scope');
  assert.ok(pendingPanelAt >= 0 && lockedScopeAt > pendingPanelAt);
  const recoverySurface = appeal.slice(pendingPanelAt, lockedScopeAt);
  assert.match(recoverySurface, /performWrite\(pending\)/);
  assert.match(recoverySurface, /clearPending\(pending\)/);
});

test("Appeal global latch blocks every read and diagnostic path at control and handler boundaries", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");

  assert.match(appeal, /const rejectNonRecoveryIfLocked = useCallback\(\(\) => \{\s*if \(!recoveryChecked \|\| busy \|\| reading \|\| refreshing\) return true;\s*if \(!writeLocked && pending === null\) return false;/);
  assert.match(appeal, /GLOBAL_WRITE_LOCKED/);
  assert.match(appeal, /!recoveryChecked[\s\S]*initialRefreshStarted[\s\S]*!canReview[\s\S]*busy[\s\S]*reading[\s\S]*refreshing[\s\S]*writeLocked[\s\S]*pending !== null/);
  for (const handler of [
    "manuallyRefreshReviewerWork",
    "findBySource",
    "findById",
    "openAppeal",
    "openAssigned",
    "openDiscoveredAssignment",
    "openHistoryItem",
  ]) {
    const declaration = handler === "manuallyRefreshReviewerWork" ? `const ${handler}` : `function ${handler}`;
    const start = appeal.indexOf(declaration);
    assert.ok(start >= 0, `${handler} must exist`);
    assert.match(appeal.slice(start, start + 360), /rejectNonRecoveryIfLocked\(\)/, `${handler} must fail closed on the global latch`);
  }
  for (const label of ["按来源读取", "按 ID 读取", "同步分配、队列与历史", "刷新分配、队列与历史", "诊断读取"]) {
    const labelAt = appeal.indexOf(label);
    assert.ok(labelAt >= 0, `${label} control must exist`);
    assert.match(appeal.slice(Math.max(0, labelAt - 240), labelAt), /disabled=\{actionLocked\}/, `${label} must honor the global latch`);
  }
});

test("Appeal recovery precedes initial GET and post-write snapshots cannot bypass ordering", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");
  const recoveryAt = appeal.indexOf("const recovered = parsePendingIntent");
  const checkedAt = appeal.indexOf("setRecoveryChecked(true)", recoveryAt);
  const initialAt = appeal.indexOf('void coordinatedRefreshReviewerWork("INITIAL")');
  assert.ok(recoveryAt >= 0 && checkedAt > recoveryAt && initialAt > checkedAt);
  assert.doesNotMatch(appeal, /setTimeout/);
  assert.match(appeal, /if \(\(writeLocked \|\| pending !== null\) && !controlledRefreshActive\.current\) \{[\s\S]{0,160}reviewerRefreshCoordinator\.invalidate\(\);\s*detailReadCoordinator\.invalidate\(\)/);
  assert.match(appeal, /setReading\(false\);\s*setRefreshing\(false\)/);
  assert.match(appeal, /useLayoutEffect\(\(\) => \{\s*return \(\) => \{\s*detailReadCoordinator\.invalidate\(\);\s*reviewerRefreshCoordinator\.invalidate\(\)/);

  const refreshWrapperAt = appeal.indexOf("const refreshReviewerWork = useCallback");
  const manualAt = appeal.indexOf("const manuallyRefreshReviewerWork", refreshWrapperAt);
  const refreshWrapper = appeal.slice(refreshWrapperAt, manualAt);
  assert.match(refreshWrapper, /coordinatedRefreshReviewerWork\("POST_WRITE", options\)/);
  assert.doesNotMatch(refreshWrapper, /loadReviewerSnapshot\(|commitReviewerSnapshot\(/);
  assert.match(appeal, /if \(origin !== "MANUAL"\) setInitialRefreshStarted\(true\)/);
  assert.match(appeal, /writeConfirmed = true;\s*if \(record\.resource_type === "APPEAL_REVIEW"\) setInitialRefreshStarted\(true\)/);
  assert.match(appeal, /settlePendingForRefresh\(\)[\s\S]*await refreshReviewerWork\(\)[\s\S]*releaseWrite\(record\)/);
  assert.equal((appeal.match(/commitReviewerSnapshot\(snapshot\)/g) ?? []).length, 1);
  assert.equal((appeal.match(/setReviewerSnapshot\(snapshot\)/g) ?? []).length, 1);
});

test("Appeal detail GETs use one invalidatable coordinator while owned post-write reads stay controlled", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");
  assert.match(appeal, /const \[detailReadCoordinator\] = useState\(createAtomicRefreshCoordinator\)/);
  assert.match(appeal, /const runDetailRead = useCallback[\s\S]*detailReadCoordinator\.run\(\{[\s\S]*isValid: \(\) => isReadGenerationValid\(origin\)/);
  assert.equal((appeal.match(/runDetailRead\("INTERACTIVE"/g) ?? []).length, 8);
  assert.equal((appeal.match(/runDetailRead\("POST_WRITE"/g) ?? []).length, 3);
  assert.equal((appeal.match(/setBusy\(true\)/g) ?? []).length, 1, "only writes own write-busy; reads own generation-safe reading state");
  assert.match(appeal, /controlledRefreshActive\.current = true;\s*settlePendingForRefresh\(\)/);
  assert.match(appeal, /finally \{\s*controlledRefreshActive\.current = false;\s*setBusy\(false\)/);

  for (const loader of ["loadOwn", "loadAssigned", "loadTerminal"]) {
    const start = appeal.indexOf(`const ${loader}`);
    const end = appeal.indexOf("\n  const ", start + 8);
    const body = appeal.slice(start, end);
    assert.match(body, /await request\(/, `${loader} must perform the GET`);
    assert.doesNotMatch(body, /adoptOwn|adoptAssigned|setNotice|setError/, `${loader} must stage without committing UI state`);
  }
});

test("Appeal validates release, decision, and claim snapshots before one staged UI commit", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");
  const validatorAt = appeal.indexOf("function validateAppealPostWriteSnapshot");
  const pendingRecordAt = appeal.indexOf("function pendingRecord", validatorAt);
  const validator = appeal.slice(validatorAt, pendingRecordAt);
  for (const eventType of [
    "AppealReviewAssignmentReleased",
    "AppealDecisionPublished",
  ]) assert.match(validator, new RegExp(eventType));
  assert.match(validator, /queued \|\| !assigned/);
  assert.match(validator, /queued \|\| assigned \|\| completed === null \|\| completed\.decision_code !== expectedDecisionCode/);
  assert.match(validator, /INVALID_APPEAL_REVIEWER_SNAPSHOT_BINDING/);

  const performWriteAt = appeal.indexOf("const performWrite = useCallback");
  const catchAt = appeal.indexOf("} catch (caught)", performWriteAt);
  const successPath = appeal.slice(performWriteAt, catchAt);
  assert.match(successPath, /refreshReviewerWork\(\{\s*validate: \(snapshot\) => validateAppealPostWriteSnapshot/);
  assert.match(successPath, /afterCommit: \(\) => adoptAssigned\(fresh\)/);
  assert.match(successPath, /const terminal = await readTerminal\(committed\.appeal_id/);
  assert.match(successPath, /fresh\.decision\.decision_version_id !== committed\.decision_version_id/);
  assert.match(successPath, /fresh\.decision\.decided_at !== completed\.decided_at/);
  assert.match(successPath, /deferCommit: true/);
  assert.match(successPath, /commitReviewerSnapshot\(freshReviewerSnapshot, terminal\)/);
  const decisionAt = successPath.indexOf("if (isDecision)");
  const terminalAt = successPath.indexOf("const terminal = await readTerminal", decisionAt);
  const decisionCommitAt = successPath.indexOf("commitReviewerSnapshot(freshReviewerSnapshot, terminal)", terminalAt);
  assert.ok(decisionAt >= 0 && terminalAt > decisionAt && decisionCommitAt > terminalAt);
  assert.doesNotMatch(successPath.slice(decisionAt, terminalAt), /commitReviewerSnapshot|setTerminalAppeal/);
  assert.doesNotMatch(successPath.slice(successPath.indexOf("const fresh = await readAssigned"), successPath.indexOf("await refreshReviewerWork({", successPath.indexOf("const fresh = await readAssigned"))), /adoptAssigned\(|setNotice\(/);
  const confirmedFailureAt = appeal.indexOf("if (writeConfirmed)", catchAt);
  const ordinaryFailureAt = appeal.indexOf("const problem = failure(caught)", confirmedFailureAt);
  const confirmedFailure = appeal.slice(confirmedFailureAt, ordinaryFailureAt);
  assert.match(confirmedFailure, /clearPending\(record\)[\s\S]*APPEAL_POST_COMMIT_REFRESH_FAILED[\s\S]*保留操作前完整快照/);
  assert.doesNotMatch(confirmedFailure, /setAssignedAppeal|setTerminalAppeal|setReviewerSnapshot/);
});

test("Appeal completed history is keyboard-operable, keeps verified emptiness distinct, and tasks focus exact fresh rows", async () => {
  const appeal = await readFile(new URL("app/appeal-workbench.tsx", root), "utf8");
  assert.match(appeal, /id="appeal-review-history-title" tabIndex=\{-1\}/);
  assert.match(appeal, /history\.items\.map[\s\S]*<button[\s\S]*ref=\{\(element\)[\s\S]*openHistoryItem\(item\)/);
  assert.match(appeal, /terminalAppealTitleRef[\s\S]*destination\.focus\(\{ preventScroll: true \}\)/);
  assert.match(appeal, /reviewerSnapshot === null && reviewerSnapshotUnavailable[\s\S]*读取失败，不是已验证的空历史/);
  assert.match(appeal, /history\?\.items\.length === 0[\s\S]*fresh 服务端快照已验证/);
  assert.match(appeal, /history\.has_more[\s\S]*has_more=true[\s\S]*has_more=false/);
  assert.match(appeal, /taskTarget\.read_kind === "HISTORY"[\s\S]*focusReviewHistoryTask\(taskTarget\)/);
  assert.match(appeal, /focusReviewHistoryTask[\s\S]*coordinatedRefreshReviewerWork\("MANUAL"[\s\S]*snapshot\.history\.items\.some/);
  assert.match(appeal, /setTerminalAppeal\(\(current\) => current\?\.appeal_id === candidate\.appeal_id \? current : null\)/);
  assert.match(appeal, /historyItemRefs\.current\.get\(candidate\.appeal_id\)[\s\S]*destination\.focus/);
});

test("restricted Appeal narratives remain component-memory-only, including unknown outcome recovery", async () => {
  const [appeal, contract] = await Promise.all([
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
    readFile(new URL("lib/app-contract.mjs", root), "utf8"),
  ]);
  assert.match(appeal, /const \[applicantStatement, setApplicantStatement\] = useState\(""\)/);
  assert.match(appeal, /const \[reviewerNote, setReviewerNote\] = useState\(""\)/);
  assert.match(appeal, /function isRestrictedNarrativeWrite[\s\S]*\/draft[\s\S]*\/review-draft/);
  assert.match(appeal, /if \(isRestrictedNarrativeWrite\(record\)\) \{[\s\S]*sessionStorage\.removeItem\(PENDING_KEY\)/);
  assert.match(appeal, /setApplicantStatement\(""\)/);
  assert.match(appeal, /setReviewerNote\(""\)/);
  assert.doesNotMatch(appeal, /localStorage|console\.(?:log|info|warn|error)|indexedDB/);
  assert.doesNotMatch(appeal, /URLSearchParams\([^)]*(?:applicantStatement|reviewerNote)/);
  assert.match(contract, /appealApplicantWrite\?\.\[2\] === "draft" \|\| appealReviewWrite\?\.\[2\] === "review-draft"\) return null/);
});
