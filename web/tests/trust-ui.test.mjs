import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

function evaluateLocalDateTime({ now, timezone }) {
  const helperUrl = new URL("lib/product-workspace-state.mjs", root).href;
  const source = `
    import { dateTimeLocalToIso, formatDateTimeLocal } from ${JSON.stringify(helperUrl)};
    const local = formatDateTimeLocal(new Date(${JSON.stringify(now)}));
    const iso = dateTimeLocalToIso(local);
    process.stdout.write(JSON.stringify({ local, iso }));
  `;
  return JSON.parse(execFileSync(process.execPath, [
    "--input-type=module",
    "--eval",
    source,
  ], {
    encoding: "utf8",
    env: { ...process.env, TZ: timezone },
  }));
}

test("Trust incident datetime-local defaults and submission preserve the browser wall clock", async () => {
  const cases = [
    {
      timezone: "UTC",
      now: "2026-01-15T12:30:00.000Z",
      local: "2026-01-15T12:30",
    },
    {
      timezone: "Asia/Shanghai",
      now: "2026-01-15T12:30:00.000Z",
      local: "2026-01-15T20:30",
    },
    {
      timezone: "America/New_York",
      now: "2026-01-15T12:30:00.000Z",
      local: "2026-01-15T07:30",
    },
  ];
  for (const scenario of cases) {
    const result = evaluateLocalDateTime(scenario);
    assert.equal(result.local, scenario.local, scenario.timezone);
    assert.equal(result.iso, scenario.now, scenario.timezone);
  }

  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  const converterStart = trust.indexOf("function toUtc(value: string)");
  const converterEnd = trust.indexOf("\n\nfunction toggleCode", converterStart);
  const converter = trust.slice(converterStart, converterEnd);
  assert.ok(converterStart >= 0 && converterEnd > converterStart);
  assert.match(trust, /import \{\s*dateTimeLocalToIso,\s*formatDateTimeLocal,\s*\} from "\.\.\/lib\/product-workspace-state\.mjs"/);
  assert.match(trust, /useState\(\(\) => formatDateTimeLocal\(new Date\(\)\)\)/);
  assert.match(converter, /return dateTimeLocalToIso\(value\)/);
  assert.match(converter, /throw new TypeError\("INVALID_TRUST_TIMESTAMP"\)/);
  assert.doesNotMatch(converter, /new Date\(value\)|\.toISOString\(\)/);
  assert.doesNotMatch(trust, /new Date\(\)\.toISOString\(\)\.slice\(0, 16\)/);
  assert.match(trust, /incidentStartedAt: toUtc\(incidentStartedAt\)/);
  assert.match(trust, /incidentEndedAt: incidentEndedAt \? toUtc\(incidentEndedAt\) : null/);
});

test("ProductClient exposes the role-scoped Trust workbench and one global write latch", async () => {
  const [product, trust, route] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("app/v1/app/[...path]/route.ts", root), "utf8"),
  ]);

  assert.match(product, /import \{ TrustWorkbench, type TrustCaseHistoryTaskTarget \} from "\.\/trust-workbench"/);
  assert.match(product, /selectedWorkspace\?\.role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(product, /selectedWorkspace\?\.role_codes\.includes\("TRUST_OFFICER"\)/);
  assert.match(product, /const claimTrustWrite = useCallback/);
  assert.match(product, /pendingRef\.current = record;[\s\S]*setPendingOwner\("TRUST"\)/);
  assert.match(product, /writeLocked=\{busy \|\| logoutIntent !== null \|\| \(pendingOwner !== null && pendingOwner !== "TRUST"\)\}/);
  assert.match(route, /export const GET = handle/);
  assert.match(route, /export const POST = handle/);
  assert.match(route, /export const PUT = handle/);

  for (const phrase of [
    "从我的需求中选择举报对象", "我的举报与处理结果", "重新发现", "加载更多",
    "诊断：按报告 ID 读取", "案件领取队列", "高风险解除复核",
    "领取案件", "领取解除复核", "读取已分配详情", "释放当前分配", "分诊草稿",
    "发布分诊", "设置短期保护 Hold", "解除当前 Hold", "发布不可变初始结论",
    "第二名 TRUST_OFFICER", "服务端派生", "处理结果", "申诉资格", "申诉截止",
    "我的已完成 Trust 案件", "has_more=", "服务端还有更早的本人完成记录",
  ]) assert.match(trust, new RegExp(phrase));

  assert.match(trust, /canSubmitReport = workspace\.role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(trust, /canOperateCases = workspace\.workspace_kind === "PLATFORM"[\s\S]*workspace\.role_codes\.includes\("TRUST_OFFICER"\)/);
  assert.doesNotMatch(trust, /trust_officer_01|trust_officer_02/);
});

test("Trust writes parse receipt-safe commands, then perform authorized fresh reads", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  for (const symbol of [
    "createTrustReportIntent", "createTrustCaseClaimIntent", "createTrustAssignmentReleaseIntent",
    "createTrustTriageDraftIntent", "createTrustTriagePublishIntent", "createTrustHoldIntent",
    "createTrustHoldReleaseClaimIntent", "createTrustHoldReleaseIntent", "createTrustOutcomeIntent",
    "parseTrustCommandEnvelope", "parseTrustReportEnvelope", "parseTrustQueueEnvelope",
    "parseTrustHoldReleaseQueueEnvelope", "parseTrustOwnReportListEnvelope", "parseTrustCaseEnvelope",
  ]) assert.match(trust, new RegExp(symbol));

  assert.match(trust, /const committed = parseTrustCommandEnvelope\(result\.value\)/);
  assert.match(trust, /result\.etag !== null/);
  assert.match(trust, /fresh\.report_id !== committed\.report_id/);
  assert.match(trust, /freshReportList = await readOwnReportPage\(null/);
  assert.match(trust, /page\.items\.some\(\(item\) => item\.report_id === committed\.report_id\)/);
  assert.match(trust, /commitOwnReportFirstPage\(freshReportList\);\s*commitReport\(stagedReport\)/);
  assert.match(trust, /fresh\.aggregate_version < committed\.aggregate_version/);
  assert.match(trust, /path\.endsWith\("\/assignment\/release"\)[\s\S]*await refreshQueues\(\{/);
  assert.match(trust, /holdRelease[\s\S]*await refreshQueues\(\{/);
  assert.doesNotMatch(trust, /returned\.entity_tag|items\.some\(\(item\) => item\.hold_id === committed\.hold_id\)/);
  assert.match(trust, /expectedCommandEvent\(record\.intent\.path\)/);
  assert.doesNotMatch(trust, /parseTrustCaseEnvelope\(result\.value\)/);
});

test("Trust triage draft reports a missing restricted note without relying on native validation", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  assert.match(trust, /function saveTriageDraft\(event: FormEvent\)/);
  assert.match(trust, /if \(!restrictedNote\.trim\(\)\) \{[\s\S]*TRUST_RESTRICTED_NOTE_REQUIRED[\s\S]*页面没有发送空白草稿/);
  assert.match(trust, /<form className="workbench-card sensitive-card" noValidate onSubmit=\{saveTriageDraft\}>/);
  assert.match(trust, /受限备注（必填、只写、仅内存）/);
});

test("Trust pending recovery is exclusive and queue refreshes are busy, handled, and atomic", async () => {
  const [trust, styles] = await Promise.all([
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
  ]);

  assert.match(trust, /const \[queueSnapshot, setQueueSnapshot\] = useState<TrustQueueSnapshot>/);
  assert.match(trust, /const \[caseProjection, holdProjection, assignmentProjection, historyProjection\] = await Promise\.all\(\[/);
  assert.match(trust, /setQueueSnapshot\(snapshot\)/);
  assert.doesNotMatch(trust, /setQueue\(|setHoldReleaseQueue\(|setAssignments\(/);

  assert.match(trust, /const \[queueRefreshCoordinator\] = useState\(createAtomicRefreshCoordinator\)/);
  assert.match(trust, /const coordinatedRefreshQueues = useCallback\([\s\S]*queueRefreshCoordinator\.run\(\{/);
  assert.match(trust, /load: loadQueueSnapshot,\s*isValid: \(\) => isReadGenerationValid\(origin\),\s*validate: options\.validate,\s*commit: \(snapshot\) => \{\s*commitQueueSnapshot\(snapshot\);\s*options\.afterCommit\?\.\(snapshot\)/);
  assert.match(trust, /const manuallyRefreshQueues = useCallback\(async \(\) => \{[\s\S]*await coordinatedRefreshQueues\("MANUAL"\)/);
  assert.match(trust, /useEffect\(\(\) => \{[\s\S]*coordinatedRefreshQueues\("INITIAL"\)/);
  assert.match(trust, /setBusy: \(value\) => \{\s*setRefreshing\(value\)/);
  assert.match(trust, /onError: \(caught\) => \{[\s\S]*setError\(failure\(caught\)\)/);
  assert.match(trust, /onClick=\{\(\) => void manuallyRefreshQueues\(\)\}/);
  assert.doesNotMatch(trust, /onClick=\{\(\) => void (?:load|refresh)Queue(?:Snapshot|s)?\(\)\}/);

  assert.match(trust, /busy: busy \|\| reading \|\| refreshing \|\| !recoveryChecked/);
  assert.match(trust, /<fieldset[\s\S]*aria-disabled=\{actionLocked\}[\s\S]*disabled=\{actionLocked\}/);
  const pendingPanelAt = trust.indexOf("TRUST WRITE OUTCOME UNKNOWN");
  const lockedScopeAt = trust.indexOf('className={actionLocked ? "pending-write-scope');
  assert.ok(pendingPanelAt >= 0 && lockedScopeAt > pendingPanelAt);
  const recoverySurface = trust.slice(pendingPanelAt, lockedScopeAt);
  assert.match(recoverySurface, /performWrite\(pending\)/);
  assert.match(recoverySurface, /clearPending\(pending\)/);
  assert.match(styles, /\.pending-write-scope--locked \{[^}]*opacity:[^}]*filter:/);
  assert.match(styles, /\.pending-write-scope--locked, \.pending-write-scope--locked \* \{ cursor: not-allowed; \}/);
});

test("Trust checks recovery before initial GET and fails closed at every read boundary", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  const recoveryAt = trust.indexOf("const recovered = parsePendingIntent");
  const checkedAt = trust.indexOf("setRecoveryChecked(true)", recoveryAt);
  const initialAt = trust.indexOf('void coordinatedRefreshQueues("INITIAL")');
  assert.ok(recoveryAt >= 0 && checkedAt > recoveryAt && initialAt > checkedAt);
  assert.doesNotMatch(trust, /setTimeout/);
  assert.match(trust, /if \(\(writeLocked \|\| pending !== null\) && !controlledRefreshActive\.current\) \{[\s\S]{0,160}queueRefreshCoordinator\.invalidate\(\);\s*detailReadCoordinator\.invalidate\(\)/);
  assert.match(trust, /setReading\(false\);\s*setRefreshing\(false\)/);
  assert.match(trust, /useLayoutEffect\(\(\) => \{\s*return \(\) => \{\s*detailReadCoordinator\.invalidate\(\);\s*queueRefreshCoordinator\.invalidate\(\)/);
  assert.match(trust, /if \(!recoveryChecked \|\| busy \|\| reading \|\| refreshing\) return true;/);

  for (const handler of ["manuallyRefreshQueues", "refreshOwnReports", "lookupReport", "openOwnedReport", "openAssignedCase", "openDiscoveredCase", "openDiscoveredHold"]) {
    const declaration = ["manuallyRefreshQueues", "refreshOwnReports"].includes(handler) ? `const ${handler}` : `function ${handler}`;
    const start = trust.indexOf(declaration);
    assert.ok(start >= 0, `${handler} must exist`);
    assert.match(trust.slice(start, start + 380), /rejectNonRecoveryIfLocked\(\)/, `${handler} must fail closed on recovery, global lock, pending, and busy`);
  }
});

test("Trust INITIAL reads re-arm through state after lock invalidation and queues never render an unverified zero", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");

  assert.match(trust, /const \[initialRefreshStarted, setInitialRefreshStarted\] = useState\(false\)/);
  assert.match(trust, /const \[ownReportInitialStarted, setOwnReportInitialStarted\] = useState\(false\)/);
  assert.doesNotMatch(trust, /ownReportInitialStarted\s*=\s*useRef/);

  const ownRefreshAt = trust.indexOf("const refreshOwnReports");
  const queueRefreshAt = trust.indexOf("const coordinatedRefreshQueues", ownRefreshAt);
  assert.ok(ownRefreshAt >= 0 && queueRefreshAt > ownRefreshAt);
  const ownRefresh = trust.slice(ownRefreshAt, queueRefreshAt);
  assert.match(ownRefresh, /if \(!result\.ok && "stale" in result && origin === "INITIAL"\) \{\s*setOwnReportInitialStarted\(false\)/);

  const queueRefreshEnd = trust.indexOf("const refreshQueues", queueRefreshAt);
  assert.ok(queueRefreshEnd > queueRefreshAt);
  const queueRefresh = trust.slice(queueRefreshAt, queueRefreshEnd);
  assert.match(queueRefresh, /const result = await queueRefreshCoordinator\.run\(\{/);
  assert.match(queueRefresh, /if \(!result\.ok && "stale" in result && origin === "INITIAL"\) \{\s*setInitialRefreshStarted\(false\)/);
  assert.match(queueRefresh, /return result/);

  assert.match(trust, /\|\| initialRefreshStarted[\s\S]{0,500}coordinatedRefreshQueues\("INITIAL"\)[\s\S]{0,220}\}, \[[^\]]*initialRefreshStarted/);
  assert.match(trust, /\|\| ownReportInitialStarted[\s\S]{0,500}setOwnReportInitialStarted\(true\);\s*void refreshOwnReports\("INITIAL"\)[\s\S]{0,220}\}, \[[^\]]*ownReportInitialStarted/);

  assert.match(trust, /const \[queueSnapshotLoaded, setQueueSnapshotLoaded\] = useState\(false\)/);
  assert.match(trust, /const \[queueSnapshotUnavailable, setQueueSnapshotUnavailable\] = useState\(false\)/);
  assert.match(trust, /ownReportsLoaded && ownReportList !== null \? ownReportList\.items\.length : "—"/);
  assert.doesNotMatch(trust, /ownReportList\?\.items\.length \?\? 0/);
  const commitAt = trust.indexOf("const commitQueueSnapshot");
  const loadCaseAt = trust.indexOf("const loadCase", commitAt);
  const queueCommit = trust.slice(commitAt, loadCaseAt);
  assert.match(queueCommit, /setQueueSnapshot\(snapshot\);\s*setQueueSnapshotLoaded\(true\);\s*setQueueSnapshotUnavailable\(false\)/);
  assert.match(queueRefresh, /if \(!queueSnapshotLoaded\) setQueueSnapshotUnavailable\(true\)/);

  for (const [collection, unavailableCopy] of [
    ["assignments", "活动分配当前不可用；这不代表没有分配。"],
    ["queue", "案件队列当前不可用；这不代表没有未领取案件。"],
    ["holdReleaseQueue", "高风险解除复核当前不可用；这不代表没有待复核项目。"],
  ]) {
    assert.match(trust, new RegExp(`queueSnapshotLoaded && ${collection}\\.length === 0`));
    assert.match(trust, new RegExp(`!queueSnapshotLoaded && queueSnapshotUnavailable[^\\n]*${unavailableCopy}`));
    assert.doesNotMatch(trust, new RegExp(`\\{${collection}\\.length === 0 &&`));
  }
});

test("owned-report pagination keeps per-page ETags and diagnostic reads clear stale detail", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");

  const collectionAt = trust.indexOf("type TrustOwnReportCollection");
  const detailOriginAt = trust.indexOf("type DetailReadOrigin", collectionAt);
  assert.ok(collectionAt >= 0 && detailOriginAt > collectionAt);
  const collection = trust.slice(collectionAt, detailOriginAt);
  assert.match(collection, /page_entity_tags: string\[\]/);
  assert.doesNotMatch(collection, /\bentity_tag\s*:/);

  const firstPageAt = trust.indexOf("const commitOwnReportFirstPage");
  const readCaseAt = trust.indexOf("const readCase", firstPageAt);
  const firstPageCommit = trust.slice(firstPageAt, readCaseAt);
  assert.match(firstPageCommit, /setOwnReportList\(\{\s*items: page\.items,\s*next_cursor: page\.next_cursor,\s*page_entity_tags: \[page\.entity_tag\]/);
  assert.doesNotMatch(firstPageCommit, /\bentity_tag\s*:\s*page\.entity_tag/);

  const refreshAt = trust.indexOf("const refreshOwnReports");
  const refreshEnd = trust.indexOf("const coordinatedRefreshQueues", refreshAt);
  const pagination = trust.slice(refreshAt, refreshEnd);
  assert.match(pagination, /page_entity_tags: \[\.\.\.prior!\.page_entity_tags, page\.entity_tag\]/);
  assert.doesNotMatch(pagination, /\bentity_tag\s*:\s*page\.entity_tag/);

  const lookupAt = trust.indexOf("async function lookupReport");
  const openOwnedAt = trust.indexOf("async function openOwnedReport", lookupAt);
  assert.ok(lookupAt >= 0 && openOwnedAt > lookupAt);
  const lookup = trust.slice(lookupAt, openOwnedAt);
  const readAt = lookup.indexOf('await runDetailRead("INTERACTIVE"');
  assert.ok(readAt > 0);
  assert.match(lookup.slice(0, readAt), /setError\(null\);\s*setOwnReport\(null\)/);
  assert.match(lookup, /onError: \(caught\) => \{\s*setOwnReport\(null\);\s*setError\(failure\(caught\)\)/);
});

test("Trust detail GETs use one invalidatable coordinator while owned post-write reads stay controlled", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  assert.match(trust, /const \[detailReadCoordinator\] = useState\(createAtomicRefreshCoordinator\)/);
  assert.match(trust, /const runDetailRead = useCallback[\s\S]*detailReadCoordinator\.run\(\{[\s\S]*isValid: \(\) => isReadGenerationValid\(origin\)/);
  assert.equal((trust.match(/runDetailRead\("INTERACTIVE"/g) ?? []).length, 6);
  assert.equal((trust.match(/runDetailRead\("POST_WRITE"/g) ?? []).length, 4);
  assert.equal((trust.match(/setBusy\(true\)/g) ?? []).length, 1, "only writes own write-busy; reads own generation-safe reading state");
  assert.match(trust, /controlledRefreshActive\.current = true;\s*settlePendingForRefresh\(\)/);
  assert.match(trust, /finally \{\s*controlledRefreshActive\.current = false;\s*setBusy\(false\)/);

  for (const loader of ["loadCase", "loadAssignedHold", "loadReport", "loadOwnReportPage"]) {
    const start = trust.indexOf(`const ${loader}`);
    const end = trust.indexOf("\n  const ", start + 8);
    const body = trust.slice(start, end);
    assert.match(body, /await request\(/, `${loader} must perform the GET`);
    assert.doesNotMatch(body, /setSelected|setOwnReport|setNotice|setError/, `${loader} must stage without committing UI state`);
  }
});

test("Trust validates receipt-specific post-write snapshots before its single UI commit", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  const validatorAt = trust.indexOf("function validateTrustPostWriteSnapshot");
  const pendingRecordAt = trust.indexOf("function pendingRecord", validatorAt);
  const validator = trust.slice(validatorAt, pendingRecordAt);
  for (const eventType of [
    "TrustCaseClaimed",
    "TrustCaseAssignmentReleased",
    "TrustHoldReleaseClaimed",
    "SafetyHoldReleased",
    "TrustCaseOutcomePublished",
  ]) assert.match(validator, new RegExp(eventType));
  assert.match(validator, /INVALID_TRUST_QUEUE_SNAPSHOT_BINDING/);

  const refreshAt = trust.indexOf("await refreshQueues({");
  const releaseAt = trust.indexOf("releaseWrite(record)", refreshAt);
  const postWriteRefresh = trust.slice(refreshAt, releaseAt);
  assert.match(postWriteRefresh, /validate: \(snapshot\) => validateTrustPostWriteSnapshot\(/);
  assert.match(postWriteRefresh, /afterCommit: \(snapshot\) =>/);
  assert.match(postWriteRefresh, /commitAssignedHold\(freshHold\)/);
  assert.match(postWriteRefresh, /commitCase\(freshCase\)/);
  assert.match(trust, /const refreshReleasedHoldCase = holdRelease !== null && record\.resource_type === "TRUST_CASE"/);
  assert.match(trust, /!holdRelease \|\| refreshReleasedHoldCase[\s\S]*fresh\.active_hold !== null[\s\S]*INVALID_TRUST_RELEASED_HOLD_STILL_ACTIVE/);
  assert.match(validator, /expectsCaseAssignmentAfterHoldRelease && \(caseQueued \|\| !caseAssigned\)/);
  assert.match(postWriteRefresh, /if \(holdRelease && !refreshReleasedHoldCase\) setSelectedCase\(null\)/);
  const nonReportSettleAt = trust.indexOf("settlePendingForRefresh()", trust.indexOf("const holdClaim", validatorAt));
  assert.doesNotMatch(trust.slice(nonReportSettleAt, refreshAt), /commitCase\(|commitAssignedHold\(|setNotice\([^)]*已确认/);
  assert.match(trust, /if \(writeConfirmed\) \{\s*clearPending\(record\);\s*setError\(\{ status: 503, code: "TRUST_POST_COMMIT_REFRESH_FAILED"/);
});

test("Demand Owner chooses from the already-authorized demand projection instead of pasting identifiers", async () => {
  const [product, trust] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
  ]);

  for (const phrase of [
    "从我的需求中选择举报对象",
    "当前工作区的需求清单不可用；页面没有把失败显示为零。",
    "当前没有处于可举报状态且带有当前版本的需求。",
    "可举报需求（必须明确选择）",
    "提交时服务端会再次核对所有权、状态、精确版本和举报期限",
    "我的举报与处理结果",
    "列表摘要未被当作详情或申诉依据",
    "刷新、重新 bootstrap 或重新登录后，可从“我的举报与处理结果”重新发现来源",
    "加载更多",
    "诊断：按报告 ID 读取",
  ]) assert.match(trust, new RegExp(phrase));

  assert.match(product, /<TrustWorkbench[\s\S]{0,500}demands=\{demands\}[\s\S]{0,200}demandsAvailable=\{demandScope\}/);
  assert.match(trust, /const reportTargets = canSubmitReport \? demands\.filter\(isReportableDemand\) : \[\]/);
  assert.match(trust, /resource\.resource_type === "DEMAND"[\s\S]*resource\.current_version !== null[\s\S]*TRUST_REPORTABLE_DEMAND_STATUSES\.has\(resource\.status\)/);
  assert.match(trust, /reportTargets\.map\(\(target\) =>/);
  assert.match(trust, /type="radio"/);
  assert.match(trust, /value=\{target\.current_version\.version_id\}/);
  assert.match(trust, /item\.current_version\.version_id === selectedReportTargetVersionId/);
  assert.match(trust, /\) \?\? null;/);
  assert.doesNotMatch(trust, /reportTargets\[0\]/);
  assert.match(trust, /demandId: target\.object_id/);
  assert.match(trust, /demandVersionId: target\.current_version\.version_id/);
  assert.match(trust, /evidenceReferenceIds: \[target\.current_version\.version_id\]/);
  assert.match(trust, /if \(!demandsAvailable \|\| !target\)/);
  assert.doesNotMatch(trust, /report-targets|parseTrustReportTargetsEnvelope|readReportTargets/);

  assert.match(trust, /request\(`\$\{TRUST_ROOT\}\/reports\?\$\{query\.toString\(\)\}`\)/);
  assert.match(trust, /parseTrustOwnReportListEnvelope\(response\.value\)/);
  assert.match(trust, /page\.items\.some\(\(item\) => knownIds\.has\(item\.report_id\)\)/);
  assert.match(trust, /INVALID_TRUST_REPORT_CURSOR_CYCLE/);
  assert.match(trust, /onClick=\{\(\) => void openOwnedReport\(item\)\}/);
  assert.match(trust, /load: \(\) => loadReport\(item\.report_id\)/);
  assert.match(trust, /fresh\.demand_id !== item\.demand_id/);
  assert.doesNotMatch(trust, /Trust8 discovery（尚未实现）/);

  assert.doesNotMatch(trust, /<label>Demand ID<input/);
  assert.doesNotMatch(trust, /<label>精确 Demand version ID<input/);
  assert.doesNotMatch(trust, /<label>合成证据引用 ID<input/);
  assert.match(product, /<TrustWorkbench[\s\S]{0,500}key=\{`trust-workbench:\$\{selectedWorkspace\.workspace_id\}`\}/);
});

test("restricted_note remains write-only and never enters browser persistence", async () => {
  const [trust, contract] = await Promise.all([
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("lib/app-contract.mjs", root), "utf8"),
  ]);
  assert.match(trust, /function isRestrictedNoteWrite[\s\S]*\/triage-draft/);
  assert.match(trust, /if \(isRestrictedNoteWrite\(record\)\) \{[\s\S]*sessionStorage\.removeItem\(PENDING_KEY\);[\s\S]*return;/);
  assert.doesNotMatch(trust, /sessionStorage\.setItem\([^\n]*restrictedNote/);
  assert.doesNotMatch(trust, /localStorage|console\.(?:log|info|warn|error)|indexedDB/);
  assert.match(trust, /setRestrictedNote\(""\)/);
  assert.match(trust, /sealed_note_reference/);
  assert.match(trust, /sealed_note_sha256/);
  assert.match(contract, /body: \{ expected_draft_version: exact\.triage_draft\.triage_version \}/);
  assert.doesNotMatch(contract, /TRUST_SAFE_TRIAGE_KEYS[\s\S]{0,300}"restricted_note"/);
});
