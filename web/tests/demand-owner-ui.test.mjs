import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  dateTimeLocalToIso,
  editorResponseBindingMatches,
  expectedEditorResponseObjectId,
  persistEditorScratch,
} from "../lib/product-workspace-state.mjs";

const root = new URL("../", import.meta.url);

test("Demand Owner can always enter a dedicated new-demand screen", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const railStart = client.indexOf('<aside className="workspace-rail"');
  const railEnd = client.indexOf("</aside>", railStart);
  const rail = client.slice(railStart, railEnd);

  assert.ok(railStart >= 0 && railEnd > railStart);
  assert.match(rail, /canCreateDemand && <button[\s\S]*className="rail-create-button"[\s\S]*>＋ 新建需求<\/button>/);
  assert.doesNotMatch(rail, /!selected[\s\S]*rail-create-button/);
  assert.match(rail, /disabled=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null\}/);
  assert.match(client, /demandCreationOpen && canCreateDemand && <section className="demand-create-panel"/);
  assert.match(client, /!demandCreationOpen && !selected && !selectedAccount && !selectedFinanceReview/);
});

test("all editor-leaving navigation uses the same scratch guard", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const guardStart = client.indexOf("const prepareToLeaveSelectedEditor");
  const guardEnd = client.indexOf("\n\n  const adoptResource", guardStart);
  const guard = client.slice(guardStart, guardEnd);
  const start = client.indexOf("function beginDemandCreation()");
  const end = client.indexOf("\n\n  function createDemand", start);
  const action = client.slice(start, end);

  assert.ok(guardStart >= 0 && guardEnd > guardStart);
  assert.match(guard, /conflict !== null/);
  assert.match(guard, /CONFLICT_RESOLUTION_REQUIRED/);
  assert.ok(guard.indexOf("conflict !== null") < guard.indexOf("!dirty || !selected"));
  assert.match(guard, /!dirty \|\| !selected/);
  assert.match(guard, /persistEditorScratchToStorage\(sessionStorage, selected, sections\)/);
  assert.match(guard, /SCRATCH_PERSIST_FAILED/);
  assert.ok(start >= 0 && end > start);
  assert.match(action, /pendingRef\.current !== null/);
  assert.match(action, /logoutIntentRef\.current !== null/);
  assert.match(action, /!prepareToLeaveSelectedEditor\(\)/);
  assert.match(action, /setSelected\(null\)/);
  assert.match(action, /setDemandCreationOpen\(true\)/);
  assert.doesNotMatch(action, /performWrite|requestWorkspaceJson|fetch\(/);
  for (const entry of [
    ["switchWorkspace", "const switchWorkspace = useCallback", "\n\n  useEffect"],
    ["refreshWorkspaceSafely", "function refreshWorkspaceSafely()", "\n\n  const replaceResource"],
    ["openResource", "async function openResource", "\n\n  async function openAccount"],
    ["openAccount", "async function openAccount", "\n\n  async function reloadReviewQueue"],
    ["openRevalidatedFinanceCurrentAccountTask", "async function openRevalidatedFinanceCurrentAccountTask", "\n\n  async function recoverMissingCurrentAccountTaskResource"],
    ["openFinanceFundingReview", "async function openFinanceFundingReview", "\n\n  async function openFinanceFundingHistoryItem"],
    ["openFinanceFundingHistoryItem", "async function openFinanceFundingHistoryItem", "\n\n  function claimFinanceFundingReview"],
    ["claimFinanceFundingReview", "function claimFinanceFundingReview", "\n\n  function confirmFinanceFundingReview"],
    ["claimReview", "function claimReview", "\n\n  function verifyDemand"],
  ]) {
    const [label, startToken, endToken] = entry;
    const entryStart = client.indexOf(startToken);
    const entryEnd = client.indexOf(endToken, entryStart);
    assert.ok(entryStart >= 0 && entryEnd > entryStart, `${label} exists`);
    assert.match(client.slice(entryStart, entryEnd), /prepareToLeaveSelectedEditor\(\)/, `${label} is guarded`);
  }
});

test("scratch persistence reports storage and size failures instead of silently discarding", () => {
  const saved = new Map();
  const storage = { setItem: (key, value) => saved.set(key, value) };
  const resource = { resource_type: "DEMAND", object_id: "demand_internal_0000001", revision: 7 };
  const savedAt = new Date("2026-08-24T04:00:00.000Z");

  assert.equal(persistEditorScratch(storage, resource, { "/problem": "kept" }, savedAt), true);
  const encoded = saved.get("desire-pilot-scratch:v1:DEMAND:demand_internal_0000001");
  assert.deepEqual(JSON.parse(encoded), {
    version: 1,
    saved_at: savedAt.toISOString(),
    resource_type: "DEMAND",
    object_id: "demand_internal_0000001",
    base_revision: 7,
    sections: { "/problem": "kept" },
  });
  assert.equal(persistEditorScratch(storage, resource, { "/problem": "界".repeat(100_000) }, savedAt), false);
  assert.equal(persistEditorScratch({ setItem: () => { throw new Error("quota"); } }, resource, {}, savedAt), false);
});

test("confirmed creation accepts only the exact create sentinel and a real bound response", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n  async function beginSignIn", writeStart);
  const performWrite = client.slice(writeStart, writeEnd);

  assert.equal(expectedEditorResponseObjectId("DEMAND", "new_demand_internal"), undefined);
  assert.equal(expectedEditorResponseObjectId("CREATOR_PROFILE", "new_profile_internal"), undefined);
  assert.equal(expectedEditorResponseObjectId("DEMAND", "new_but_real_object_001"), "new_but_real_object_001");
  assert.equal(editorResponseBindingMatches("DEMAND", "new_demand_internal", "DEMAND", "demand_real_000000001"), true);
  assert.equal(editorResponseBindingMatches("DEMAND", "new_demand_internal", "DEMAND", "new_demand_internal"), false);
  assert.equal(editorResponseBindingMatches("DEMAND", "new_demand_internal", "DEMAND", "new_profile_internal"), false);
  assert.equal(editorResponseBindingMatches("DEMAND", "new_demand_internal", "CREATOR_PROFILE", "profile_real_000001"), false);
  assert.equal(editorResponseBindingMatches("DEMAND", "new_but_real_object_001", "DEMAND", "another_object_00001"), false);

  assert.match(performWrite, /expectedEditorResponseObjectId\(record\.resource_type, record\.object_id\)/);
  assert.match(performWrite, /editorResponseBindingMatches\(/);
  assert.doesNotMatch(performWrite, /object_id\.startsWith\("new_"\)/);
  assert.match(performWrite, /replaceResource\(resource\);[\s\S]*adoptResource\(resource, false\);[\s\S]*record\.object_id === "new_demand_internal"[\s\S]*setCreateReference\(""\)/);
  assert.match(client, /const adoptResource[\s\S]*setDemandCreationOpen\(false\)/);
  assert.match(client, /const clearWorkspaceObjects[\s\S]*setCreateReference\(""\)[\s\S]*setCreateExpiry\(defaultDemandExpiry\(\)\)/);
});

test("datetime-local defaults and submission preserve the local wall clock", async () => {
  const helperUrl = new URL("lib/product-workspace-state.mjs", root).href;
  const output = execFileSync(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { defaultDemandExpiry, dateTimeLocalToIso } from ${JSON.stringify(helperUrl)};
     const value = defaultDemandExpiry(Date.parse("2026-08-24T04:00:00.000Z"));
     process.stdout.write(JSON.stringify({ value, iso: dateTimeLocalToIso(value) }));`,
  ], {
    encoding: "utf8",
    env: { ...process.env, TZ: "Asia/Shanghai" },
  });

  assert.deepEqual(JSON.parse(output), {
    value: "2026-10-23T12:00",
    iso: "2026-10-23T04:00:00.000Z",
  });
  assert.throws(() => dateTimeLocalToIso("2026-02-30T12:00"), /INVALID_EXPIRY/);

  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const start = client.indexOf("function createDemand(event: FormEvent)");
  const end = client.indexOf("\n\n  function recordFindings", start);
  const create = client.slice(start, end);
  assert.match(create, /expiresAt: dateTimeLocalToIso\(createExpiry\)/);
  assert.doesNotMatch(create, /new Date\(createExpiry\)/);
});

test("object reads cannot race or overwrite a pending creation", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const openStart = client.indexOf("async function openResource(");
  const openEnd = client.indexOf("\n\n  async function openAccount", openStart);
  const open = client.slice(openStart, openEnd);
  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n  async function beginSignIn", writeStart);
  const write = client.slice(writeStart, writeEnd);

  assert.match(open, /busy[\s\S]*pendingRef\.current !== null[\s\S]*logoutIntentRef\.current !== null/);
  assert.match(open, /const readEpoch = resourceReadEpochRef\.current \+ 1/);
  assert.match(open, /resourceReadEpochRef\.current !== readEpoch[\s\S]*return;/);
  assert.match(write, /resourceReadEpochRef\.current \+= 1;[\s\S]*requestWorkspaceJson/);
  assert.match(client, /<ResourceGroup disabled=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null\}/);
  assert.match(client, /className="resource-link"[\s\S]*disabled=\{disabled\}/);
});

test("editor inputs lock for every in-flight or outcome-unknown write", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const mountStart = client.indexOf("{selected && <ResourceEditor");
  const mountEnd = client.indexOf("/>}", mountStart);
  const mount = client.slice(mountStart, mountEnd);
  const editorStart = client.indexOf("function ResourceEditor({");
  const editorEnd = client.indexOf("\n\nfunction StructuredSectionEditor", editorStart);
  const editor = client.slice(editorStart, editorEnd);

  assert.ok(mountStart >= 0 && mountEnd > mountStart);
  assert.match(mount, /busy=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null \|\| conflict !== null\}/);
  assert.ok(editorStart >= 0 && editorEnd > editorStart);
  assert.match(editor, /<fieldset[\s\S]*aria-busy=\{busy\}[\s\S]*aria-describedby=\{busy \? "editor-write-lock-status" : undefined\}[\s\S]*className="editor-write-scope"[\s\S]*disabled=\{busy\}/);
  assert.match(editor, /正在同步服务端事实、处理版本冲突或确认写入结果；编辑控件已锁定，避免新输入被响应覆盖。/);
  assert.match(editor, /<StructuredSectionEditor[\s\S]*<\/fieldset>/);
  assert.match(editor, /className="primary-button" disabled=\{!dirty \|\| !configuration \|\| editorIssues\.length > 0\}[^>]*>保存草稿<\/button>/);
});
