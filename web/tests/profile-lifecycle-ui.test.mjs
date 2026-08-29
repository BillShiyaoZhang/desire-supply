import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const clientPath = new URL("../app/product-client.tsx", import.meta.url);

test("Creator lifecycle UI is capability-bound, dirty-safe, and archive-confirmed", async () => {
  const source = await readFile(clientPath, "utf8");
  assert.match(source, /createProfileLifecycleIntent\(\{/);
  assert.match(source, /if \(dirty\) \{[\s\S]*UNSAVED_PROFILE_CHANGES/);
  assert.match(source, /action === "ARCHIVE" && !profileArchiveConfirmed/);
  assert.match(source, /PROFILE_ARCHIVE_CONFIRMATION_REQUIRED/);
  assert.match(source, /resource\.capabilities\.includes\("PAUSE"\)/);
  assert.match(source, /resource\.capabilities\.includes\("RESUME"\)/);
  assert.match(source, /resource\.capabilities\.includes\("ARCHIVE"\)/);
  assert.match(source, /我理解归档不可恢复/);
  assert.match(source, /disabled=\{busy \|\| dirty \|\| !profileArchiveConfirmed\}/);
  assert.match(source, /暂停期间不会进入新的匹配；请先恢复画像/);
  assert.match(source, /归档后不再存在“当前版本”/);
});

test("Creator lifecycle 412 clears the old request and fresh-reads the Profile", async () => {
  const source = await readFile(clientPath, "utf8");
  const lifecycleRecovery = source.indexOf("&& isProfileLifecyclePath(record.intent.path)");
  const contentConflict = source.indexOf("const conflictSurface = parseThreeWayConflict");
  assert.ok(lifecycleRecovery > 0);
  assert.ok(contentConflict > lifecycleRecovery);
  const recoveryBlock = source.slice(lifecycleRecovery, contentConflict);
  assert.match(recoveryBlock, /persistPending\(null\)/);
  assert.match(recoveryBlock, /`\$\{ENDPOINTS\.profiles\}\/\$\{record\.object_id\}`/);
  assert.match(recoveryBlock, /parseEtaggedEditorResponse/);
  assert.match(recoveryBlock, /adoptResource\(refreshed, false\)/);
});
