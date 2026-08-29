import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("412 UI performs explicit section choices without raw JSON or an automatic write", async () => {
  const [client, css] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
  ]);
  const panelStart = client.indexOf("function ConflictPanel({");
  const panel = client.slice(panelStart);

  assert.ok(panelStart >= 0);
  assert.match(client, /key=\{`\$\{selected\.resource_type\}:\$\{conflict\.currentEtag\}:\$\{conflict\.current\.version_id \?\? "none"\}`\}/);
  assert.match(panel, /planEditorConflictMerge\([\s\S]*conflict\.base\.content[\s\S]*conflict\.current\.content[\s\S]*conflict\.yours\.content[\s\S]*choices/);
  assert.match(panel, /section\.state === "COLLISION"/);
  assert.match(panel, /type="radio"/);
  assert.match(panel, /checked=\{choices\[section\.path\] === "SERVER"\}/);
  assert.match(panel, /checked=\{choices\[section\.path\] === "MINE"\}/);
  assert.match(panel, /disabled=\{!merge\.complete \|\| merge\.content === null\}/);
  assert.match(panel, /onClick=\{\(\) => onResolve\(choices\)\}/);
  assert.match(panel, /role="alert"[\s\S]*onClick=\{onDiscard\}/);
  assert.doesNotMatch(panel, /defaultChecked|<pre>|JSON\.stringify|performWrite\(|requestWorkspaceJson\(|fetch\(/);
  assert.doesNotMatch(panel, /保留我的内容并换到新基线/);

  for (const selector of [
    ".conflict-version-summary",
    ".conflict-auto-merge",
    ".conflict-section-list",
    ".conflict-section-choice",
    ".conflict-choice-grid",
    ".conflict-version-option.is-selected",
  ]) {
    assert.ok(css.includes(selector), `${selector} is styled`);
  }
  assert.match(css, /\.conflict-version-summary, \.conflict-choice-grid \{ grid-template-columns: 1fr; \}/);
});

test("an unresolved conflict blocks leaving and locks the underlying editor", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const guardStart = client.indexOf("const prepareToLeaveSelectedEditor");
  const guardEnd = client.indexOf("\n\n  const adoptResource", guardStart);
  const guard = client.slice(guardStart, guardEnd);
  const mountStart = client.indexOf("{selected && <ResourceEditor");
  const mountEnd = client.indexOf("/>}", mountStart);
  const mount = client.slice(mountStart, mountEnd);

  assert.match(guard, /if \(conflict !== null\)[\s\S]*CONFLICT_RESOLUTION_REQUIRED[\s\S]*return false/);
  assert.ok(guard.indexOf("conflict !== null") < guard.indexOf("!dirty || !selected"));
  assert.match(mount, /busy=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null \|\| conflict !== null\}/);
});
