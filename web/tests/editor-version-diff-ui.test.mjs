import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("both Creator Profile and Demand history use one read-only loaded-version comparison", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const start = client.indexOf("function VersionComparison(");
  const end = client.indexOf("\n\nfunction ResourceEditor", start);
  const comparison = client.slice(start, end);
  const historyStart = client.indexOf('<section className="history-grid">');
  const historyEnd = client.indexOf("\n  </>;", historyStart);
  const history = client.slice(historyStart, historyEnd);

  assert.ok(start >= 0 && end > start);
  assert.match(history, /<VersionComparison key=\{resource\.object_id\} versions=\{resource\.versions\} \/>/);
  assert.match(comparison, /diffEditorVersionContent\(before\.content, after\.content\)/);
  assert.match(comparison, /比较基线/);
  assert.match(comparison, /比较目标/);
  assert.equal((comparison.match(/<select value=/g) ?? []).length, 2);
  assert.match(comparison, /setSelection\(\{/);
  assert.doesNotMatch(comparison, /disabled=\{[^}]*VersionId/);
  assert.match(comparison, /至少有两个已授权历史版本后才可比较/);
  assert.match(comparison, /所选版本的授权内容完全一致/);
  assert.match(comparison, /role="alert"/);
  assert.ok(comparison.indexOf("version-comparison__selectors") < comparison.indexOf("version-comparison__error"));
  assert.match(comparison, /entry\.type === "ADDED" \? "新增"/);
  assert.match(comparison, /entry\.path/);
});

test("comparison defaults to the latest two versions and survives loaded-version refreshes", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const defaultsStart = client.indexOf("function defaultVersionComparison(");
  const comparisonStart = client.indexOf("function VersionComparison(", defaultsStart);
  const comparisonEnd = client.indexOf("\n\nfunction ResourceEditor", comparisonStart);
  const defaults = client.slice(defaultsStart, comparisonStart);
  const comparison = client.slice(comparisonStart, comparisonEnd);

  assert.match(defaults, /left\.version_no - right\.version_no/);
  assert.match(defaults, /ordered\.at\(-2\)\?\.version_id/);
  assert.match(defaults, /ordered\.at\(-1\)\?\.version_id/);
  assert.match(comparison, /byId\.has\(selection\.beforeVersionId\)[\s\S]*defaults\.beforeVersionId/);
  assert.match(comparison, /byId\.has\(selection\.afterVersionId\)[\s\S]*defaults\.afterVersionId/);
  assert.match(comparison, /versions\.length < 2/);
  assert.doesNotMatch(comparison, /current_version|capabilities|status === "ARCHIVED"/);
});

test("comparison never performs IO or receives identity and authorization context", async () => {
  const [client, diffSource] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/editor-version-diff.mjs", root), "utf8"),
  ]);
  const start = client.indexOf("function VersionComparison(");
  const end = client.indexOf("\n\nfunction ResourceEditor", start);
  const comparison = client.slice(start, end);

  assert.match(comparison, /\{ versions \}: \{ versions: EditorVersion\[\] \}/);
  assert.doesNotMatch(comparison, /requestJson|requestWorkspaceJson|fetch\(|performWrite|onSave|onAdvance/);
  assert.doesNotMatch(comparison, /actor|role_codes|workspace|organization|membership/);
  assert.doesNotMatch(comparison, /JSON\.stringify|<pre|readonly-json/);
  assert.doesNotMatch(diffSource, /fetch\(|localStorage|sessionStorage|document\.|window\.|actor_id|role_codes/);
});

test("comparison styles expose responsive selectors, differences, equal, and error states", async () => {
  const css = await readFile(new URL("app/globals.css", root), "utf8");
  for (const className of [
    "version-comparison",
    "version-comparison__selectors",
    "version-comparison__equal",
    "version-comparison__error",
    "version-diff-list",
    "version-diff--added",
    "version-diff--removed",
    "version-diff--changed",
    "version-diff__values",
  ]) assert.match(css, new RegExp(`\\.${className.replaceAll("_", "\\_")}`));
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*version-comparison__selectors/);
});
