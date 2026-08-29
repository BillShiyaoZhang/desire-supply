import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("structured editors use the server-reviewed choice catalog and keep legacy values explicit", async () => {
  const [client, fields, css, contract] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/editor-fields.mjs", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
    readFile(new URL("lib/app-contract.mjs", root), "utf8"),
  ]);

  assert.match(client, /<StructuredSectionEditor[\s\S]*configuration=\{configuration\}/);
  assert.match(client, /resolveEditorChoice\(configuration, resourceType, canonicalPath\)/);
  assert.match(client, /<option disabled value=\{value\}>旧值（当前不可选）：/);
  assert.match(client, /aria-invalid=\{!known\}/);
  assert.match(client, /来源：\{sources\.join\("、"\)\}/);
  assert.match(client, /disabled=\{additionUnavailable\}/);
  assert.match(client, /现有旧值仍可逐项移除；当前目录不允许新增/);
  assert.match(client, /arrayItemTemplate\(resourceType, canonicalPath, value, configuration\)/);
  assert.match(client, /structuredContentIssues\(selected\.resource_type, sections, configuration\)/);
  assert.match(client, /structuredContentIssues\(resource\.resource_type, sections, configuration\)/);
  assert.match(client, /function advanceResource[\s\S]*structuredContentIssues\(selected\.resource_type, sections, configuration\)/);
  assert.match(client, /<fieldset[\s\S]{0,240}disabled=\{busy\}\s*>/);
  assert.match(client, /includes\("PUBLISH"\)[\s\S]{0,240}disabled=\{dirty \|\| !configuration \|\| editorIssues\.length > 0\}/);
  assert.match(client, /includes\("SUBMIT"\)[\s\S]{0,240}disabled=\{dirty \|\| !configuration \|\| editorIssues\.length > 0\}/);

  assert.match(fields, /normalizeEditorChoicePath/);
  assert.match(fields, /\? "\*" : segment/);
  assert.match(fields, /CHOICE_UNAVAILABLE/);
  assert.match(fields, /CHOICE_CATALOG_UNAVAILABLE/);
  assert.match(fields, /TAXONOMY_BUNDLE_NODE: "分类节点"/);
  assert.match(fields, /INTERNAL_SANDBOX_POLICY: "沙盒策略"/);
  assert.match(fields, /INTERNAL_SANDBOX_PRESET: "预设"/);
  assert.match(css, /choice-field/);

  for (const currentDefault of ["GENERAL", "EXPLORATION", "GENERAL_RESEARCH", "VALIDATION"]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${currentDefault}\\b`));
  }
  for (const reviewedDefault of [
    "DOMAIN.SOFTWARE", "PROBLEM.OPERATIONS", "SKILL.SYSTEMS_ANALYSIS", "TASK.ANALYSIS", "SYNTHETIC_USER",
  ]) assert.match(contract, new RegExp(reviewedDefault.replaceAll(".", "\\.")));
});
