import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

function openingTags(source, component) {
  const matches = [...source.matchAll(new RegExp(`<${component}\\b([\\s\\S]*?)\\/>`, "g"))];
  assert.ok(matches.length > 0, `${component} must remain mounted by ProductClient`);
  return matches.map((match) => match[1]);
}

test("pilot shell gives keyed sibling workbenches distinct stable namespaces", async () => {
  const product = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const expectedKeys = new Map([
    ["ReviewHistoryPanel", "`review-history:${selectedWorkspace.workspace_id}`"],
    ["SessionManager", "`session-manager:${session.session.session_id}:${me.user_id}`"],
    ["TrustWorkbench", "`trust-workbench:${selectedWorkspace.workspace_id}`"],
    ["AppealWorkbench", "`appeal-workbench:${selectedWorkspace.workspace_id}`"],
  ]);

  const siblingKeys = [];
  for (const [component, expectedKey] of expectedKeys) {
    for (const tag of openingTags(product, component)) {
      const key = tag.match(/key=\{([^\n]+)\}/)?.[1];
      assert.equal(key, expectedKey, `${component} must use its own key namespace`);
    }
    siblingKeys.push(expectedKey);
  }

  assert.equal(new Set(siblingKeys).size, siblingKeys.length, "keyed pilot siblings must not share a key expression");
  assert.doesNotMatch(product, /<(?:ReviewHistoryPanel|TrustWorkbench|AppealWorkbench)\b[\s\S]*?key=\{selectedWorkspace\.workspace_id\}/);
});
