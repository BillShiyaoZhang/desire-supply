import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { DEMAND_EDITABLE_PATHS, PROFILE_EDITABLE_PATHS } from "../lib/app-contract.mjs";
import { buildEditorWorkflow } from "../lib/editor-workflow.mjs";

test("each authorized profile and demand section is reachable exactly once with at most four sections per step", () => {
  for (const [type, paths] of [["CREATOR_PROFILE", PROFILE_EDITABLE_PATHS], ["DEMAND", DEMAND_EDITABLE_PATHS]]) {
    const steps = buildEditorWorkflow(type, paths);
    assert.equal(steps.length, 5);
    assert.equal(steps.at(-1).id, "review");
    assert.deepEqual(steps.at(-1).paths, []);
    assert.deepEqual(steps.flatMap((step) => step.paths).sort(), [...paths].sort());
    for (const step of steps.slice(0, -1)) assert.ok(step.paths.length >= 2 && step.paths.length <= 4);
  }
});

test("capability changes remove inaccessible groups and retain unknown future paths without mutating inputs", () => {
  const paths = Object.freeze(["/ai", "/problem", "/future", "/future", "/extra", "/extra2", "/extra3", "/extra4"]);
  const steps = buildEditorWorkflow("DEMAND", paths);
  assert.deepEqual(steps.slice(0, 2).map((step) => step.id), ["outcome", "responsibility"]);
  assert.deepEqual(steps.flatMap((step) => step.paths).sort(), [...new Set(paths)].sort());
  assert.ok(steps.every((step) => step.paths.length <= 4));
  assert.deepEqual(buildEditorWorkflow("DEMAND", []).map((step) => step.id), ["review"]);
});

test("step changes preserve the controlled draft and all writes stay behind the busy lock and review", async () => {
  const source = await readFile(new URL("../app/product-client.tsx", import.meta.url), "utf8");
  const start = source.indexOf("function ResourceEditor(");
  const end = source.indexOf("\n\nfunction StructuredSectionEditor", start);
  const editor = source.slice(start, end);
  assert.match(editor, /aria-current=\{activeStep\.id === step\.id \? "step" : undefined\}/);
  assert.match(editor, /activeStep\.paths\.map/);
  assert.match(editor, /encoded=\{sections\[path\] \?\? "null"\}/);
  assert.match(editor, /onChange=\{\(value\) => onSectionChange\(path, serializeStructuredSection\(value\)\)\}/);
  assert.match(editor, /aria-busy=\{busy\}[\s\S]*disabled=\{busy\}/);
  assert.match(editor, /activeStep\.id === "review" && <div className="editor-actions">/);
  assert.doesNotMatch(editor, /aria-current="step"|已完成步骤|defaultValue=/);
});
