import assert from "node:assert/strict";
import test from "node:test";
import {
  DEMAND_EDITABLE_PATHS,
  PROFILE_EDITABLE_PATHS,
} from "../lib/app-contract.mjs";
import { planEditorConflictMerge } from "../lib/editor-conflict-merge.mjs";

function completeContent(resourceType, overrides = {}) {
  const paths = resourceType === "CREATOR_PROFILE"
    ? PROFILE_EDITABLE_PATHS
    : DEMAND_EDITABLE_PATHS;
  return {
    ...Object.fromEntries(paths.map((path) => [path.slice(1), null])),
    ...overrides,
  };
}

test("non-overlapping server and user section edits merge automatically in schema order", () => {
  const base = completeContent("DEMAND", {
    problem: { background: "旧问题" },
    scope: { deliverables: [] },
    budget: { maximum_amount_minor: 100 },
  });
  const current = {
    ...base,
    scope: { deliverables: [{ item_id: "one", description: "服务器新增" }] },
  };
  const yours = {
    ...base,
    budget: { maximum_amount_minor: 200 },
  };

  const plan = planEditorConflictMerge("DEMAND", base, current, yours);

  assert.equal(plan.complete, true);
  assert.deepEqual(plan.unresolvedPaths, []);
  assert.deepEqual(plan.content.problem, { background: "旧问题" });
  assert.deepEqual(plan.content.scope, {
    deliverables: [{ item_id: "one", description: "服务器新增" }],
  });
  assert.deepEqual(plan.content.budget, { maximum_amount_minor: 200 });
  assert.equal(plan.sections.length, 13);
  assert.deepEqual(plan.sections.slice(0, 7).map(({ path, state }) => ({ path, state })), [
    { path: "/problem", state: "UNCHANGED" },
    { path: "/scope", state: "SERVER_ONLY" },
    { path: "/acceptance", state: "UNCHANGED" },
    { path: "/skills", state: "UNCHANGED" },
    { path: "/matching", state: "UNCHANGED" },
    { path: "/schedule", state: "UNCHANGED" },
    { path: "/budget", state: "MINE_ONLY" },
  ]);
});

test("the same change on both sides is merged without asking", () => {
  const base = completeContent("CREATOR_PROFILE", { availability: null });
  const current = completeContent("CREATOR_PROFILE", {
    availability: { weekly_hours: 8 },
  });
  const plan = planEditorConflictMerge("CREATOR_PROFILE", base, current, current);

  assert.equal(plan.complete, true);
  assert.deepEqual(plan.content.availability, { weekly_hours: 8 });
  assert.equal(
    plan.sections.find((section) => section.path === "/availability")?.state,
    "SAME_CHANGE",
  );
});

test("a true section collision stays unresolved until one explicit side is chosen", () => {
  const base = completeContent("DEMAND", { problem: { background: "基线" } });
  const current = completeContent("DEMAND", { problem: { background: "服务器" } });
  const yours = completeContent("DEMAND", { problem: { background: "我的" } });

  const unresolved = planEditorConflictMerge("DEMAND", base, current, yours);
  assert.equal(unresolved.complete, false);
  assert.equal(unresolved.content, null);
  assert.deepEqual(unresolved.unresolvedPaths, ["/problem"]);

  const server = planEditorConflictMerge("DEMAND", base, current, yours, {
    "/problem": "SERVER",
  });
  const mine = planEditorConflictMerge("DEMAND", base, current, yours, {
    "/problem": "MINE",
  });
  assert.deepEqual(server.content, current);
  assert.deepEqual(mine.content, yours);
});

test("removed array entries, added values, and null keep three-way semantics", () => {
  const base = completeContent("CREATOR_PROFILE", {
    interests: ["BASE"],
    availability: null,
    conflicts: [],
  });
  const current = completeContent("CREATOR_PROFILE", {
    interests: [],
    availability: { weekly_hours: 4 },
    conflicts: ["SERVER_ADDED"],
  });
  const yours = completeContent("CREATOR_PROFILE", {
    interests: ["MINE_CHANGED"],
    availability: null,
    conflicts: [],
  });

  const unresolved = planEditorConflictMerge("CREATOR_PROFILE", base, current, yours);
  assert.deepEqual(unresolved.unresolvedPaths, ["/interests"]);
  const merged = planEditorConflictMerge("CREATOR_PROFILE", base, current, yours, {
    "/interests": "SERVER",
  });
  assert.deepEqual(merged.content.interests, []);
  assert.deepEqual(merged.content.availability, { weekly_hours: 4 });
  assert.deepEqual(merged.content.conflicts, ["SERVER_ADDED"]);
});

test("an absent base merges only equal sections and conflicts on different sections", () => {
  const current = completeContent("DEMAND", {
    problem: { background: "服务器" },
    scope: { deliverables: [] },
  });
  const yours = completeContent("DEMAND", {
    problem: { background: "我的" },
    scope: { deliverables: [] },
  });
  const plan = planEditorConflictMerge("DEMAND", {}, current, yours);

  assert.deepEqual(plan.unresolvedPaths, ["/problem"]);
  assert.equal(
    plan.sections.find((section) => section.path === "/scope")?.state,
    "SAME_CHANGE",
  );
});

test("inputs remain unchanged, results are frozen, and stale choices fail closed", () => {
  const base = completeContent("CREATOR_PROFILE", { ai: { allowed: false } });
  const current = completeContent("CREATOR_PROFILE", { ai: { allowed: true } });
  const yours = completeContent("CREATOR_PROFILE", { ai: { allowed: false } });
  const snapshots = [structuredClone(base), structuredClone(current), structuredClone(yours)];
  const plan = planEditorConflictMerge("CREATOR_PROFILE", base, current, yours);

  assert.deepEqual([base, current, yours], snapshots);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.sections), true);
  assert.equal(Object.isFrozen(plan.content), true);
  assert.equal(Object.isFrozen(plan.content.ai), true);
  assert.throws(
    () => planEditorConflictMerge("CREATOR_PROFILE", base, current, yours, { "/ai": "MINE" }),
    /INVALID_EDITOR_CONFLICT_MERGE/,
  );
  assert.throws(
    () => planEditorConflictMerge(
      "DEMAND",
      {},
      { ...completeContent("DEMAND"), unexpected: true },
      completeContent("DEMAND"),
    ),
    /INVALID_EDITOR_CONFLICT_MERGE/,
  );
  const incomplete = completeContent("DEMAND");
  delete incomplete.scope;
  assert.throws(
    () => planEditorConflictMerge("DEMAND", {}, incomplete, completeContent("DEMAND")),
    /INVALID_EDITOR_CONFLICT_MERGE/,
  );
});
