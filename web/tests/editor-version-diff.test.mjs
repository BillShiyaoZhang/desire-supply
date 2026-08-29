import assert from "node:assert/strict";
import test from "node:test";
import { diffEditorVersionContent } from "../lib/editor-version-diff.mjs";

test("equal projected content is deterministic across object insertion order", () => {
  const left = {
    skills: { must_have: [{ skill_code: "SKILL.A", minimum_level_code: "WORKING" }] },
    problem: { background: "合成问题", domain_code: "DOMAIN.A" },
  };
  const right = {
    problem: { domain_code: "DOMAIN.A", background: "合成问题" },
    skills: { must_have: [{ minimum_level_code: "WORKING", skill_code: "SKILL.A" }] },
  };

  assert.deepEqual(diffEditorVersionContent(left, right), { equal: true, changes: [] });
});

test("nested scalar additions, removals, and changes use escaped stable paths", () => {
  const result = diffEditorVersionContent({
    "a/b": { "x~y": "旧值", removed: true },
  }, {
    "a/b": { "x~y": "新值", added: 3 },
  });

  assert.deepEqual(result, {
    equal: false,
    changes: [
      {
        type: "ADDED",
        path: "/a~1b/added",
        before: null,
        after: { value_type: "NUMBER", value: 3 },
      },
      {
        type: "REMOVED",
        path: "/a~1b/removed",
        before: { value_type: "BOOLEAN", value: true },
        after: null,
      },
      {
        type: "CHANGED",
        path: "/a~1b/x~0y",
        before: { value_type: "STRING", value: "旧值" },
        after: { value_type: "STRING", value: "新值" },
      },
    ],
  });
});

test("empty containers and type changes are closed summaries rather than raw JSON", () => {
  assert.deepEqual(diffEditorVersionContent({
    removed_object: {},
    changed: "旧值",
  }, {
    added_array: [],
    changed: { nested: "不会作为原始 JSON 输出" },
  }), {
    equal: false,
    changes: [
      {
        type: "ADDED",
        path: "/added_array",
        before: null,
        after: { value_type: "EMPTY_ARRAY" },
      },
      {
        type: "CHANGED",
        path: "/changed",
        before: { value_type: "STRING", value: "旧值" },
        after: { value_type: "OBJECT", size: 1 },
      },
      {
        type: "REMOVED",
        path: "/removed_object",
        before: { value_type: "EMPTY_OBJECT" },
        after: null,
      },
    ],
  });
});

test("ordinary arrays retain index semantics for primitive and object values", () => {
  assert.deepEqual(diffEditorVersionContent({ tags: ["A", "B"], rows: [{ label: "一" }] }, {
    tags: ["A", "C", "D"],
    rows: [{ label: "二" }],
  }).changes, [
    {
      type: "CHANGED",
      path: "/rows/0/label",
      before: { value_type: "STRING", value: "一" },
      after: { value_type: "STRING", value: "二" },
    },
    {
      type: "CHANGED",
      path: "/tags/1",
      before: { value_type: "STRING", value: "B" },
      after: { value_type: "STRING", value: "C" },
    },
    {
      type: "ADDED",
      path: "/tags/2",
      before: null,
      after: { value_type: "STRING", value: "D" },
    },
  ]);
});

test("schema repeaters follow item_id across insertions and edits", () => {
  const before = {
    scope: {
      deliverables: [
        { item_id: "deliverable_1", description: "旧描述" },
        { item_id: "deliverable_2", description: "保留" },
      ],
    },
  };
  const after = {
    scope: {
      deliverables: [
        { item_id: "deliverable_3", description: "新增" },
        { item_id: "deliverable_1", description: "新描述" },
        { item_id: "deliverable_2", description: "保留" },
      ],
    },
  };

  assert.deepEqual(diffEditorVersionContent(before, after).changes, [
    {
      type: "CHANGED",
      path: "/scope/deliverables/@item_id=deliverable_1/description",
      before: { value_type: "STRING", value: "旧描述" },
      after: { value_type: "STRING", value: "新描述" },
    },
    {
      type: "ADDED",
      path: "/scope/deliverables/@item_id=deliverable_3/description",
      before: null,
      after: { value_type: "STRING", value: "新增" },
    },
    {
      type: "ADDED",
      path: "/scope/deliverables/@item_id=deliverable_3/item_id",
      before: null,
      after: { value_type: "STRING", value: "deliverable_3" },
    },
  ]);
});

test("criterion_id identity and a pure reorder remain visible without index churn", () => {
  const before = {
    acceptance: { criteria: [
      { criterion_id: "criterion_1", description: "一" },
      { criterion_id: "criterion_2", description: "二" },
    ] },
  };
  const after = {
    acceptance: { criteria: [
      { criterion_id: "criterion_2", description: "二" },
      { criterion_id: "criterion_1", description: "一" },
    ] },
  };

  assert.deepEqual(diffEditorVersionContent(before, after).changes, [{
    type: "CHANGED",
    path: "/acceptance/criteria/@order",
    before: { value_type: "ITEM_ORDER", value: ["criterion_1", "criterion_2"] },
    after: { value_type: "ITEM_ORDER", value: ["criterion_2", "criterion_1"] },
  }]);
});

test("milestone item removal uses its stable identity path", () => {
  const before = { milestone_plan: { items: [{ item_id: "milestone_1", label: "准备", percent: 100 }] } };
  const after = { milestone_plan: { items: [] } };
  assert.deepEqual(diffEditorVersionContent(before, after).changes, [
    {
      type: "REMOVED",
      path: "/milestone_plan/items/@item_id=milestone_1/item_id",
      before: { value_type: "STRING", value: "milestone_1" },
      after: null,
    },
    {
      type: "REMOVED",
      path: "/milestone_plan/items/@item_id=milestone_1/label",
      before: { value_type: "STRING", value: "准备" },
      after: null,
    },
    {
      type: "REMOVED",
      path: "/milestone_plan/items/@item_id=milestone_1/percent",
      before: { value_type: "NUMBER", value: 100 },
      after: null,
    },
  ]);
});

test("missing schema identity safely falls back to array indexes", () => {
  const before = { scope: { deliverables: [{ description: "一" }, { description: "二" }] } };
  const after = { scope: { deliverables: [{ description: "二" }, { description: "一" }] } };
  assert.deepEqual(diffEditorVersionContent(before, after).changes.map((entry) => entry.path), [
    "/scope/deliverables/0/description",
    "/scope/deliverables/1/description",
  ]);
});

test("duplicate explicit item_id or criterion_id never guesses repeater identity", () => {
  const result = diffEditorVersionContent({
    scope: { deliverables: [
      { item_id: "duplicate", description: "一" },
      { item_id: "duplicate", description: "二" },
    ] },
    acceptance: { criteria: [
      { criterion_id: "duplicate", description: "甲" },
      { criterion_id: "duplicate", description: "乙" },
    ] },
  }, {
    scope: { deliverables: [
      { item_id: "duplicate", description: "二" },
      { item_id: "duplicate", description: "一" },
    ] },
    acceptance: { criteria: [
      { criterion_id: "duplicate", description: "乙" },
      { criterion_id: "duplicate", description: "甲" },
    ] },
  });

  assert.deepEqual(result.changes.map((entry) => entry.path), [
    "/acceptance/criteria/0/description",
    "/acceptance/criteria/1/description",
    "/scope/deliverables/0/description",
    "/scope/deliverables/1/description",
  ]);
  assert.equal(result.changes.some((entry) => entry.path.includes("@item_id=") || entry.path.includes("@criterion_id=")), false);
});

test("input is not mutated and the closed result is frozen", () => {
  const before = { problem: { background: "旧" } };
  const after = { problem: { background: "新" } };
  const beforeSnapshot = structuredClone(before);
  const afterSnapshot = structuredClone(after);
  const result = diffEditorVersionContent(before, after);

  assert.deepEqual(before, beforeSnapshot);
  assert.deepEqual(after, afterSnapshot);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.changes), true);
  assert.equal(Object.isFrozen(result.changes[0]), true);
  assert.equal(Object.isFrozen(result.changes[0].before), true);
});

test("non-JSON, cyclic, sparse, accessor, excessive-depth, and non-object roots fail closed", () => {
  const cyclic = {};
  cyclic.self = cyclic;
  const sparse = new Array(2);
  sparse[1] = "x";
  const accessor = {};
  Object.defineProperty(accessor, "leak", { enumerable: true, get: () => "x" });
  let deep = { value: true };
  for (let index = 0; index < 65; index += 1) deep = { child: deep };

  for (const invalid of [undefined, null, [], { value: undefined }, { value: NaN }, { value: 1n }, cyclic, { sparse }, accessor, deep, new Date()]) {
    assert.throws(() => diffEditorVersionContent(invalid, {}), /INVALID_EDITOR_VERSION_CONTENT/);
  }
});
