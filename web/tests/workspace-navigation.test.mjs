import assert from "node:assert/strict";
import test from "node:test";
import { buildWorkspaceNavigation, resolveWorkspaceView, workspaceViewForTarget } from "../lib/workspace-navigation.mjs";

test("navigation exposes only destinations established for the current workspace", () => {
  assert.deepEqual(buildWorkspaceNavigation({}).map((item) => item.id), ["tasks", "security"]);
  const creator = buildWorkspaceNavigation({ profileScope: true, canUseMatching: true, isCreator: true });
  assert.deepEqual(creator.map((item) => item.id), ["tasks", "profiles", "matching", "security"]);
  assert.equal(creator.find((item) => item.id === "matching").label, "合作邀请");
  assert.equal(resolveWorkspaceView("accounts", creator, null), "tasks");
  assert.deepEqual(buildWorkspaceNavigation({ canAdminAccounts: "true", canInspectDemands: 1 }).map((item) => item.id), ["tasks", "security"]);
});

test("recovering writes always expose their owning module without adding authority", () => {
  const owner = buildWorkspaceNavigation({ demandScope: true, canUseTrust: true, canUseAppeal: true, canUseMatching: true });
  for (const [pending, view] of [["TRUST", "trust"], ["APPEAL", "appeal"], ["MATCHING", "matching"], ["SESSION", "security"]]) {
    assert.equal(resolveWorkspaceView("tasks", owner, pending), view);
  }
  assert.equal(resolveWorkspaceView("tasks", owner, "ORGANIZATION"), "tasks");
  assert.equal(resolveWorkspaceView("tasks", buildWorkspaceNavigation({ canReviewMatching: true }), "MATCHING"), "matching-review");
  assert.equal(resolveWorkspaceView("demands", owner, null), "demands");
});

test("task focus targets map to their containing module", () => {
  for (const [element, view] of [["review-history-title", "review"], ["review-queue-title", "review"], ["finance-funding-title", "funding"], ["trust-case-history-title", "trust"], ["appeal-workbench-title", "appeal"]]) {
    assert.equal(workspaceViewForTarget(element), view);
  }
  assert.equal(workspaceViewForTarget("untrusted-arbitrary-target"), "tasks");
});
