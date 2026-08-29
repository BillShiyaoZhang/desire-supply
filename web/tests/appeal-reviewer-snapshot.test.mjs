import assert from "node:assert/strict";
import test from "node:test";

import { loadConsistentAppealReviewerSnapshot } from "../lib/appeal-reviewer-snapshot.mjs";
import { runAtomicRefresh } from "../lib/workbench-refresh.mjs";

function deferred() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}

function item(appealId) {
  return { appeal_id: appealId };
}

test("Appeal reviewer refresh retries one cross-endpoint overlap and commits only the consistent snapshot", async () => {
  const first = { queue: deferred(), assignments: deferred(), history: deferred() };
  const second = { queue: deferred(), assignments: deferred(), history: deferred() };
  const attempts = { queue: 0, assignments: 0, history: 0 };
  const batches = [first, second];
  const load = (kind) => {
    const attempt = attempts[kind];
    attempts[kind] += 1;
    return batches[attempt][kind].promise;
  };
  const prior = { version: "prior-complete-snapshot" };
  let visible = prior;
  const commits = [];
  const errors = [];
  const busy = [];
  const refresh = runAtomicRefresh({
    load: () => loadConsistentAppealReviewerSnapshot({
      loadAssignments: () => load("assignments"),
      loadHistory: () => load("history"),
      loadQueue: () => load("queue"),
    }),
    commit: (snapshot) => {
      commits.push(snapshot);
      visible = snapshot;
    },
    onSuccess() {},
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });

  first.queue.resolve({ items: [item("appeal-transitioning")] });
  first.assignments.resolve({ items: [item("appeal-transitioning")] });
  first.history.resolve({ entity_tag: '"appeal-1-first"', has_more: false, items: [] });
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(attempts, { queue: 2, assignments: 2, history: 2 });
  assert.equal(visible, prior);
  assert.deepEqual(commits, []);

  const expected = {
    assignments: [item("appeal-assigned")],
    history: {
      entity_tag: '"appeal-2-second"',
      has_more: false,
      items: [item("appeal-completed")],
    },
    queue: [item("appeal-queued")],
  };
  second.queue.resolve({ items: expected.queue });
  second.assignments.resolve({ items: expected.assignments });
  second.history.resolve(expected.history);

  assert.deepEqual(await refresh, { ok: true, snapshot: expected });
  assert.deepEqual(visible, expected);
  assert.equal(visible, commits[0]);
  assert.deepEqual(commits, [expected]);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, false]);
});

test("Appeal reviewer refresh rejects a second overlap and preserves the prior complete snapshot", async () => {
  let visible = { version: "prior-complete-snapshot" };
  let attempts = 0;
  const errors = [];
  const result = await runAtomicRefresh({
    load: () => loadConsistentAppealReviewerSnapshot({
      loadAssignments: async () => ({ items: [item(`appeal-${attempts}`)] }),
      loadHistory: async () => ({ entity_tag: '"appeal-overlap"', has_more: false, items: [] }),
      loadQueue: async () => {
        attempts += 1;
        return { items: [item(`appeal-${attempts}`)] };
      },
    }),
    commit: (snapshot) => { visible = snapshot; },
    onSuccess: () => assert.fail("a repeated overlap cannot commit"),
    onError: (error) => errors.push(error),
    setBusy() {},
  });

  assert.equal(result.ok, false);
  assert.match(result.error.message, /APPEAL_REVIEWER_SNAPSHOT_OVERLAP/);
  assert.deepEqual(visible, { version: "prior-complete-snapshot" });
  assert.equal(errors.length, 1);
});
