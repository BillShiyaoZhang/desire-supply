import assert from "node:assert/strict";
import test from "node:test";

import {
  createAtomicRefreshCoordinator,
  nonRecoveryControlsLocked,
  runAtomicRefresh,
} from "../lib/workbench-refresh.mjs";

function deferred() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}

test("a pending unknown outcome locks every non-recovery control", () => {
  assert.equal(nonRecoveryControlsLocked({ busy: false, pending: null, writeLocked: false }), false);
  assert.equal(nonRecoveryControlsLocked({ busy: true, pending: null, writeLocked: false }), true);
  assert.equal(nonRecoveryControlsLocked({ busy: false, pending: null, writeLocked: true }), true);
  assert.equal(nonRecoveryControlsLocked({ busy: false, pending: { intent: "same request" }, writeLocked: false }), true);
});

test("managed refresh stages every collection before one atomic commit", async () => {
  const queue = deferred();
  const assignments = deferred();
  const busy = [];
  const commits = [];
  const successes = [];
  const errors = [];
  const refreshing = runAtomicRefresh({
    load: async () => {
      const [queueItems, assignmentItems] = await Promise.all([queue.promise, assignments.promise]);
      return { assignmentItems, queueItems };
    },
    commit: (snapshot) => commits.push(snapshot),
    onSuccess: (snapshot) => successes.push(snapshot),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });

  assert.deepEqual(busy, [true]);
  queue.resolve(["queue-v2"]);
  await Promise.resolve();
  assert.deepEqual(commits, []);

  assignments.resolve(["assignment-v2"]);
  const result = await refreshing;
  const expected = { assignmentItems: ["assignment-v2"], queueItems: ["queue-v2"] };
  assert.deepEqual(result, { ok: true, snapshot: expected });
  assert.deepEqual(commits, [expected]);
  assert.deepEqual(successes, [expected]);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, false]);
});

test("managed refresh converts rejection to a handled result and commits nothing", async () => {
  const expectedError = new Error("queue unavailable");
  const commits = [];
  const errors = [];
  const busy = [];
  const result = await runAtomicRefresh({
    load: async () => {
      await Promise.resolve();
      throw expectedError;
    },
    commit: (snapshot) => commits.push(snapshot),
    onSuccess: () => assert.fail("a rejected load cannot report success"),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });

  assert.deepEqual(result, { ok: false, error: expectedError });
  assert.deepEqual(commits, []);
  assert.deepEqual(errors, [expectedError]);
  assert.deepEqual(busy, [true, false]);
});

test("overlapping refreshes suppress an older commit and keep busy until the active generation settles", async () => {
  const coordinator = createAtomicRefreshCoordinator();
  const older = deferred();
  const newer = deferred();
  const commits = [];
  const successes = [];
  const errors = [];
  const busy = [];
  const options = (load) => ({
    load,
    commit: (snapshot) => commits.push(snapshot),
    onSuccess: (snapshot) => successes.push(snapshot),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });

  const olderRun = coordinator.run(options(() => older.promise));
  const newerRun = coordinator.run(options(() => newer.promise));
  assert.deepEqual(busy, [true, true]);

  older.resolve("older snapshot");
  assert.deepEqual(await olderRun, { ok: false, stale: true });
  assert.deepEqual(commits, []);
  assert.deepEqual(successes, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, true]);

  newer.resolve("newer snapshot");
  assert.deepEqual(await newerRun, { ok: true, snapshot: "newer snapshot" });
  assert.deepEqual(commits, ["newer snapshot"]);
  assert.deepEqual(successes, ["newer snapshot"]);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, true, false]);
});

test("an older response cannot overwrite a newer snapshot that already committed", async () => {
  const coordinator = createAtomicRefreshCoordinator();
  const older = deferred();
  const newer = deferred();
  const commits = [];
  const busy = [];
  const options = (load) => ({
    load,
    commit: (snapshot) => commits.push(snapshot),
    onSuccess() {},
    onError: (error) => assert.fail(`unexpected refresh error: ${String(error)}`),
    setBusy: (value) => busy.push(value),
  });

  const olderRun = coordinator.run(options(() => older.promise));
  const newerRun = coordinator.run(options(() => newer.promise));
  newer.resolve("newest snapshot");
  assert.deepEqual(await newerRun, { ok: true, snapshot: "newest snapshot" });
  assert.deepEqual(commits, ["newest snapshot"]);
  assert.deepEqual(busy, [true, true, false]);

  older.resolve("stale snapshot");
  assert.deepEqual(await olderRun, { ok: false, stale: true });
  assert.deepEqual(commits, ["newest snapshot"]);
  assert.deepEqual(busy, [true, true, false]);
});

test("invalidation makes an in-flight response stale without commit, error, or busy cleanup", async () => {
  const coordinator = createAtomicRefreshCoordinator();
  const inFlight = deferred();
  const commits = [];
  const errors = [];
  const busy = [];
  const refresh = coordinator.run({
    load: () => inFlight.promise,
    commit: (snapshot) => commits.push(snapshot),
    onSuccess: () => assert.fail("an invalidated generation cannot report success"),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });

  assert.deepEqual(busy, [true]);
  coordinator.invalidate();
  busy.push(false); // The lock transition owns cancellation UI state.
  inFlight.resolve("stale after lock");
  assert.deepEqual(await refresh, { ok: false, stale: true });
  assert.deepEqual(commits, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, false]);
});

for (const workbench of ["Trust", "Appeal"]) {
  for (const staleOutcome of ["success", "failure"]) {
    test(`${workbench} detail reads suppress a stale ${staleOutcome} after a foreign lock and let the unlocked generation win`, async () => {
      const coordinator = createAtomicRefreshCoordinator();
      const stale = deferred();
      const newer = deferred();
      const commits = [];
      const successes = [];
      const errors = [];
      const busy = [];
      let unlocked = true;
      const options = (load) => ({
        load,
        isValid: () => unlocked,
        commit: (snapshot) => commits.push(snapshot),
        onSuccess: (snapshot) => successes.push(snapshot),
        onError: (error) => errors.push(error),
        setBusy: (value) => busy.push(value),
      });

      const staleRun = coordinator.run(options(() => stale.promise));
      unlocked = false;
      coordinator.invalidate();
      busy.push(false); // The lock transition owns cancellation UI state.

      unlocked = true;
      const newerRun = coordinator.run(options(() => newer.promise));
      if (staleOutcome === "success") stale.resolve(`${workbench} stale detail`);
      else stale.reject(new Error(`${workbench} stale failure`));

      assert.deepEqual(await staleRun, { ok: false, stale: true });
      assert.deepEqual(commits, []);
      assert.deepEqual(successes, []);
      assert.deepEqual(errors, []);
      assert.deepEqual(busy, [true, false, true]);

      newer.resolve(`${workbench} current detail`);
      assert.deepEqual(await newerRun, { ok: true, snapshot: `${workbench} current detail` });
      assert.deepEqual(commits, [`${workbench} current detail`]);
      assert.deepEqual(successes, [`${workbench} current detail`]);
      assert.deepEqual(errors, []);
      assert.deepEqual(busy, [true, false, true, false]);
    });
  }

  test(`${workbench} post-write validation rejects a contradictory snapshot before commit and releases its latch`, async () => {
    const coordinator = createAtomicRefreshCoordinator();
    const priorSnapshot = { version: `${workbench} prior` };
    const contradictory = { version: `${workbench} contradictory` };
    const valid = { version: `${workbench} valid` };
    const validationError = new TypeError(`${workbench.toUpperCase()}_SNAPSHOT_CONTRADICTS_RECEIPT`);
    const commits = [];
    const successes = [];
    const errors = [];
    const busy = [];
    let visibleSnapshot = priorSnapshot;
    let latchHeld = true;
    let explicitError = null;

    try {
      const result = await coordinator.run({
        load: async () => contradictory,
        validate: () => { throw validationError; },
        commit: (snapshot) => {
          commits.push(snapshot);
          visibleSnapshot = snapshot;
        },
        onSuccess: (snapshot) => successes.push(snapshot),
        onError: (error) => errors.push(error),
        setBusy: (value) => busy.push(value),
      });
      assert.deepEqual(result, { ok: false, error: validationError });
      if (!result.ok) explicitError = `${workbench.toUpperCase()}_POST_COMMIT_REFRESH_FAILED`;
    } finally {
      latchHeld = false;
    }

    assert.equal(visibleSnapshot, priorSnapshot);
    assert.deepEqual(commits, []);
    assert.deepEqual(successes, []);
    assert.deepEqual(errors, [validationError]);
    assert.deepEqual(busy, [true, false]);
    assert.equal(latchHeld, false);
    assert.equal(explicitError, `${workbench.toUpperCase()}_POST_COMMIT_REFRESH_FAILED`);

    const validResult = await coordinator.run({
      load: async () => valid,
      validate: (snapshot) => assert.equal(snapshot, valid),
      commit: (snapshot) => {
        commits.push(snapshot);
        visibleSnapshot = snapshot;
      },
      onSuccess: (snapshot) => successes.push(snapshot),
      onError: (error) => assert.fail(`valid ${workbench} snapshot failed: ${String(error)}`),
      setBusy: (value) => busy.push(value),
    });
    assert.deepEqual(validResult, { ok: true, snapshot: valid });
    assert.equal(visibleSnapshot, valid);
    assert.deepEqual(commits, [valid]);
    assert.deepEqual(successes, [valid]);
    assert.deepEqual(busy, [true, false, true, false]);
  });
}

test("Trust SafetyHoldReleased bundle cannot preserve an active hold behind a retained triage assignment", async () => {
  const oldCase = { active_hold: { hold_id: "hold-1", status: "ACTIVE" }, case_id: "case-1", version: 4 };
  const priorSnapshot = { assignments: [{ case_id: "case-1", purpose: "CASE_TRIAGE" }], queue: [] };
  const validBundle = {
    detail: { active_hold: null, case_id: "case-1", version: 5 },
    snapshot: { assignments: [{ case_id: "case-1", purpose: "CASE_TRIAGE" }], queue: [] },
  };
  const busy = [];
  const errors = [];
  const successes = [];
  let selectedCase = oldCase;
  let visibleSnapshot = priorSnapshot;
  let commits = 0;
  const validateReleasedBundle = (bundle) => {
    const stillAssigned = bundle.snapshot.assignments.some((item) => item.case_id === bundle.detail.case_id);
    if (!stillAssigned || bundle.detail.active_hold !== null || bundle.detail.version < oldCase.version) {
      throw new TypeError("INVALID_TRUST_RELEASED_HOLD_STILL_ACTIVE");
    }
  };

  const validResult = await runAtomicRefresh({
    load: async () => validBundle,
    validate: validateReleasedBundle,
    commit: (bundle) => {
      commits += 1;
      visibleSnapshot = bundle.snapshot;
      selectedCase = bundle.detail;
    },
    onSuccess: (bundle) => successes.push(bundle),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });
  assert.deepEqual(validResult, { ok: true, snapshot: validBundle });
  assert.equal(selectedCase.active_hold, null);
  assert.equal(visibleSnapshot, validBundle.snapshot);
  assert.equal(commits, 1);
  assert.deepEqual(successes, [validBundle]);
  assert.deepEqual(errors, []);
  assert.deepEqual(busy, [true, false]);

  const contradictoryBundle = {
    detail: { active_hold: { hold_id: "hold-1", status: "ACTIVE" }, case_id: "case-1", version: 5 },
    snapshot: validBundle.snapshot,
  };
  selectedCase = oldCase;
  visibleSnapshot = priorSnapshot;
  commits = 0;
  successes.length = 0;
  errors.length = 0;
  busy.length = 0;
  const contradictoryResult = await runAtomicRefresh({
    load: async () => contradictoryBundle,
    validate: validateReleasedBundle,
    commit: () => { commits += 1; },
    onSuccess: (bundle) => successes.push(bundle),
    onError: (error) => errors.push(error),
    setBusy: (value) => busy.push(value),
  });
  assert.equal(contradictoryResult.ok, false);
  assert.match(errors[0]?.message ?? "", /INVALID_TRUST_RELEASED_HOLD_STILL_ACTIVE/);
  assert.equal(selectedCase, oldCase);
  assert.equal(visibleSnapshot, priorSnapshot);
  assert.equal(commits, 0);
  assert.deepEqual(successes, []);
  assert.deepEqual(busy, [true, false]);
});
