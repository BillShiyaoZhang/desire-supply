const OVERLAP = "APPEAL_REVIEWER_SNAPSHOT_OVERLAP";

function appealIds(items) {
  return new Set(items.map((item) => item.appeal_id));
}

export function assertAppealReviewerSnapshotDisjoint(snapshot) {
  const queue = appealIds(snapshot.queue);
  const assignments = appealIds(snapshot.assignments);
  const history = appealIds(snapshot.history.items);
  const overlaps = (
    [...queue].some((appealId) => assignments.has(appealId) || history.has(appealId))
    || [...assignments].some((appealId) => history.has(appealId))
  );
  if (overlaps) throw new TypeError(OVERLAP);
  return snapshot;
}

export async function loadConsistentAppealReviewerSnapshot({
  loadAssignments,
  loadHistory,
  loadQueue,
}) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const [queueProjection, assignmentProjection, historyProjection] = await Promise.all([
      loadQueue(),
      loadAssignments(),
      loadHistory(),
    ]);
    const snapshot = {
      assignments: assignmentProjection.items,
      history: historyProjection,
      queue: queueProjection.items,
    };
    try {
      return assertAppealReviewerSnapshotDisjoint(snapshot);
    } catch (error) {
      if (!(error instanceof TypeError) || error.message !== OVERLAP || attempt === 1) {
        throw error;
      }
    }
  }
  throw new TypeError(OVERLAP);
}
