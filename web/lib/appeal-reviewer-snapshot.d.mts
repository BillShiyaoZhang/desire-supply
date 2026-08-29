type AppealIdentity = Readonly<{ appeal_id: string }>;

export type AppealReviewerSnapshot<
  QueueItem extends AppealIdentity,
  AssignmentItem extends AppealIdentity,
  HistoryProjection extends Readonly<{ items: AppealIdentity[] }>,
> = Readonly<{
  assignments: AssignmentItem[];
  history: HistoryProjection;
  queue: QueueItem[];
}>;

export function assertAppealReviewerSnapshotDisjoint<
  Snapshot extends AppealReviewerSnapshot<AppealIdentity, AppealIdentity, Readonly<{ items: AppealIdentity[] }>>,
>(snapshot: Snapshot): Snapshot;

export function loadConsistentAppealReviewerSnapshot<
  QueueItem extends AppealIdentity,
  AssignmentItem extends AppealIdentity,
  HistoryProjection extends Readonly<{ items: AppealIdentity[] }>,
>(loaders: Readonly<{
  loadAssignments: () => Promise<Readonly<{ items: AssignmentItem[] }>>;
  loadHistory: () => Promise<HistoryProjection>;
  loadQueue: () => Promise<Readonly<{ items: QueueItem[] }>>;
}>): Promise<AppealReviewerSnapshot<QueueItem, AssignmentItem, HistoryProjection>>;
