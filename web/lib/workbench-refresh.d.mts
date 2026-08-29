export function nonRecoveryControlsLocked(input: {
  busy: boolean;
  pending: unknown;
  writeLocked: boolean;
}): boolean;

export type AtomicRefreshResult<T> =
  | { ok: true; snapshot: T }
  | { ok: false; error: unknown }
  | { ok: false; stale: true };

export type AtomicRefreshOptions<T> = {
  commit: (snapshot: T) => void;
  isValid?: () => boolean;
  load: () => Promise<T>;
  onError: (error: unknown) => void;
  onSuccess: (snapshot: T) => void;
  setBusy: (busy: boolean) => void;
  validate?: (snapshot: T) => void;
};

export type AtomicRefreshCoordinator = {
  invalidate(): void;
  run<T>(input: AtomicRefreshOptions<T>): Promise<AtomicRefreshResult<T>>;
};

export function createAtomicRefreshCoordinator(): AtomicRefreshCoordinator;

export function runAtomicRefresh<T>(input: AtomicRefreshOptions<T>): Promise<AtomicRefreshResult<T>>;
