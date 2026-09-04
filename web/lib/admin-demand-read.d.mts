export function createAdminDemandReader(): {
  cancel(): void;
  run<T>(
    read: (signal: AbortSignal) => Promise<T>,
    commit: (value: T) => void,
    fail: (error: unknown) => void,
  ): Promise<void>;
};
