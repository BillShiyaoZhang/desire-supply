export function nonRecoveryControlsLocked({ busy, pending, writeLocked }) {
  return Boolean(busy || writeLocked || pending);
}

export function createAtomicRefreshCoordinator() {
  let latestGeneration = 0;

  return {
    invalidate() {
      latestGeneration += 1;
    },
    async run({
      commit,
      isValid = () => true,
      load,
      onError,
      onSuccess,
      setBusy,
      validate = () => {},
    }) {
      const generation = ++latestGeneration;
      const isActive = () => generation === latestGeneration && isValid();
      setBusy(true);
      try {
        const snapshot = await load();
        if (!isActive()) {
          return { ok: false, stale: true };
        }
        validate(snapshot);
        if (!isActive()) {
          return { ok: false, stale: true };
        }
        commit(snapshot);
        onSuccess(snapshot);
        return { ok: true, snapshot };
      } catch (error) {
        if (!isActive()) {
          return { ok: false, stale: true };
        }
        onError(error);
        return { ok: false, error };
      } finally {
        if (isActive()) setBusy(false);
      }
    },
  };
}

export async function runAtomicRefresh({
  commit,
  isValid,
  load,
  onError,
  onSuccess,
  setBusy,
  validate,
}) {
  return createAtomicRefreshCoordinator().run({
    commit,
    isValid,
    load,
    onError,
    onSuccess,
    setBusy,
    validate,
  });
}
