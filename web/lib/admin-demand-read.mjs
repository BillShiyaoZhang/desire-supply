// Aborting saves work; the generation check also rejects transports that finish
// after cancellation. Each panel owns its reader for one session/workspace.
export function createAdminDemandReader() {
  let generation = 0;
  let active = null;
  function cancel() {
    generation += 1;
    active?.abort();
    active = null;
  }
  return {
    cancel,
    async run(read, commit, fail) {
      cancel();
      const current = generation;
      const controller = new AbortController();
      active = controller;
      try {
        const value = await read(controller.signal);
        if (current === generation && !controller.signal.aborted) commit(value);
      } catch (error) {
        if (current === generation && !controller.signal.aborted) fail(error);
      } finally {
        if (current === generation) active = null;
      }
    },
  };
}
