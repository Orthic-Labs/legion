export { assertContract, bindRunIdentity } from './lib/contracts.mjs';
export { EXIT_CODES, KernelError } from './lib/errors.mjs';
export { ID_PREFIXES, mintId, validateExecutionTaskId, validateId } from './lib/ids.mjs';
export { JsonlJournal } from './lib/journal.mjs';
export { TaskLifecycle } from './lib/lifecycle.mjs';
export { DEFAULT_PROFILE_POLICY, downgradeModelProfile, loadModelProfile } from './lib/profiles.mjs';
export { negotiateCapabilities, OperationRegistry } from './lib/registry.mjs';
export { LaneScheduler, schedulerOptionsFromArgv } from './lib/scheduler.mjs';
export { ArtifactStore, digestContent, EventStore } from './lib/stores.mjs';

export const KERNEL_TASK_ID_BRIDGE_DECISION = Object.freeze({
  decision: 'keep-bridge',
  executionTaskId: 'T-#.#',
  kernelTaskId: 'ktask_<ulid>',
  field: 'kernelTaskId',
  rationale: 'ExecutionTask identity is human-facing contract state; Kernel task identity is an opaque durable runtime handle.',
});
