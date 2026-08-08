import { WORKER_PROFILE, assertEnum } from '../../contracts/enums.mjs';
import { KernelError } from './errors.mjs';

export const DEFAULT_PROFILE_POLICY = Object.freeze({
  strict: Object.freeze({ maxPacketTasks: 1, maxConcurrency: 1, maxMutationConcurrency: 1, allowReadOnlyParallel: false, allowWorkerSpawn: false }),
  standard: Object.freeze({ maxPacketTasks: 4, maxConcurrency: 2, maxMutationConcurrency: 1, allowReadOnlyParallel: true, allowWorkerSpawn: false }),
  advanced: Object.freeze({ maxPacketTasks: 8, maxConcurrency: 4, maxMutationConcurrency: 4, allowReadOnlyParallel: true, allowWorkerSpawn: true }),
});

const ORDER = ['strict', 'standard', 'advanced'];

function validateLimits(name, limits) {
  const integerFields = ['maxPacketTasks', 'maxConcurrency', 'maxMutationConcurrency'];
  const booleanFields = ['allowReadOnlyParallel', 'allowWorkerSpawn'];
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)) {
    throw new KernelError('INVALID_ARGUMENT', `profile limits missing for ${name}`, { category: 'policy' });
  }
  for (const field of integerFields) {
    if (!Number.isInteger(limits[field]) || limits[field] < 1) {
      throw new KernelError('INVALID_ARGUMENT', `${name}.${field} must be a positive integer`, { category: 'policy' });
    }
  }
  for (const field of booleanFields) {
    if (typeof limits[field] !== 'boolean') {
      throw new KernelError('INVALID_ARGUMENT', `${name}.${field} must be boolean`, { category: 'policy' });
    }
  }
  if (limits.maxMutationConcurrency > limits.maxConcurrency) {
    throw new KernelError('INVALID_ARGUMENT', 'mutation concurrency cannot exceed total concurrency', { category: 'policy' });
  }
  return limits;
}

export function loadModelProfile(name, policy = DEFAULT_PROFILE_POLICY) {
  try {
    assertEnum('worker profile', WORKER_PROFILE, name);
  } catch (cause) {
    throw new KernelError('INVALID_ARGUMENT', `unknown worker profile: ${name}`, { category: 'usage', cause });
  }
  const limits = validateLimits(name, policy[name]);
  return Object.freeze({ name, limits: Object.freeze({ ...limits }), assignedBy: 'qualification-policy' });
}

export function downgradeModelProfile(profile, reason, options = {}) {
  if (typeof reason !== 'string' || !reason.trim()) {
    throw new KernelError('INVALID_ARGUMENT', 'profile downgrade reason is required', { category: 'usage' });
  }
  if (typeof options.requestedBy === 'string' && options.requestedBy.toLowerCase() === 'model') {
    throw new KernelError('AUTHORITY_DENIED', 'model-requested profile changes are forbidden', { category: 'authority' });
  }
  const current = loadModelProfile(profile.name, options.policy ?? DEFAULT_PROFILE_POLICY);
  const index = ORDER.indexOf(current.name);
  const downgraded = loadModelProfile(ORDER[Math.max(0, index - 1)], options.policy ?? DEFAULT_PROFILE_POLICY);
  return Object.freeze({ ...downgraded, downgrade: Object.freeze({ from: current.name, reason, source: options.requestedBy ?? 'qualification-policy' }) });
}
