import { assertContract } from './contracts.mjs';
import { KernelError } from './errors.mjs';

export class OperationRegistry {
  constructor() {
    this.operations = new Map();
  }

  register(descriptor) {
    if (!descriptor || typeof descriptor !== 'object') {
      throw new KernelError('INVALID_ARGUMENT', 'operation descriptor must be an object', { category: 'usage' });
    }
    assertContract('operation-envelope-v1', descriptor.envelope, 'operation envelope');
    if (descriptor.operationId !== descriptor.envelope.operationId || descriptor.version !== descriptor.envelope.operationVersion) {
      throw new KernelError('INVALID_ARGUMENT', 'operation descriptor identity does not match envelope', { category: 'usage' });
    }
    if (typeof descriptor.handlerBinding !== 'string' || !descriptor.handlerBinding) {
      throw new KernelError('INVALID_ARGUMENT', 'operation handler binding is required', { category: 'usage' });
    }
    if (this.operations.has(descriptor.operationId)) {
      throw new KernelError('SCOPE_CONFLICT', `operation already registered: ${descriptor.operationId}`, { category: 'conflict' });
    }
    const registered = structuredClone(descriptor);
    this.operations.set(descriptor.operationId, registered);
    return structuredClone(registered);
  }

  lookup(operationId) {
    const descriptor = this.operations.get(operationId);
    if (!descriptor) {
      throw new KernelError('OPERATION_NOT_AVAILABLE', `unknown operation: ${operationId}`, {
        category: 'usage',
        remediation: 'Call capability discovery and select a registered operation ID.',
      });
    }
    return structuredClone(descriptor);
  }

  list() {
    return [...this.operations.values()]
      .map(structuredClone)
      .sort((left, right) => left.operationId < right.operationId ? -1 : left.operationId > right.operationId ? 1 : 0);
  }
}

function normalizeCapabilities(value, label) {
  if (!Array.isArray(value) || value.some((capability) => typeof capability !== 'string' || capability.length === 0)) {
    throw new KernelError('INVALID_ARGUMENT', `${label} must be a non-empty string array`, { category: 'usage' });
  }
  return [...new Set(value)].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
}

export function negotiateCapabilities(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new KernelError('INVALID_ARGUMENT', 'capability negotiation options must be an object', { category: 'usage' });
  }
  const required = normalizeCapabilities(options.required === undefined ? [] : options.required, 'required capabilities');
  const supported = normalizeCapabilities(options.supported === undefined ? [] : options.supported, 'supported capabilities');
  const supportedSet = new Set(supported);
  const available = required.filter((capability) => supportedSet.has(capability));
  const missing = required.filter((capability) => !supportedSet.has(capability));
  return { available, missing, compatible: missing.length === 0 };
}
