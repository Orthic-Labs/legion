export function validateFaultInjection(fault, capability) {
  if (!capability || capability.status !== 'available') return { status: 'unproven', reason: 'fault-capability-unavailable' };
  if (!fault?.id || !fault?.durationMs || fault.durationMs < 1) return { status: 'blocked', reason: 'fault-not-bounded' };
  if (fault.production === true) return { status: 'blocked', reason: 'production-fault-forbidden' };
  return { status: 'pass' };
}
