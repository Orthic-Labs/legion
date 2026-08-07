export function contractConflicts(contract) { return contract.conflicts?.map((field) => ({ field, status: 'conflict' })) ?? []; }
