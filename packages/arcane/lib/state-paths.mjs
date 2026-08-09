import { join } from 'node:path';
import { digestValue } from './canonical.mjs';

export const stateRoot = (workspace) => join(workspace, '.audit', 'arcane');
export const statePaths = (workspace) => {
  const root = stateRoot(workspace);
  return { root, receipts: join(root, 'receipts'), replay: join(root, 'replay'), capabilityGrants: join(root, 'capabilities', 'grants'), capabilityTransitions: join(root, 'capabilities', 'transitions'), contractSeals: join(root, 'contract-seals'), authorityBindings: join(root, 'authority-bindings'), sessionBindings: join(root, 'session-bindings'), preEffectCorrelations: join(root, 'pre-effect-correlations') };
};
export const keyHex = (domain, values) => digestValue({ domain, values }).slice(7);
export const stateFile = (dir, domain, values) => join(dir, `${keyHex(domain, values)}.json`);
