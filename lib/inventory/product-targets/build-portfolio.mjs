import { digest } from '../../core/binding.mjs';
import { validateTarget } from './contracts.mjs';
export function buildPortfolio({ candidates = [], declarations = [], binding = null }) {
  const byId = new Map();
  for (const target of [...candidates, ...declarations]) { validateTarget(target); if (byId.has(target.id)) throw new Error(`target ID collision: ${target.id}`); byId.set(target.id, target); }
  const targets = [...byId.values()].sort((a,b) => a.id.localeCompare(b.id));
  const unknown = targets.filter((target) => target.kind === 'unknown-deliverable');
  const value = { schemaVersion: 1, kind: 'nemesis-product-portfolio', targets, relations: [], coverage: { expectedDeliverables: targets.length, classifiedTargets: targets.length - unknown.length, unknownDeliverables: unknown.map((target) => target.id) }, binding };
  return { ...value, digest: digest(value) };
}
