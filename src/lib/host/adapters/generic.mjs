// Generic / custom-harness adapter.
//
// The escape hatch that makes "add a harness = one small descriptor, no Legion
// core change" literally true, including for a harness Legion has never heard of.
// A custom harness supplies its own descriptor as DATA — a JSON file at
// `.agents/legion-harness.json`, or the LEGION_HARNESS_DESCRIPTOR env pointing at
// one — and the same engine installs/verifies it. With no descriptor it falls
// back to the guaranteed-portable common surfaces: AGENTS.md baseline + the
// .agents/skills packages. It never invents a mechanism it was not told about.
import { existsSync, readFileSync } from 'node:fs';
import { join, isAbsolute } from 'node:path';

const DEFAULT = {
  id: 'generic',
  displayName: 'Generic / custom harness',
  installOwner: 'adapter',
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'common Agent Skills surface' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
    mcp: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
  },
};

// Resolve a caller-supplied descriptor: env var path wins, then a repo-local
// declaration, then the portable default. The supplied object is merged over the
// default so a custom harness only needs to state what differs.
export function resolveGenericDescriptor(root, env = process.env) {
  const fromEnv = env.LEGION_HARNESS_DESCRIPTOR;
  const candidates = [
    fromEnv ? (isAbsolute(fromEnv) ? fromEnv : join(root, fromEnv)) : null,
    join(root, '.agents', 'legion-harness.json'),
  ].filter(Boolean);
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    try {
      const declared = JSON.parse(readFileSync(path, 'utf8'));
      return { ...DEFAULT, ...declared, surfaces: { ...DEFAULT.surfaces, ...(declared.surfaces ?? {}) }, source: path };
    } catch { /* malformed — fall through to default */ }
  }
  return { ...DEFAULT, source: 'built-in default' };
}

// The generic adapter always "detects" as a last resort so a custom harness is
// never left with no adapter; the registry only falls back to it explicitly.
export default {
  ...DEFAULT,
  detect: { env: ['LEGION_HARNESS', 'LEGION_HARNESS_DESCRIPTOR'] },
  resolve: resolveGenericDescriptor,
};
