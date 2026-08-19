// Generic / custom-harness adapter.
//
// The escape hatch behind the seam's actual invariant:
//
//   Adding a harness requires only a DESCRIPTOR when its surfaces can be
//   expressed with the adapter mechanisms that already exist (agents-md /
//   native-file instructions, skills-dir projection, json or toml MCP
//   registration, blocking-hook enforcement). A harness with a genuinely new
//   transport or config format requires ONE shared mechanism implementation in
//   the engine — added once, for every harness — but never a second copy of
//   Legion's semantics.
//
// That is narrower than "an unknown harness needs zero code at all", which was
// only ever true for harnesses whose surfaces happened to match the existing
// mechanisms.
//
// A custom harness supplies its descriptor as DATA — a JSON file at
// `.agents/legion-harness.json`, or LEGION_HARNESS_DESCRIPTOR pointing at one —
// and the same engine installs/verifies it. With no descriptor it falls back to
// the portable common surfaces: AGENTS.md baseline + the .agents/skills
// packages. It never invents a mechanism it was not told about.
import { existsSync, readFileSync } from 'node:fs';
import { join, isAbsolute } from 'node:path';

const DEFAULT = {
  id: 'generic',
  displayName: 'Generic / custom harness',
  installOwner: 'adapter',
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'canonical packages projected to .agents/skills and referenced from the instructions block' },
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
    // Fail closed. A malformed descriptor previously fell through to the default
    // silently, so a typo in a custom harness's declaration installed the WRONG
    // surfaces and reported success. A descriptor that exists but does not parse
    // is an error the operator must see.
    let declared;
    try { declared = JSON.parse(readFileSync(path, 'utf8')); }
    catch (err) {
      const error = new Error(`harness descriptor at ${path} does not parse: ${err.message}`);
      error.code = 'HARNESS_DESCRIPTOR_INVALID';
      throw error;
    }
    if (!declared || typeof declared !== 'object' || Array.isArray(declared)) {
      const error = new Error(`harness descriptor at ${path} must be a JSON object`);
      error.code = 'HARNESS_DESCRIPTOR_INVALID';
      throw error;
    }
    return { ...DEFAULT, ...declared, surfaces: { ...DEFAULT.surfaces, ...(declared.surfaces ?? {}) }, source: path };
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
