// The fixed vocabulary every harness adapter is measured against.
//
// A harness integration is not one yes/no. It is five independent surfaces, each
// of which a given harness supports natively, partially, or not at all. Keeping
// the vocabulary closed here — rather than letting each adapter invent terms — is
// what makes the fidelity table comparable across harnesses and lets the
// conformance tests assert it.

// The surfaces, in a stable order for reporting.
export const SURFACES = Object.freeze(['instructions', 'skills', 'agents', 'mcp', 'hooks']);

export const SURFACE_MEANING = Object.freeze({
  instructions: 'where/how the harness receives Legion baseline context',
  skills: 'where the harness discovers Agent Skills (SKILL.md packages)',
  agents: 'whether the harness supports native agents/subagents',
  mcp: 'how the legion MCP server is registered',
  hooks: 'what hook / effect-enforcement surfaces exist',
});

// Observed support per surface. These are honest states, not aspirations:
//   strong      native mechanism, full canonical fidelity
//   degraded    reaches the harness, but with a stated loss (e.g. skills via the
//               common .agents/skills surface rather than a first-class API, or
//               instructions as flattened context)
//   unsupported the harness has no mechanism for this surface
export const FIDELITY = Object.freeze(['strong', 'degraded', 'unsupported']);

export function assertFidelity(value, where) {
  if (!FIDELITY.includes(value)) throw new TypeError(`${where}: fidelity must be one of ${FIDELITY.join('|')}, got ${value}`);
}

// Enforcement is the one surface where transport is necessarily host-specific
// (a blocking command hook, a permission prompt, or nothing). Guard semantics
// stay host-neutral; only transport differs. An adapter must never declare
// `strong` enforcement for a harness that lacks the hook/permission mechanism to
// actually block an effect — that is the difference between a gate and theatre.
export function enforcementFidelity(mechanism) {
  if (!mechanism || mechanism.kind === 'none') return 'unsupported';
  if (mechanism.kind === 'blocking-hook') return 'strong';
  // An observe-only or advisory transport can report but not block.
  return 'degraded';
}
