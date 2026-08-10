import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Absorbs enforce_brief.py, enforce_minimize_policy.py & ccx_gateway_mode.py:
// three standalone Python injectors that exist only because
// renderHostRuntimeOutput returns null on allowed SessionStart/SubagentStart.
const here = dirname(fileURLToPath(import.meta.url));
const BRIEF_FALLBACK = join(here, '..', 'policy', 'inject', 'brief-policy.md');
const MINIMIZE_POLICY = join(here, '..', 'policy', 'minimize-policy.md');
const CCX_DIRECTIVE = join(here, '..', 'policy', 'inject', 'ccx-gateway-directive.md');
const POLICY_TOML_REL = join('tools', 'lib', 'policy.toml');

function readFileOrNull(path) {
  try { return readFileSync(path, 'utf8'); } catch { return null; }
}

// policy.toml WINS when readable (I-4); brief-policy.md is the fallback.
// BRIEF_MODE_OFF=1 is the operator kill switch the Python hook carried.
function briefContent(workspace) {
  if (process.env.BRIEF_MODE_OFF === '1') return null;
  const toml = readFileOrNull(join(workspace, POLICY_TOML_REL));
  const match = toml && toml.match(/\[brief\][\s\S]*?\bcontent\s*=\s*"""\n?([\s\S]*?)"""/);
  if (match && match[1].trim()) return match[1].trim();
  return readFileOrNull(BRIEF_FALLBACK)?.trim() ?? null;
}

// CCX_GATEWAY_MODE_OFF=1 is the operator kill switch the Python hook carried.
function ccxDirective() {
  if (process.env.CCX_GATEWAY_MODE_OFF === '1') return null;
  const base = process.env.ANTHROPIC_BASE_URL || '';
  if (!base.includes('127.0.0.1:8801') && !base.includes('localhost:8801')) return null;
  return readFileOrNull(CCX_DIRECTIVE)?.trim() ?? null;
}

export function buildPolicyInjection({ workspace }) {
  const minimize = readFileOrNull(MINIMIZE_POLICY)?.trim() ?? null;
  const parts = [briefContent(workspace), minimize, ccxDirective()].filter(Boolean);
  if (parts.length === 0) return null;
  const result = { additionalContext: parts.join('\n\n---\n\n') };
  if (minimize) result.systemMessage = 'MINIMIZE:ON';
  return result;
}
