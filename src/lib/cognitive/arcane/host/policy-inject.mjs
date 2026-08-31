import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Absorbs enforce_brief.py, enforce_minimize_policy.py & ccx_gateway_mode.py:
// three standalone Python injectors that exist only because
// renderHostRuntimeOutput returns null on allowed SessionStart/SubagentStart.
const here = dirname(fileURLToPath(import.meta.url));
const BRIEF_FALLBACK = join(here, '..', 'policy', 'brief-policy.md');
const MINIMIZE_POLICY = join(here, '..', 'policy', 'minimize-policy.md');
const CCX_DIRECTIVE = join(here, '..', 'policy', 'ccx-gateway-directive.md');
const POLICY_TOML_REL = join('tools', 'lib', 'policy.toml');
const GOTCHAS_REL = join('docs', 'GOTCHAS.md');
const GOTCHA_LIMIT = 2;

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

function words(value) {
  return new Set(String(value ?? '').toLowerCase().match(/[a-z0-9][a-z0-9_-]{2,}/g) ?? []);
}

function gotchaReminder(workspace, prompt) {
  const promptWords = words(prompt);
  if (promptWords.size === 0) return null;
  const markdown = readFileOrNull(join(workspace, GOTCHAS_REL));
  if (!markdown) return null;
  const matches = [];
  for (const section of markdown.split(/^### /m).slice(1)) {
    const [heading = '', ...bodyLines] = section.split(/\r?\n/);
    const keysLine = bodyLines.find((line) => /^\*\*Keys:\*\*/i.test(line));
    if (!keysLine) continue;
    const keys = keysLine.replace(/^\*\*Keys:\*\*\s*/i, '').split(',').map((key) => key.trim()).filter(Boolean);
    if (!keys.some((key) => [...words(key)].every((word) => promptWords.has(word)))) continue;
    const fix = bodyLines.find((line) => /^\*\*Fix:\*\*/.test(line)) ?? '';
    matches.push(`- ${heading.trim()}${fix ? ` — ${fix.replace(/^\*\*Fix:\*\*\s*/, '')}` : ''}`);
    if (matches.length === GOTCHA_LIMIT) break;
  }
  if (matches.length === 0) return null;
  return `Relevant workspace gotchas — apply before acting:\n${matches.join('\n')}`;
}

export function buildPolicyInjection({ workspace, prompt = null, gotchasOnly = false, routeEnvelope = null }) {
  const minimize = readFileOrNull(MINIMIZE_POLICY)?.trim() ?? null;
  const gotcha = gotchaReminder(workspace, prompt);
  const route = routeEnvelope?.kind === 'arcane-route-envelope' ? `ARCANE_ROUTE:${JSON.stringify(routeEnvelope)}` : null;
  const parts = gotchasOnly ? [route, gotcha].filter(Boolean) : [route, briefContent(workspace), minimize, ccxDirective(), gotcha].filter(Boolean);
  if (parts.length === 0) return null;
  const result = { additionalContext: parts.join('\n\n---\n\n') };
  if (!gotchasOnly && minimize) result.systemMessage = 'MINIMIZE:ON';
  return result;
}
