import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateSkillBundle } from './contracts.mjs';

const COMMAND = /^\/([a-z][a-z0-9-]*)(?:\s|$)/;

const NATURAL_ROUTES = [
  ['handoff', /\b(handoff|cold chat|clean new (?:chat|thread)|new thread|zero context|bloated (?:chat|thread)|source pointer|transfer (?:all|every) context|new chat .* continue)\b/i],
  ['dispatch', /\b(dispatch|another agent|fresh executor|split independent tasks across|bounded work to a fresh executor|copy-paste task packet)\b/i],
  ['doctor', /\b(?:TRT protocol|council on (?:my )?TRT)\b/i],
  ['execution-preflight', /\b(?:batch script .*smoke-test|smoke-test .*batch script)\b/i],
  ['marketing', /\bProduct Hunt launch\b/i],
  ['cortex', /\bmap current architecture\b/i],
  ['audit', /\bbefore claiming .* verify tests pass\b/i],
  ['debugger', /\b(debug|failing|fails?|403|crash(?:es|ing)?|root cause|diagnosis|hypotheses?|instrumentation|try\/?catch)\b/i],
  ['architect', /\b(architect(?:ure)?[- ]design|implementation plan|plan (?:how|a |adding|our |this |the |to )|design and plan|plan missing work|forget plan|implementation tasks)\b/i],
  ['tasklist', /\b(execution task list|persistent auditable tasklist|show me steps before execution)\b/i],
  ['qa', /\b(QA settings|app viewport|hover states?|dialog focus trap)\b/i],
  ['covenant', /\b(council|jury and counsel|full Council review|fallback seats?|same packet .* (?:both|two) panels|review seat .* (?:working tree|verdict))\b/i],
  ['alchemist', /\bjust fucking do it\b/i],
  ['commit', /\breview this diff\b/i],
];

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function resolveSkillInvocation(input, { root = resolve(import.meta.dirname, '../..') } = {}) {
  const match = COMMAND.exec(String(input ?? '').trim());
  if (!match) return { status: 'not-found', reason: 'not-explicit-command' };

  const requested = `/${match[1]}`;
  const aliases = readJson(resolve(root, 'src/config/capability-aliases.json')).aliases ?? {};
  let target = requested;
  const seen = new Set();
  while (aliases[target] && aliases[target].startsWith('/')) {
    if (seen.has(target)) return { status: 'invalid', requested, reason: 'alias-cycle' };
    seen.add(target);
    target = aliases[target].split(/\s+/, 1)[0];
  }

  const canonical = target.slice(1);
  const index = readJson(resolve(root, 'src/registry/skills/index.json'));
  const record = index.bundles.find(({ id }) => id === canonical);
  if (!record) return { status: 'not-found', requested, canonical };
  const manifest = validateSkillBundle(readJson(resolve(root, record.manifest)));
  return { status: 'resolved', requested, canonical, manifestPath: record.manifest, manifest };
}

export function resolveSkillPrompt(input, options = {}) {
  const explicit = resolveSkillInvocation(input, options);
  if (explicit.reason !== 'not-explicit-command') return explicit;
  const text = String(input ?? '').trim();
  const route = NATURAL_ROUTES.find(([, pattern]) => pattern.test(text));
  if (!route) return { status: 'not-found', reason: 'no-semantic-route' };
  const [canonical] = route;
  const root = options.root ?? resolve(import.meta.dirname, '../..');
  const index = readJson(resolve(root, 'src/registry/skills/index.json'));
  const record = index.bundles.find(({ id }) => id === canonical);
  if (!record) return { status: 'routed', canonical, reason: 'external-capability' };
  const manifest = validateSkillBundle(readJson(resolve(root, record.manifest)));
  return { status: 'resolved', canonical, manifestPath: record.manifest, manifest };
}
