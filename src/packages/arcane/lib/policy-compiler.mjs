import { readFileSync } from 'node:fs';

import { validatePolicyBundle } from './policy.mjs';

const LINE = /^(allow|deny) ([A-Z_]+) approval=(required|none) trust=(capability-signature) enforcement=(strong|observed|advisory|unsupported|degraded)(?: note="((?:[^"\\]|\\.)*)")?$/;

export class PolicyRuleCompileError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyRuleCompileError';
  }
}

function parseNote(value, lineNumber) {
  if (value === undefined) return undefined;
  try { return JSON.parse(`"${value}"`); } catch { throw new PolicyRuleCompileError(`line ${lineNumber}: invalid note string`); }
}

/** Parse controlled-English effect rules; comments and blank lines are ignored. */
export function parsePolicyRules(source) {
  const rules = [];
  for (const [index, raw] of String(source).split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = LINE.exec(line);
    if (!match) throw new PolicyRuleCompileError(`line ${index + 1}: invalid rule`);
    const [, rule, effectClass, approval, trustMinimum, requiredEnforcement, note] = match;
    rules.push({ effectClass, rule, approvalRequired: approval === 'required', trustMinimum, requiredEnforcement, ...(note === undefined ? {} : { note: parseNote(note, index + 1) }) });
  }
  return rules;
}

/** Replace only effectRules in a valid base policy, preserving every other policy decision. */
export function compilePolicyRules({ source, base }) {
  const parsed = parsePolicyRules(source);
  const baseClasses = base?.effectRules?.map(({ effectClass }) => effectClass);
  if (!Array.isArray(baseClasses)) throw new PolicyRuleCompileError('base policy has no effectRules');
  const allowed = new Set(baseClasses);
  const seen = new Set();
  for (const { effectClass } of parsed) {
    if (!allowed.has(effectClass)) throw new PolicyRuleCompileError(`unknown effect class: ${effectClass}`);
    if (seen.has(effectClass)) throw new PolicyRuleCompileError(`duplicate effect class: ${effectClass}`);
    seen.add(effectClass);
  }
  const missing = baseClasses.filter((effectClass) => !seen.has(effectClass));
  if (missing.length) throw new PolicyRuleCompileError(`missing effect class(es): ${missing.join(', ')}`);
  const byClass = new Map(parsed.map((rule) => [rule.effectClass, rule]));
  const bundle = { ...base, effectRules: baseClasses.map((effectClass) => byClass.get(effectClass)) };
  const validation = validatePolicyBundle(bundle);
  if (!validation.valid) throw new PolicyRuleCompileError(`compiled policy failed validation: ${validation.issues.map(({ message }) => message).join('; ')}`);
  return bundle;
}

export function compilePolicyFiles({ sourcePath, basePath }) {
  let base;
  try { base = JSON.parse(readFileSync(basePath, 'utf8')); } catch (error) { throw new PolicyRuleCompileError(`base policy unreadable: ${basePath} (${error.message})`); }
  let source;
  try { source = readFileSync(sourcePath, 'utf8'); } catch (error) { throw new PolicyRuleCompileError(`rule source unreadable: ${sourcePath} (${error.message})`); }
  return compilePolicyRules({ source, base });
}

export function renderPolicy(bundle) {
  return `${JSON.stringify(bundle, null, 2)}\n`;
}
