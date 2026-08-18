import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { compilePolicyRules, parsePolicyRules } from '../lib/policy-compiler.mjs';

const root = path.dirname(fileURLToPath(new URL('../policy/arcane-policy-v1.json', import.meta.url)));
const base = JSON.parse(readFileSync(path.join(root, 'arcane-policy-v1.json'), 'utf8'));
const source = readFileSync(path.join(root, 'arcane-policy-v1.rules'), 'utf8');

test('canonical controlled-English rules reproduce every policy effect rule', () => {
  assert.deepEqual(compilePolicyRules({ source, base }).effectRules, base.effectRules);
});

test('compiler rejects unknown, duplicate, missing, and schema-invalid rules', () => {
  assert.throws(() => compilePolicyRules({ source: source.replace('FILE_WRITE', 'UNKNOWN'), base }), /unknown effect class/);
  assert.throws(() => compilePolicyRules({ source: `${source}\nallow FILE_WRITE approval=none trust=capability-signature enforcement=strong`, base }), /duplicate effect class/);
  assert.throws(() => compilePolicyRules({ source: source.replace(/^.*FILE_WRITE.*\n/m, ''), base }), /missing effect class/);
  assert.throws(() => compilePolicyRules({ source: source.replace('enforcement=strong', 'enforcement=advisory'), base }), /compiled policy failed validation/);
});

test('parser permits comments, blanks, and escaped note text only', () => {
  assert.deepEqual(parsePolicyRules('# comment\n\nallow FILE_WRITE approval=none trust=capability-signature enforcement=strong note="quoted \\"note\\""'), [{ effectClass: 'FILE_WRITE', rule: 'allow', approvalRequired: false, trustMinimum: 'capability-signature', requiredEnforcement: 'strong', note: 'quoted "note"' }]);
  assert.throws(() => parsePolicyRules('allow FILE_WRITE approval=none trust=other enforcement=strong'), /invalid rule/);
});
