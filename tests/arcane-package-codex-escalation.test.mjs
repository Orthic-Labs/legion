// The escalation ladder, ported from gate_codex_escalation.py. Its rule: two
// attempts, each with what actually went wrong, before dispatching to codex.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  evaluateCodexEscalation,
  evidenceCount,
  promptArgument,
  sourceFile,
} from '../src/lib/host/arcane/codex-escalation.mjs';

const TWO = 'I tried the nvm shim and it failed with ENOENT. Then I ran the direct binary path and it crashed with exit code 127.';

test('a command that never mentions codex exec is not this gate\'s business', () => {
  for (const command of ['git status', 'node --test', 'echo codex']) {
    assert.deepEqual(evaluateCodexEscalation(command), { allowed: true });
  }
});

test('two evidenced attempts pass', () => {
  const result = evaluateCodexEscalation(`codex exec "${TWO}"`);
  assert.equal(result.allowed, true);
  assert.equal(result.evidence, 2);
});

test('intent without outcomes is not evidence', () => {
  const result = evaluateCodexEscalation('codex exec "I tried a few things and I attempted several approaches before giving up on this"');
  assert.equal(result.allowed, false);
  assert.match(result.reason, /at least 2 self-attempts/);
});

test('one evidenced attempt is still short', () => {
  const result = evaluateCodexEscalation('codex exec "I ran the migration and it failed with a UniqueViolation error on the slug column"');
  assert.equal(result.allowed, false);
  assert.equal(result.evidence, 1);
});

test('an interpreter command that merely mentions codex exec is left alone', () => {
  // `python foo.py` owns the command line; codex exec here is script text.
  assert.deepEqual(evaluateCodexEscalation('python run.py --mode "codex exec"'), { allowed: true });
});

test('a heredoc body counts as the prompt', () => {
  const command = `codex exec <<'EOF'\n${TWO}\nEOF`;
  assert.equal(evaluateCodexEscalation(command).allowed, true);
});

test('a stdin-fed prompt is read from its file', () => {
  const command = 'cat prompt.md | codex exec';
  assert.equal(sourceFile(command), 'prompt.md');
  assert.equal(evaluateCodexEscalation(command, () => TWO).allowed, true);
  assert.equal(evaluateCodexEscalation(command, () => 'no attempts here').allowed, false);
});

test('an unreadable stdin source is refused, never waved through', () => {
  // Otherwise piping from anywhere unreadable would be the bypass.
  const result = evaluateCodexEscalation('cat missing.md | codex exec', () => null);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /could not be read/);
});

test('two attempt verbs describing one attempt count once', () => {
  // "tried and tested" within 20 chars is one attempt, not two.
  assert.equal(evidenceCount('I tried and tested it; it failed with a TypeError.'), 1);
});

test('promptArgument ignores flags and paths, taking the longest real body', () => {
  assert.equal(promptArgument('codex exec --model gpt -C "D:/workspace"'), '');
  assert.equal(promptArgument(`codex exec "${TWO}"`), TWO);
});

test('a codex exec carrying no prompt at all is refused, not defaulted open', () => {
  const result = evaluateCodexEscalation('codex exec --model gpt-5');
  assert.equal(result.allowed, false);
  assert.equal(result.evidence, 0);
});
