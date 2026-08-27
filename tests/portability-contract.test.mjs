import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { portabilityReport } from '../scripts/check-portability.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('tracked product files contain no unclassified developer-local paths or usernames', () => {
  assert.deepEqual(portabilityReport(root).issues, []);
});

test('portability guard rejects new leaks & dead exemptions', () => {
  const fixture = mkdtempSync(join(tmpdir(), 'legion-portability-'));
  try {
    for (const path of ['src/config/portability-allowlist.json', 'migration/native-rust/dispatches/INSTALLED-COMPOSITION-RESOLUTION-DISPATCH.json', 'migration/native-rust/dispatches/REMAINING-CODE-EDIT-REQUEST.md']) {
      mkdirSync(dirname(join(fixture, path)), { recursive: true });
      cpSync(join(root, path), join(fixture, path));
    }
    mkdirSync(join(fixture, 'src'), { recursive: true });
    const developerName = ['AD', 'RDS'].join('');
    writeFileSync(join(fixture, 'src', 'leak.mjs'), `export const root = "C:/Users/${developerName}/project";\n`);
    const policyPath = join(fixture, 'src/config/portability-allowlist.json');
    const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
    policy.rules.push({ path: 'missing.md', patterns: ['developer-workspace'], occurrences: { 'developer-workspace': 1 }, class: 'historical', reason: 'fixture' });
    writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
    const report = portabilityReport(fixture);
    assert.equal(report.status, 'fail');
    assert.ok(report.issues.some(({ path, reason }) => path === 'src/leak.mjs' && reason.includes('unclassified')));
    assert.ok(report.issues.some(({ path, reason }) => path === 'missing.md' && reason.includes('does not exist')));
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
