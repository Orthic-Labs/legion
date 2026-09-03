import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runFrameworkSuite } from '../src/providers/framework-suite.mjs';

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-framework-'));
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), content);
  }
  return root;
}

function plan(families) {
  return { coverageFamilies: Object.entries(families).map(([id, paths]) => ({ id, denominator: { paths } })) };
}

test('Electron dangerous preferences are blocking candidates', () => {
  const root = fixture({ 'src/main.ts': `new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } })` });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.electron': ['src/main.ts'] }) })[0];
    assert.equal(result.status, 'candidates');
    assert.equal(result.ownerProvider, 'framework.major-suite');
    assert.deepEqual(result.candidates.map((item) => item.ruleId).sort(), ['electron-context-isolation', 'electron-node-integration']);
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Django debug and CSRF bypass are detected as candidates', () => {
  const root = fixture({ 'app/settings.py': 'DEBUG = True\nALLOWED_HOSTS = ["*"]', 'app/views.py': '@csrf_exempt\ndef hook(request): pass' });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.django': ['app/settings.py', 'app/views.py'] }) })[0];
    assert.equal(result.status, 'candidates');
    assert.ok(result.candidates.some((item) => item.ruleId === 'django-debug'));
    assert.ok(result.candidates.some((item) => item.ruleId === 'django-csrf-exempt'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Next public secret and Angular trust bypass are detected', () => {
  const root = fixture({
    'next.config.js': 'env: { NEXT_PUBLIC_API_SECRET: process.env.API_SECRET }',
    'src/component.ts': 'this.sanitizer.bypassSecurityTrustHtml(userHtml)',
  });
  try {
    const results = runFrameworkSuite({ root, plan: plan({ 'framework.next': ['next.config.js'], 'framework.angular': ['src/component.ts'] }) });
    assert.equal(results.find((item) => item.family === 'framework.next').status, 'candidates');
    assert.equal(results.find((item) => item.family === 'framework.angular').status, 'candidates');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('benign framework fixture emits no candidates', () => {
  const root = fixture({ 'src/app.py': 'from fastapi import FastAPI\napp = FastAPI()' });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.fastapi': ['src/app.py'] }) })[0];
    assert.equal(result.status, 'pass');
    assert.equal(result.candidates.length, 0);
    assert.equal(result.findings.length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// --- coverage corpora: framework.frontend and framework.backend -------------
// bench/corpora/frameworks/{frontend,backend} are the measured-pack corpora
// sealed against this file by scripts/seal-coverage-evidence.mjs.
import { analyzeFramework as analyzeFrontendFramework } from '../src/providers/frameworks/frontend/index.mjs';
import { analyzeFramework as analyzeBackendFramework } from '../src/providers/frameworks/backend/index.mjs';
import { fileURLToPath } from 'node:url';
import { runFrameworkCorpus } from './providers/framework-corpus.mjs';

runFrameworkCorpus({
  corpusRoot: fileURLToPath(new URL('../bench/corpora/frameworks/frontend/', import.meta.url)),
  run: ({ framework, ...input }, authority) => analyzeFrontendFramework(framework, input, authority),
});

runFrameworkCorpus({
  corpusRoot: fileURLToPath(new URL('../bench/corpora/frameworks/backend/', import.meta.url)),
  run: ({ framework, ...input }, authority) => analyzeBackendFramework(framework, input, authority),
});
