import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runFrameworkSuite } from '../providers/framework-suite.mjs';

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

test('Electron dangerous preferences are blocking findings', () => {
  const root = fixture({ 'src/main.ts': `new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } })` });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.electron': ['src/main.ts'] }) })[0];
    assert.equal(result.status, 'fail');
    assert.deepEqual(result.findings.map((item) => item.ruleId).sort(), ['electron-context-isolation', 'electron-node-integration']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Django debug and CSRF bypass are detected', () => {
  const root = fixture({ 'app/settings.py': 'DEBUG = True\nALLOWED_HOSTS = ["*"]', 'app/views.py': '@csrf_exempt\ndef hook(request): pass' });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.django': ['app/settings.py', 'app/views.py'] }) })[0];
    assert.equal(result.status, 'fail');
    assert.ok(result.findings.some((item) => item.ruleId === 'django-debug'));
    assert.ok(result.findings.some((item) => item.ruleId === 'django-csrf-exempt'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Next public secret and Angular trust bypass are detected', () => {
  const root = fixture({
    'next.config.js': 'env: { NEXT_PUBLIC_API_SECRET: process.env.API_SECRET }',
    'src/component.ts': 'this.sanitizer.bypassSecurityTrustHtml(userHtml)',
  });
  try {
    const results = runFrameworkSuite({ root, plan: plan({ 'framework.next': ['next.config.js'], 'framework.angular': ['src/component.ts'] }) });
    assert.equal(results.find((item) => item.family === 'framework.next').status, 'fail');
    assert.equal(results.find((item) => item.family === 'framework.angular').status, 'fail');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('benign framework fixture remains clean', () => {
  const root = fixture({ 'src/app.py': 'from fastapi import FastAPI\napp = FastAPI()' });
  try {
    const result = runFrameworkSuite({ root, plan: plan({ 'framework.fastapi': ['src/app.py'] }) })[0];
    assert.equal(result.status, 'pass');
    assert.equal(result.findings.length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
