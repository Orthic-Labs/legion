import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runNativeFamilies } from '../src/providers/native-family-runner.mjs';

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-native-'));
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), content);
  }
  return root;
}

function plan(families) {
  return { coverageFamilies: Object.entries(families).map(([id, paths]) => ({ id, denominator: { paths } })) };
}

test('Laravel provider detects mass-assignment and raw SQL hazards', () => {
  const root = fixture({
    'composer.json': '{"require":{"laravel/framework":"^12"}}',
    'app/Service.php': '<?php Model::unguard(); DB::unprepared($sql);',
  });
  try {
    const results = runNativeFamilies({ root, plan: plan({ 'language.php': ['composer.json', 'app/Service.php'], 'framework.laravel': ['composer.json', 'app/Service.php'] }) });
    const laravel = results.find((item) => item.family === 'framework.laravel');
    assert.equal(laravel.status, 'fail');
    assert.deepEqual(laravel.findings.map((item) => item.ruleId).sort(), ['laravel-raw-sql', 'laravel-unguard']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('ASP.NET and Spring framework checks are deterministic', () => {
  const root = fixture({
    'Api/Program.cs': 'services.AddCors(x => x.AllowAnyOrigin().AllowCredentials());',
    'src/Security.java': 'http.csrf(csrf -> csrf.disable()); requestMatchers("/admin").permitAll();',
  });
  try {
    const results = runNativeFamilies({ root, plan: plan({
      'framework.aspnet': ['Api/Program.cs'],
      'framework.spring': ['src/Security.java'],
    }) });
    assert.equal(results.find((item) => item.family === 'framework.aspnet').status, 'fail');
    assert.equal(results.find((item) => item.family === 'framework.spring').status, 'fail');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('missing native toolchain is UNPROVEN, never clean', () => {
  const root = fixture({ 'src/main.go': 'package main' });
  try {
    const oldPath = process.env.PATH;
    process.env.PATH = '';
    const results = runNativeFamilies({ root, plan: plan({ 'language.go': ['src/main.go'] }) });
    process.env.PATH = oldPath;
    const go = results.find((item) => item.family === 'language.go');
    assert.equal(go.status, 'unproven');
    assert.equal(go.complete, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Tailwind dynamic class construction is surfaced', () => {
  const root = fixture({ 'src/App.tsx': 'return <div className={`bg-${tone}`}/>' });
  try {
    const results = runNativeFamilies({ root, plan: plan({ 'framework.tailwind': ['src/App.tsx'] }) });
    const tailwind = results.find((item) => item.family === 'framework.tailwind');
    assert.ok(tailwind.findings.some((item) => item.ruleId === 'tailwind-dynamic-class'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('React provider catches dangerous HTML and missing effect cleanup', () => {
  const root = fixture({
    'src/App.tsx': `import { useEffect } from 'react';\nexport function App(){ useEffect(()=>{ window.addEventListener('resize', resize); }, []); return <div dangerouslySetInnerHTML={{__html: html}}/> }`,
  });
  try {
    const results = runNativeFamilies({ root, plan: plan({ 'framework.react': ['src/App.tsx'] }) });
    const react = results.find((item) => item.family === 'framework.react');
    assert.equal(react.status, 'pass');
    assert.ok(react.findings.some((item) => item.ruleId === 'react-dangerous-html'));
    assert.ok(react.findings.some((item) => item.ruleId === 'react-effect-cleanup'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Tauri provider compares invoke calls against registered commands', () => {
  const root = fixture({
    'src/App.tsx': `invoke('delete_everything')`,
    'src-tauri/src/lib.rs': `#[tauri::command]\nfn safe_command() {}`,
    'src-tauri/tauri.conf.json': '{}',
  });
  try {
    const results = runNativeFamilies({ root, plan: plan({ 'framework.tauri': ['src/App.tsx', 'src-tauri/src/lib.rs', 'src-tauri/tauri.conf.json'] }) });
    const tauri = results.find((item) => item.family === 'framework.tauri');
    assert.equal(tauri.status, 'fail');
    assert.ok(tauri.findings.some((item) => item.ruleId === 'tauri-unregistered-command'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
