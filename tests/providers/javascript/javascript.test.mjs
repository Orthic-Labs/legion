import assert from 'node:assert/strict';
import test from 'node:test';
import jsPack, { jsFingerprint } from '../../../providers/native/javascript/index.mjs';
import reactPack from '../../../providers/frameworks/react/index.mjs';
import nextPack from '../../../providers/frameworks/next/index.mjs';
import { consoleErrorObservation, performanceObservation, runtimeReceipt } from '../../../providers/runtime/browser/index.mjs';

function projectionWith(parsedExtensions, deps = []) {
  return { parsedExtensions, auditFacts: { packageManifests: deps } };
}

test('js pack detects js/ts extensions', () => {
  assert.equal(jsPack.detect({ projection: projectionWith(['js', 'ts']) }), true);
  assert.equal(jsPack.detect({ projection: projectionWith(['py']) }), false);
});

test('js pack emits type-check and test commands from the denominator', () => {
  const commands = jsPack.commands({ root: '/repo', files: ['src/a.ts', 'src/a.test.ts'], manifests: ['package.json'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'js.types'));
  assert.ok(commands.some((c) => c.id === 'js.test'));
  // fast profile skips the build command.
  const fast = jsPack.commands({ root: '/repo', files: ['src/a.ts'], manifests: ['package.json'], profile: 'fast' });
  assert.ok(!fast.some((c) => c.id === 'js.build'));
});

test('js pack normalizes execution to a provider result', () => {
  const result = jsPack.normalize({ commandId: 'js.types', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(result.status, 'pass');
  assert.equal(result.complete, true);
});

test('js fingerprint is stable', () => {
  assert.equal(jsFingerprint({ file: 'a.ts', line: 3, ruleId: 'r' }), jsFingerprint({ file: 'a.ts', line: 3, ruleId: 'r' }));
  assert.ok(jsFingerprint({ file: 'a.ts', line: 3, ruleId: 'r' }).startsWith('sha256:'));
});

test('react pack detects react dependency', () => {
  assert.equal(reactPack.detect({ projection: projectionWith(['tsx'], [{ name: 'react' }]) }), true);
  assert.equal(reactPack.detect({ projection: projectionWith(['tsx'], []) }), false);
});

test('react pack flags conditional hooks and missing deps', () => {
  const files = ['App.tsx'];
  const readFile = () => 'if (cond) { useEffect(() => { run(); }) }';
  const observations = reactPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'react.hooks.conditional-call'));
  assert.ok(observations.some((o) => o.ruleId === 'react.effects.missing-deps'));
});

test('react pack flags a11y and dangerous HTML', () => {
  const files = ['App.tsx'];
  const readFile = () => '<img src="x" /> <div dangerouslySetInnerHTML={{__html: html}} />';
  const observations = reactPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'react.a11y.img-alt'));
  assert.ok(observations.some((o) => o.ruleId === 'react.security.dangerous-html'));
});

test('react pack emits no observations for clean code', () => {
  const observations = reactPack.analyze({ files: ['Clean.tsx'], readFile: () => 'function App() { return <div>hi</div>; }' });
  assert.deepEqual(observations, []);
});

test('next pack detects next dependency', () => {
  assert.equal(nextPack.detect({ projection: projectionWith(['tsx'], [{ name: 'next' }]) }), true);
});

test('next pack flags routes without auth', () => {
  const files = ['app/api/projects/route.ts'];
  const readFile = () => 'export async function GET(request, { params }) { return Response.json(params) }';
  const observations = nextPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'next.route.missing-auth'));
});

test('next pack accepts routes with visible auth', () => {
  const files = ['app/api/projects/route.ts'];
  const readFile = () => 'export async function GET(request) { const s = await getServerSession(authOptions); return Response.json(s) }';
  const observations = nextPack.analyze({ files, readFile });
  assert.ok(!observations.some((o) => o.ruleId === 'next.route.missing-auth'));
});

test('browser runtime receipt reports shallow traversal as a gap', () => {
  const receipt = runtimeReceipt({ surfacesFound: 5, surfacesTested: 2, shallow: true });
  assert.equal(receipt.complete, false);
  assert.ok(receipt.coverageGaps.some((g) => g.kind === 'runtime-shallow-traversal'));
});

test('browser runtime receipt is complete only when fully tested', () => {
  const receipt = runtimeReceipt({ surfacesFound: 3, surfacesTested: 3, consoleErrors: 0 });
  assert.equal(receipt.complete, true);
});

test('performance observation flags long tasks and slow interactions', () => {
  const bad = performanceObservation({ surface: 'home', longTasks: 2, interactionLatencyMs: 500 });
  assert.equal(bad.violated, true);
  const good = performanceObservation({ surface: 'home', longTasks: 0, interactionLatencyMs: 80 });
  assert.equal(good.violated, false);
});

test('console error observation is structured', () => {
  const error = consoleErrorObservation({ file: 'app.ts', message: 'TypeError', surface: 'home' });
  assert.equal(error.kind, 'nemesis-console-error');
  assert.equal(error.message, 'TypeError');
});
