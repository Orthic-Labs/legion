import assert from 'node:assert/strict';
import test from 'node:test';

test('B5-007 geometry tokens preserve denominators and evidence classes', async () => {
  const { analyzeGeometryTokens } = await import('../src/providers/visual/geometry-tokens.mjs');
  const result = analyzeGeometryTokens({ declaredScale: [4, 8, 16], instances: [
    { property: 'gap', value: 8, component: 'Card', source: 'card.css:1' },
    { property: 'gap', value: 13, component: 'Card', source: 'card.css:2', rendered: { surfaceId: 'home' } },
  ] });
  assert.equal(result.denominator, 2);
  assert.equal(result.candidates[0].affectedInstances.length, 1);
  assert.equal(result.candidates[0].evidenceClass, 'source+rendered');
  assert.equal(result.inventedStandard, false);
});

test('B5-008 typography binds role surface viewport locale and font gaps', async () => {
  const { analyzeTypography } = await import('../src/providers/visual/typography.mjs');
  const result = analyzeTypography({ textItems: [{ id: 'title', role: 'heading', surfaceId: 'home', viewport: 'mobile', locale: 'de', clipped: true }] });
  assert.deepEqual(result.findings[0].context, { role: 'heading', surfaceId: 'home', viewport: 'mobile', locale: 'de' });
  assert.ok(result.coverageGaps.includes('font-evidence-missing'));
});

test('B5-009 hierarchy separates deterministic mismatch from taste', async () => {
  const { analyzeHierarchy } = await import('../src/providers/visual/hierarchy-static.mjs');
  const empty = analyzeHierarchy();
  assert.equal(empty.status, 'unproven');
  assert.ok(empty.coverageGaps.includes('hierarchy-signals-missing'));
  const result = analyzeHierarchy({ signals: [{ component: 'Hero', source: 'hero.tsx:8', semanticRank: 1, visualRank: 3 }, { component: 'Hero', source: 'hero.tsx:9', strongPrimary: true }] });
  assert.equal(result.findings[0].judgmentClass, 'deterministic');
  assert.equal(result.candidates[0].judgmentClass, 'interpretive');
  assert.equal(result.candidates[0].evidenceLimitation, 'rendered-evidence-missing');
});

test('B5-010 responsive and stacking preserve untested viewports and safe-area gaps', async () => {
  const [{ analyzeResponsive }, { analyzeStacking }] = await Promise.all([import('../src/providers/visual/responsive.mjs'), import('../src/providers/visual/stacking.mjs')]);
  assert.equal(analyzeResponsive().status, 'unproven');
  assert.equal(analyzeStacking().status, 'unproven');
  const responsive = analyzeResponsive({ requiredViewports: ['desktop', 'mobile'], surfaces: [{ id: 'home', viewport: 'desktop', overflowX: true, safeAreaMeasured: false }] });
  assert.ok(responsive.coverageGaps.includes('viewport-untested:mobile'));
  assert.ok(responsive.coverageGaps.includes('safe-area-unmeasured:home:desktop'));
  assert.equal(responsive.findings[0].viewport, 'desktop');
  assert.equal(analyzeStacking({ contexts: [{ id: 'modal', zIndexChain: [1, 9999, 2] }] }).findings[0].ruleId, 'visual.stacking-fragile-chain');
});

test('B5-011 control states expose applicability and missing evidence', async () => {
  const { analyzeControlStates } = await import('../src/providers/ux/control-states.mjs');
  const empty = analyzeControlStates({ controls: [] });
  assert.equal(empty.status, 'unproven');
  assert.equal(empty.complete, false);
  const result = analyzeControlStates({ controls: [{ id: 'save', role: 'button', accessibleName: 'Save', applicableStates: ['default', 'focus-visible', 'loading'], observedStates: ['default'] }] });
  assert.deepEqual(result.applicability.save, ['default', 'focus-visible', 'loading']);
  assert.deepEqual(result.findings[0].missingStates, ['focus-visible', 'loading']);
  assert.equal(result.complete, false);
});

test('B5-012 UX flow preserves cohorts paths measurements and inferred goals', async () => {
  const [{ buildUxFlow }, { createFlowModel }] = await Promise.all([import('../src/lib/design/ux-flow.mjs'), import('../src/providers/ux/flow-model.mjs')]);
  const flow = buildUxFlow({ goal: 'Create project', goalSource: 'route', cohort: 'first-use', entrySurfaceId: 'home', steps: [{ surfaceId: 'home', action: 'new', expectedState: 'form', actualState: 'form' }], terminalState: 'unproven', measurements: { sample: 1, completionTimeMs: 900 }, alternatePaths: ['assistive-technology'] });
  assert.equal(flow.goalInferred, true);
  assert.equal(flow.measurements.sample, 1);
  assert.deepEqual(flow.alternatePaths, ['assistive-technology']);
  assert.equal(createFlowModel({ flows: [flow] }).requiredGoals.length, 0);
  assert.equal(createFlowModel({ flows: [] }).status, 'unproven');
  assert.equal(buildUxFlow({ goal: 'Save', entrySurfaceId: 'form', steps: [], terminalState: 'success' }).terminalState, 'unproven');
});

test('B5-013 navigation cites flow and route evidence without feature invention', async () => {
  const { analyzeNavigation } = await import('../src/providers/ux/navigation.mjs');
  const empty = analyzeNavigation();
  assert.equal(empty.status, 'unproven');
  assert.ok(empty.coverageGaps.includes('navigation-routes-missing'));
  const result = analyzeNavigation({ routes: [{ path: '/home', label: 'Home' }, { path: '/admin', label: 'Home' }], flows: [{ id: 'create', routes: ['/home'] }] });
  assert.ok(result.findings.some((item) => item.ruleId === 'ux.navigation-unreachable' && item.route === '/admin'));
  assert.ok(result.findings.every((item) => item.evidenceRefs.length > 0));
  assert.equal(result.suggestions.length, 0);
});

test('B5-014 forms bind field denominator and separate client validation from security', async () => {
  const { analyzeForms } = await import('../src/providers/ux/forms.mjs');
  const empty = analyzeForms({ forms: [] });
  assert.equal(empty.status, 'unproven');
  assert.equal(empty.fieldDenominator, 0);
  const result = analyzeForms({ forms: [{ id: 'login', fields: [{ id: 'email', label: null, applicableStates: ['default', 'invalid'], observedStates: ['default'] }], clientValidation: true }] });
  assert.equal(result.fieldDenominator, 1);
  assert.equal(result.findings[0].fieldId, 'email');
  assert.equal(result.serverSecurityProven, false);
});

test('B5-015 system states separate absent implementation from untested state', async () => {
  const { analyzeSystemStates } = await import('../src/providers/ux/system-states.mjs');
  assert.equal(analyzeSystemStates().status, 'unproven');
  const result = analyzeSystemStates({ surfaces: [{ id: 'feed', expectedStates: ['loading', 'error', 'offline'], declaredStates: ['loading', 'error'], observedStates: ['loading'] }] });
  assert.equal(result.denominator, 3);
  assert.ok(result.coverageGaps.includes('state-absent:feed:offline'));
  assert.ok(result.coverageGaps.includes('state-untested:feed:error'));
});

test('B5-016 recovery requires side-effect evidence for irreversible classification', async () => {
  const { analyzeRecovery } = await import('../src/providers/ux/recovery.mjs');
  assert.equal(analyzeRecovery().status, 'unproven');
  const result = analyzeRecovery({ actions: [{ id: 'delete', risk: 'high', claimedIrreversible: true, confirmation: false, sideEffectEvidence: null }] });
  assert.equal(result.actions[0].irreversible, 'unproven');
  assert.equal(result.findings[0].recoveryEvidence, 'missing');
});

test('B5-017 data interaction keeps scale and chart interpretation unproven', async () => {
  const { analyzeDataInteractions } = await import('../src/providers/ux/data-interaction.mjs');
  assert.equal(analyzeDataInteractions().status, 'unproven');
  const result = analyzeDataInteractions({ interactions: [{ id: 'orders', kind: 'table', dataset: 'orders', headersAccessible: false, largeDataClaim: true }, { id: 'sales', kind: 'chart', dataset: 'sales', misleadingEncoding: true }] });
  assert.ok(result.coverageGaps.includes('scale-evidence-missing:orders'));
  assert.equal(result.findings.find((item) => item.interactionId === 'sales').judgmentClass, 'interpretive');
});

test('B5-018 friction and deceptive design separate deterministic and interpretive evidence', async () => {
  const [{ analyzeFriction }, { analyzeDeceptiveDesign }] = await Promise.all([import('../src/providers/ux/friction.mjs'), import('../src/providers/trust-safety/deceptive-design.mjs')]);
  assert.equal(analyzeFriction().status, 'unproven');
  assert.equal(analyzeDeceptiveDesign().status, 'unproven');
  const friction = analyzeFriction({ flows: [{ id: 'cancel', policyContext: 'subscription', steps: [{ id: 's1', loopTo: 's1' }] }] });
  assert.equal(friction.findings[0].judgmentClass, 'deterministic');
  const deceptive = analyzeDeceptiveDesign({ choices: [{ id: 'renew', flowId: 'cancel', preselected: true, consequence: 'renewal', policyContext: 'subscription' }, { id: 'tone', flowId: 'cancel', confirmshaming: true, policyContext: 'unknown' }] });
  assert.equal(deceptive.findings[0].judgmentClass, 'deterministic');
  assert.equal(deceptive.candidates[0].judgmentClass, 'interpretive');
});

test('B5-020 runtime accessibility never passes missing engine or paths', async () => {
  const { analyzeRuntimeAccessibility } = await import('../src/providers/accessibility/runtime/core.mjs');
  const missing = analyzeRuntimeAccessibility({ engine: null, requiredCases: [{ surfaceId: 'home', state: 'default' }] });
  assert.equal(missing.status, 'unproven');
  assert.equal(analyzeRuntimeAccessibility({ engine: { name: 'axe', version: '1' } }).status, 'unproven');
  const result = analyzeRuntimeAccessibility({ engine: { name: 'axe', version: '1' }, requiredCases: [{ surfaceId: 'home', state: 'default' }, { surfaceId: 'home', state: 'modal' }], requiredExercises: ['keyboard', 'reduced-motion'], exercised: ['keyboard'], runs: [{ surfaceId: 'home', state: 'default', violations: [{ rule: 'label', rootCause: 'input-name', nodes: ['#email'] }] }] });
  assert.ok(result.coverageGaps.includes('runtime-case-untested:home:modal'));
  assert.ok(result.coverageGaps.includes('runtime-exercise-untested:reduced-motion'));
  assert.equal(result.findings[0].engineVersion, '1');
});

test('B5-021 runtime adapters are bounded redacted surface receipts', async () => {
  const [{ buildBrowserSurfaceReceipt }, { buildNativeSurfaceReceipt }] = await Promise.all([import('../src/providers/runtime/browser/adapter.mjs'), import('../src/providers/runtime/native-surface/adapter.mjs')]);
  const spec = { surfaceId: 'home', route: '/', allowedActions: ['open'], allowedDestinations: ['local'] };
  const receipt = buildBrowserSurfaceReceipt(spec, { actions: ['open'], requests: [{ destination: 'local', headers: { authorization: 'secret' }, body: { password: 'secret' } }], ready: false, reachedMeaningfulState: false });
  assert.equal(receipt.status, 'unproven');
  assert.equal(receipt.shallow, true);
  assert.equal(receipt.requests[0].headers.authorization, '[REDACTED]');
  assert.equal(receipt.requests[0].body.password, '[REDACTED]');
  assert.equal(buildNativeSurfaceReceipt({ surfaceId: 'settings', allowedActions: [] }, { bridgeAvailable: false }).status, 'blocked');
});

test('B5-022 visual capture binds digests and redacts sensitive values', async () => {
  const [{ captureVisualEvidence }, { normalizeGeometry }] = await Promise.all([import('../src/providers/visual/capture.mjs'), import('../src/lib/design/geometry.mjs')]);
  const { encodePng } = await import('../src/providers/visual-core.mjs');
  const screenshotBytes = encodePng({ width: 1, height: 1, rgba: Buffer.from([0, 0, 0, 255]) });
  const result = captureVisualEvidence({ surfaceId: 'login', screenshotBytes, dom: '<input value="secret">', sensitiveValues: ['secret'], browser: { name: 'x', version: '1' }, viewport: { width: 100, height: 100, scale: 1 }, state: 'default', binding: { plan: 'p1' }, geometry: [{ id: 'input', x: 1.2, y: 2.4, width: 20, height: 10 }] });
  assert.match(result.screenshot.digest, /^sha256:/);
  assert.equal(result.screenshot.width, 1);
  assert.doesNotMatch(result.raw.dom, /secret/);
  assert.doesNotMatch(result.normalized.dom, /secret/);
  assert.equal(normalizeGeometry(result.raw.geometry)[0].x, 1.2);
});

test('B5-023 geometry findings are measured and unsupported primitives remain gaps', async () => {
  const { analyzeGeometryEvidence } = await import('../src/providers/visual/geometry.mjs');
  const result = analyzeGeometryEvidence({ surfaceId: 'home', viewport: { width: 100, height: 100 }, elements: [{ id: 'button', x: 90, y: 0, width: 20, height: 20 }, { id: 'canvas', primitive: 'canvas' }] });
  assert.equal(result.findings[0].measurement.overflowRight, 10);
  assert.ok(result.coverageGaps.includes('unsupported-geometry:canvas:canvas'));
  assert.ok(analyzeGeometryEvidence({ surfaceId: 'home', viewport: { width: 100, height: 100 }, elements: [{ id: 'tap', x: 1, y: 1, width: 10, height: 10, touchTarget: true }] }).findings.some((item) => item.ruleId === 'visual.geometry-touch-target'));
});

test('B5-024 visual diff rejects identity mismatch and never auto-accepts', async () => {
  const [{ compareVisualEvidence }, { baselineIdentity }] = await Promise.all([import('../src/providers/visual/diff.mjs'), import('../src/lib/design/baselines.mjs')]);
  const base = { route: '/', state: 'default', viewport: 'desktop', platform: 'web', browserPolicy: 'chromium', baselineId: 'b1' };
  assert.match(baselineIdentity(base), /^sha256:/);
  const result = compareVisualEvidence({ baseline: base, actual: { ...base, viewport: 'mobile' }, pixel: { changed: 10 }, geometry: {}, text: {} });
  assert.equal(result.status, 'unproven');
  assert.equal(result.baselineAccepted, false);
  assert.equal(compareVisualEvidence({ baseline: base, actual: base }).status, 'unproven');
  assert.equal(compareVisualEvidence({ baseline: base, actual: base, masks: [{ id: 'clock' }] }).status, 'unproven');
});

test('B5-025 reviewer packets require fresh independent receipts and preserve uncertainty', async () => {
  const { buildReviewPacket, validateJudgmentReceipt } = await import('../src/providers/visual/reviewer.mjs');
  const packet = buildReviewPacket({ surfaceId: 'home', screenshots: ['shot'], route: '/', state: 'default', viewport: 'desktop', omittedEvidence: ['brand-context'] });
  assert.equal(packet.scope, 'surface');
  const result = validateJudgmentReceipt(packet, { reviewer: { provider: 'other', model: 'm', contextId: 'c', fresh: true }, rendererIdentity: 'renderer', evidenceRefs: ['shot'], verdict: 'UNPROVEN', counterargument: 'Could be intentional', uncertainty: ['brand'] });
  assert.equal(result.valid, true);
  assert.deepEqual(result.receipt.uncertainty, ['brand']);
  assert.ok(result.receipt.claimLimits.includes('brand-context-missing'));
  assert.equal(validateJudgmentReceipt(packet, { reviewer: { provider: 'same', model: 'm', contextId: 'c', fresh: true }, implementerIdentity: 'same', evidenceRefs: ['shot'], counterargument: 'x', uncertainty: [] }).valid, false);
});

test('B5-026 motion binds transitions timing and reduced-motion coverage', async () => {
  const { analyzeMotion } = await import('../src/providers/visual/motion.mjs');
  const result = analyzeMotion({ transitions: [{ id: 'open', from: 'closed', to: 'open', durationMs: 500, budgetMs: 300, blocksInteraction: true }], reducedMotionExercised: false });
  assert.equal(result.findings[0].transitionId, 'open');
  assert.ok(result.coverageGaps.includes('reduced-motion-unproven'));
});

test('B5-028 bundle network cache evidence keeps identity and correctness analysis', async () => {
  const [{ analyzeBundleEvidence }, { analyzeNetworkEvidence }, { analyzeCacheEvidence }] = await Promise.all([import('../src/providers/performance/bundle/core.mjs'), import('../src/providers/performance/network/core.mjs'), import('../src/providers/performance/cache/core.mjs')]);
  const bundle = analyzeBundleEvidence({ artifact: { id: 'app.js', digest: 'sha256:x' }, modules: [{ name: 'big', bytes: 500, duplicate: true }] });
  assert.equal(bundle.artifact.digest, 'sha256:x');
  const network = analyzeNetworkEvidence({ requests: [{ id: 'r1', url: '/api', durationMs: 100, serializedBehind: 'r0' }] });
  assert.equal(network.candidates[0].requestId, 'r1');
  const cache = analyzeCacheEvidence({ entries: [{ id: 'user', sensitive: true, mutable: true, ttl: 3600 }] });
  assert.equal(cache.candidates[0].kind, 'correctness-risk');
  assert.equal(cache.recommendations.length, 0);
});
