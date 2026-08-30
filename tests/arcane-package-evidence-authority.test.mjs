import assert from 'node:assert/strict';
import test from 'node:test';

import { EvidenceAuthorityRegistry, classifyTechnologyRequirement, resolveLatencyTarget } from '../src/lib/cli/commands/governance/execution/evidence-authority.mjs';

const unbacked = new EvidenceAuthorityRegistry();
const authorized = new EvidenceAuthorityRegistry({
  latencyTargets: [{ authorityId: 'product-slo-v1', scopeId: 'checkout', targetMs: 250 }],
  technologyConstraints: [{ authorityId: 'platform-residency-v1', scopeId: 'payments', technology: 'Kubernetes', consequence: 'regional-isolation' }],
});

test('AE-EVIDENCE-001 rejects an invented numeric latency target', () => {
  const result = resolveLatencyTarget({ scopeId: 'checkout', targetMs: 200, assumption: null, authorityRequest: null }, { registry: unbacked });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_EVIDENCE_INSUFFICIENT');
  assert.equal(result.detail.disposition, 'AUTHORITY_REQUEST');
  assert.equal(result.detail.reason, 'UNAUTHORIZED_NUMERIC_TARGET');
});

test('AE-EVIDENCE-001 makes missing latency authority explicit without inventing a number', () => {
  const assumed = resolveLatencyTarget({ scopeId: 'checkout', targetMs: null, assumption: { id: 'assume-latency', rationaleDigest: 'sha256:research-gap' }, authorityRequest: null }, { registry: unbacked });
  const requested = resolveLatencyTarget({ scopeId: 'checkout', targetMs: null, assumption: null, authorityRequest: { id: 'ask-product', question: 'What latency target is authorized?' } }, { registry: unbacked });
  assert.equal(assumed.detail.disposition, 'ASSUMPTION');
  assert.equal(requested.detail.disposition, 'AUTHORITY_REQUEST');
  assert.equal(Object.hasOwn(assumed.detail, 'targetMs'), false);
});

test('AE-EVIDENCE-001 accepts only exact host-authorized numeric target', () => {
  assert.equal(resolveLatencyTarget({ scopeId: 'checkout', targetMs: 250, assumption: null, authorityRequest: null }, { registry: authorized }).detail.disposition, 'CONSTRAINT');
  assert.equal(resolveLatencyTarget({ scopeId: 'checkout', targetMs: 300, assumption: null, authorityRequest: null }, { registry: authorized }).code, 'ARC_BINDING_MISMATCH');
});

test('AE-EVIDENCE-002 classifies unbacked Kubernetes as preference, never constraint', () => {
  const result = classifyTechnologyRequirement({ scopeId: 'payments', technology: 'Kubernetes', consequence: null }, { registry: unbacked });
  assert.equal(result.allowed, true);
  assert.equal(result.detail.classification, 'PREFERENCE');
});

test('AE-EVIDENCE-002 requires exact host authority plus consequence for constraint', () => {
  assert.equal(classifyTechnologyRequirement({ scopeId: 'payments', technology: 'Kubernetes', consequence: 'regional-isolation' }, { registry: authorized }).detail.classification, 'CONSTRAINT');
  assert.equal(classifyTechnologyRequirement({ scopeId: 'payments', technology: 'Kubernetes', consequence: 'cost-saving' }, { registry: authorized }).detail.classification, 'PREFERENCE');
});

test('evidence authority rejects caller classification fields & malformed authority records', () => {
  assert.equal(classifyTechnologyRequirement({ scopeId: 'payments', technology: 'Kubernetes', consequence: null, classification: 'CONSTRAINT' }, { registry: unbacked }).code, 'ARC_SCHEMA_INVALID');
  assert.throws(() => new EvidenceAuthorityRegistry({ latencyTargets: [{ authorityId: 'self', scopeId: 'checkout', targetMs: '250' }] }), /invalid host evidence-authority records/);
});
