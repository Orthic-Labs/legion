# Arcane internal interfaces (lane E-ARCANE)

This file is the seam contract between the sub-deliverables of the Arcane
package. It exists so S03/S04/S05 can be built concurrently without importing
each other's half-finished internals. **Signatures here are binding**: if a
sub-deliverable needs to change one, it stops and reports rather than
silently diverging.

Everything below is deterministic code. No module in `packages/arcane/` may
call a model, add an npm dependency, or read a credential.

## Shared foundation (already built — import, do not reimplement)

| Module | Exports |
|---|---|
| `lib/errors.mjs` | `ArcaneError`, `arcErr(code, msg, detail)`, `decision({allowed, code, message, detail, enforcementHealth})`, `ARCANE_ERROR_CODE`, `ENFORCEMENT_LEVEL` |
| `lib/canonical.mjs` | `canonicalJson(v)`, `digest(str)`, `digestValue(v)`, `sha256Hex`, `constantTimeEqual(a,b)`, `projectBoundFields(rec, fields)`, `isDigest`, `DIGEST_PATTERN` |
| `lib/ids.mjs` | `mintId(family)`, `isId(family, v)`, `assertId(family, v)`, `ulid()`, `ID_PATTERN`, `HANDLE_PREFIX` |
| `lib/validate.mjs` | `validateAgainst(schemaName, value) -> {valid, issues}`, `assertValid(schemaName, value)`, `loadSchema(name)` |
| `lib/kernel-binding.mjs` | `bindKernel`, `unbindKernel`, `kernelBound()`, `kernelStatus()`, `mintId(family) -> {id, provisional}`, `appendEvent/readObject/putObject` (fail closed when unbound), `ARCANE_NAMESPACE` |

`decision()` is the return shape for every *gate*. `ArcaneError` is thrown only
for malformed input and fail-closed conditions. A denial is data, not an
exception.

## S03 — authenticated receipts (owner: S03)

### `lib/keys.mjs`

```js
export class KeyRing {
  constructor();
  add(keyId, keyMaterial /* Buffer */, meta = {}); // meta: {createdAt, custody, status}
  get(keyId);                 // -> {keyId, key: Buffer, custody, status} | throws ARC_AUTH_KEY_UNAVAILABLE
  has(keyId);
  revoke(keyId);
  activeKeyId();              // newest non-revoked
  list();                     // metadata only — NEVER key material
}
export function loadHostKeyRing({ dir }); // reads host-held key files; ARC_AUTH_KEY_UNAVAILABLE if absent
export function generateTestKeyRing(seedIds = ['k1']); // fixtures only, random material
```

Key material never appears in a log line, an error `detail`, a receipt, or
`list()` output. Custody model documented in `KEY-CUSTODY.md` (S03 writes it).

### `lib/receipt-auth.mjs`

```js
export const EFFECT_RECEIPT_BOUND_FIELDS;   // string[] — fields covered by the MAC
export const EVIDENCE_RECEIPT_BOUND_FIELDS; // string[]

export function signRecord(record, { keyRing, keyId, boundFields });
// -> { alg: 'HMAC-SHA256', keyId, mac: '<hex>', boundFieldsDigest: 'sha256:...' }

export function verifyRecord(record, auth, { keyRing, boundFields, expectedBinding = {} });
// -> decision(...) ; expectedBinding may constrain runId/taskId/workspace/operation/sessionId
```

- MAC is `HMAC-SHA256(key, canonicalJson(projectBoundFields(record, boundFields)))`.
- Verification is constant-time (`constantTimeEqual`).
- `boundFieldsDigest` binds the *field list itself*, so an attacker cannot
  shrink the covered set and re-sign.
- A record whose only authentication material is a legacy predecessor
  `signature_or_mac` string is rejected with `ARC_AUTH_LEGACY_DIGEST` — never
  upgraded, never treated as authenticated (S00 finding 1).

### `lib/replay.mjs`

```js
export class ReplayGuard {
  constructor({ freshnessWindowSeconds = 300, maxSkewSeconds = 60, clock = () => Date.now(), maxEntries = 100000 });
  check({ scope, nonce, sequence, timestamp }); // -> decision(...)
  // scope: { issuerId, sessionId, runId, workspaceId } — composite cache key
  size(); prune();
}
export function scopeKey(scope); // stable string form
```

Rejects: `ARC_REPLAY_NONCE_SEEN`, `ARC_REPLAY_SEQUENCE_REGRESSION` (sequence
must be strictly increasing per scope), `ARC_REPLAY_STALE` (older than the
freshness window, or further in the future than `maxSkewSeconds`).

### `lib/receipt-store.mjs`

```js
export class ReceiptStore {
  constructor({ root });           // root dir; creates <root>/receipts.jsonl + <root>/objects/
  append(record);                  // -> { sequence, recordDigest, prevDigest }
  get(receiptId);                  // -> record | null
  list({ runId } = {});            // -> record[]
  verifyChain();                   // -> { ok, length, corruptAt: number|null, reason }
  quarantine(sequence, reason);    // moves the corrupt unit aside; history stays readable
  quarantined();                   // -> entries[]
}
```

Append-only JSONL. Each line: `{ sequence, at, recordDigest, prevDigest, record }`.
Atomic write (temp file + `rename`) and owner-only mode where the platform
supports it. `verifyChain()` is the independent verification operation the
detailed plan §5.2 requires. Corruption never truncates history (§5.3).

**Capabilities** live here too:

```js
export class CapabilityStore {
  issue({ capabilityId, runId, taskId, workspace, operation, effectClass, targets, policyDigest, expiresAt, maxUses });
  check(capabilityId, { operation, effectClass, target, runId, taskId, workspace, now });
  // -> decision(...) ; ARC_CAPABILITY_{UNKNOWN,EXPIRED,EXHAUSTED,REVOKED}, ARC_BINDING_MISMATCH
  consume(capabilityId);
  revoke(capabilityId, reason);
}
```

## S04 — host-event ingestion (owner: S04)

### `lib/host-event.mjs`

```js
export const HOST_EVENT_SCHEMA;      // closed JSON Schema, additionalProperties:false, `extensions` object is the only open bag
export function validateHostEvent(e); // -> {valid, issues}
export function normalizeHostEvent(raw, { adapter }); // -> canonical host event | throws ARC_HOST_EVENT_INVALID
export const EFFECT_OBSERVATION_CLASS = ['mutation-observation','deterministic-check-candidate','source-observation','failure','non-qualifying-telemetry'];
export function classifyObservation(event, { policy }); // -> one of the above
```

### `lib/ingest.mjs`

```js
export class HostIngestor {
  constructor({ receiptStore, capabilityStore, replayGuard, keyRing, policy, clock });
  ingest(hostEvent, { authorityAssertion });
  // -> { accepted: boolean, receipt: EffectReceipt|null, observationClass, decision }
}
```

Hard rules (each needs its own negative test):
- `authorityAssertion.assertedBy === 'model'`, or any authority value read out
  of a model-controlled payload → `ARC_MODEL_SELF_REPORT`. A model self-report
  is never a receipt (ARCHITECTURE §24a).
- `authority === 'host'` plus a non-empty `receipt` string is **not** sufficient
  — the receipt must validate structurally *and* verify under
  `verifyRecord` (this is S00 finding 5, and closing it is the point of S04).
- Duplicate delivery of the same `idempotencyKey` returns the original receipt
  with `accepted: true` and appends nothing new.
- A post-effect event with no correlated pre-effect request →
  `ARC_INGEST_CORRELATION_MISSING`.
- An unknown command exiting 0 classifies as `source-observation` or
  `non-qualifying-telemetry`, never as a check candidate.
- A `FILE_WRITE`/`FILE_MOVE`/`FILE_DELETE` observation is a
  `mutation-observation` and never proves correctness.

Emitted receipts must satisfy `effect-receipt-v1` (`assertValid`), with
`authentication.perMessage: true` and `verificationMethod: 'capability-signature'`
when S03 verified the message, and `'host-connection-trust'` + `perMessage:false`
when only connection-level trust was available (an honest downgrade, per §24a).

## S05 — evidence envelope + invalidation (owner: S05)

### `lib/evidence-envelope.mjs`

```js
export const DEPENDENCY_DIMENSION;   // full set (see note below)
export function sealEvidence({ runId, taskId, contractId, producerAuthority, capability, observation,
                               evidenceClass, sourceRevision, dependencies, authentication, replayDefense, observedAt });
// -> { receipt /* valid evidence-capability-receipt-v1 */, envelope /* Arcane-side, richer */ }
export function envelopeDigest(envelope);
```

**Frozen-contract constraint:** `evidence-capability-receipt-v1.dependsOn[].kind`
is a closed 6-value enum (`decision | source-revision | config-digest |
tool-digest | policy-digest | evidence`). The detailed plan §6.2 requires far
more dimensions (lockfile, worktree dirty state, environment/platform, method
fingerprint, tool/provider version, topology, approval authority, upstream
contract revision, external source revision). Do **not** edit the frozen
package. Instead: carry the full dimension set on the Arcane-side `envelope`,
project it down to the 6 legal `kind` values on the receipt (documenting the
projection table in code), and file the enum extension as a **proposed contract
amendment** in the lane report. Every dimension that has no lossless projection
must be named in that amendment.

### `lib/invalidation.mjs`

```js
export class DependencyLedger {
  constructor({ clock });
  register(evidenceId, dependencies);        // dependencies: [{dimension, ref, digest}]
  link(evidenceId, { criterionId, claimId }); // proof/claim eligibility edges
  observeChange({ dimension, ref, digest });  // -> InvalidationEvent
  isStale(evidenceId);
  proofEligibility(criterionId);              // -> {proven|unproven|insufficient, reasons, staleEvidence[]}
  snapshot();
}
```

`observeChange` emits **one** structured invalidation event:
`{ eventId, at, changed: {dimension, ref, from, to}, staledEvidence: [], cascadedEvidence: [], affectedCriteria: [], affectedClaims: [], unaffected: [] }`.

- Cascade is transitive through `dimension: 'evidence'` edges (S00 finding: predecessor
  had **no** cascade at all — this is new work, not a port).
- Historical evidence is preserved; staleness is a new fact appended, never a
  silent refresh (detailed plan §6.3 rule 7).
- Unaffected evidence must be provably unaffected — the test asserts on the
  `unaffected` list, not just on the staled one.

## Test + evidence conventions (PROTOCOL)

- Test files: `tests/s03-*.test.mjs`, `tests/s04-*.test.mjs`, `tests/s05-*.test.mjs`.
- Run from the legion repo root: `node --test packages/arcane/tests/<file>`.
- Red log: `qualification/evidence/lanes/E-ARCANE/<ID>.red.log`
  (test written, implementation absent/failing).
- Green log: `qualification/evidence/lanes/E-ARCANE/<ID>.green.log`.
- Fixtures under `packages/arcane/fixtures/`. Test keys are *generated*
  fixtures; no real credential is ever read or written.
- Never touch `packages/contracts/`, `qualification/book-*.json`, another
  lane's paths, or run any git command.
