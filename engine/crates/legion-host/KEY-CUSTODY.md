# Arcane key custody (S03)

This document is the custody, rotation, revocation, and threat-model story
`lib/keys.mjs` points to. It covers the HMAC keys `KeyRing` holds and that
`lib/receipt-auth.mjs` signs/verifies receipts with. It does not cover
process-identity/code-signing host trust (`lib/host.js` in legacy predecessor,
carried forward as `verificationMethod: 'host-connection-trust'` on a
receipt's `authentication` block) — that is a different, connection-level
primitive with its own story (S00 baseline finding 2), not a key at all.

## Where key material lives

- **Host-held key files**, one per key, loaded by `loadHostKeyRing({ dir })`:
  `<dir>/<keyId>.key` holds hex-encoded raw key bytes; an optional sibling
  `<dir>/<keyId>.json` holds non-secret metadata (`createdAt`, `custody`,
  `status`). `dir` is chosen by the host process at startup — Arcane never
  hard-codes a path, invents one, or falls back to an unrelated location if
  the directory is absent. Absence, or a directory with no `.key` file, is
  `ARC_AUTH_KEY_UNAVAILABLE` (fail-closed), never a fabricated key.
- **Test fixtures**: `generateTestKeyRing(seedIds)` generates random 32-byte
  keys entirely in memory, tagged `custody: 'test-fixture:generateTestKeyRing'`.
  These never touch disk and must never be pointed at a real signing path.
  Every test in this package uses only this function or an equivalent
  in-memory `KeyRing` — no test reads or writes a real credential.
- **In-process only, after loading.** Once a key is in a `KeyRing`, it lives
  as a `Buffer` in process memory for the life of that process. `KeyRing` has
  no persistence, export, or serialization path of its own.

## Who can read it

- Signing identity is scoped per `(host, harness)`. A verifier loads a set of
  keyring directories, so adding a harness adds one directory instead of a
  hard-coded pair. Repeated key IDs must carry identical bytes across every
  directory; conflicting bytes fail closed as `ARC_AUTH_KEY_UNAVAILABLE`.

- Whoever can read the host key directory can read key material — the same
  filesystem-permission boundary as any other host secret. `loadHostKeyRing`
  does not add its own access control layer; it trusts the OS to have
  already scoped that directory to the intended reader.
- Inside the process, `KeyRing.get(keyId)` is the only function that returns
  key bytes. `KeyRing.list()` returns metadata only (`keyId`, `createdAt`,
  `custody`, `status`, `revokedAt`, `revokedReason`) and is safe to log.
  Nothing in `lib/keys.mjs` or `lib/receipt-auth.mjs` writes key bytes into
  an `ArcaneError.detail`, a receipt, or a log line — if you ever see raw
  key material in output, that is a bug in the caller, not intended behavior
  of this module.

## Rotation

- Add the new key under a new `keyId` (a new `<keyId>.key` file, or
  `ring.add(newKeyId, ...)` for an in-memory ring) with a later `createdAt`
  than every existing active key. `activeKeyId()` always returns the newest
  non-revoked key, so new signing operations pick it up automatically without
  code changes.
- Verification (`verifyRecord`) resolves the key by the `keyId` carried on
  the record's `authentication` block, not by "whatever is active now" — so
  receipts already signed under an older key continue to verify after
  rotation, right up until that key is explicitly revoked.
- There is no automatic time-based expiry on a key itself (only on
  capabilities, via `CapabilityStore`'s `expiresAt`/`maxUses`). Rotation is
  an operational act — add a new key, start using it, then revoke the old
  one once nothing still needs to verify against it.

## Revocation

- `KeyRing.revoke(keyId, reason)` marks a key `status: 'revoked'` and records
  `revokedAt`/`revokedReason`. A revoked key is not deleted from the ring —
  its metadata (via `list()`) stays inspectable for incident review — but
  `KeyRing.get()` treats it exactly like an unknown key: `ARC_AUTH_KEY_UNAVAILABLE`,
  fail-closed. `signRecord` can no longer sign with it. `verifyRecord`
  surfaces a live revocation explicitly as `ARC_CAPABILITY_REVOKED` when the
  `keyId` on the record's auth block resolves to a revoked entry, so a
  revocation incident is distinguishable from routine unavailability in an
  audit trail.
- Revoking a key does not retroactively invalidate receipts already verified
  and stored — `ReceiptStore` is an append-only history, and a revocation is
  a new fact about the present, not a rewrite of the past. Anything that
  depends on "was this receipt trustworthy" after a revocation is a policy
  question for the consumer (e.g. re-running `verifyChain()`/an incident
  review), not something this module silently resolves.

## Threat model

`KeyRing` and `lib/receipt-auth.mjs` defend against a network or
cross-process adversary who can observe or replay messages but does not hold
the host's signing key: forged MACs, altered signed fields, shrunk-and-resigned
bound-field lists, legacy self-hashes presented as authentication, and
messages bound to the wrong run/session/workspace/operation are all rejected
(see `tests/s03-receipt-auth.test.mjs`, `tests/s03-replay.test.mjs`).

**This is not an absolute cryptographic guarantee, and the threat model must
say so explicitly: a same-user unrestricted shell can
still undermine local isolation.** If a process runs as the same OS user as
the host process that holds a `KeyRing`, it can, in principle, read the same
`.key` files `loadHostKeyRing` reads, inspect the host process's memory, or
intercept a key before it is ever loaded — none of which this module can
detect or prevent from inside the process. HMAC-SHA256 verification proves
"whoever signed this held the key", not "the key was never accessible to
anything else running as this user." Arcane's authentication story is a
boundary against a different-identity or different-process-integrity
adversary (forged messages, replay, tampering in transit or at rest); it is
not a defense against a fully co-resident attacker with the same OS-user
privileges as the signer. Anything that needs that stronger guarantee needs
OS-level process isolation, a hardware key store, or a remote signer — none
of which are in scope for Arcane's v1 host-held-key design, and none of
which this document claims to provide.
