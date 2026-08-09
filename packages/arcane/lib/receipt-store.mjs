// S03 — append-only receipt store + capability store.
//
// Detailed plan §5.1: "Use the Legion workspace store with Sentinel namespace
// and shared immutable object pool. Do not create an unrelated
// Forge/Sentinel state root as the new authority." Lane D (Kernel) has not
// landed at the time this module was written (see lib/kernel-binding.mjs),
// so `ReceiptStore` is Arcane's own local journal under its namespace root —
// designed, per kernel-binding.mjs, to be re-parented onto the Kernel event
// store later by swapping that binding, not a second permanent authority.
// That is a recorded, typed condition, not a design claim of finality.
//
// Store properties preserved from what was worth keeping in Forge (§5.1):
// append-only logical event history, atomic write/rename, owner-only
// permissions where the platform supports them, and an independent
// verification operation. §5.2 tamper evidence: canonical event
// serialization (lib/canonical.mjs, never hand-rolled here), a per-record
// digest, a monotonic sequence, and a previous-digest hash chain over the
// full stored entry (not just the record payload), so tampering with the
// envelope fields (`sequence`, `at`, `prevDigest` itself) is caught exactly
// like tampering with `record`.
//
// §5.3 corruption handling: `quarantine()` never truncates the file. It
// replaces the corrupt line in place with a small tombstone (so byte offsets
// of every other line are undisturbed) and copies the original raw bytes
// into `<root>/quarantine.jsonl` for forensics. Every record before the
// quarantined sequence stays fully readable and verifiable exactly as it was
// before the incident — `verifyChain()` intentionally does not require
// continuity of the hash chain *across* a tombstone (that would require
// rewriting every entry appended after the corruption, which this store must
// never do), but does resume strict chain checking from the entry
// immediately after the tombstone onward.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';

import { ArcaneError, decision } from './errors.mjs';
import { digestValue } from './canonical.mjs';

function readLines(path) {
  if (!existsSync(path)) return [];
  const content = readFileSync(path, 'utf8');
  return content.split('\n').filter((l) => l.length > 0);
}

function writeAtomic(dir, path, content) {
  const tmp = join(dir, `.tmp-${randomBytes(8).toString('hex')}`);
  writeFileSync(tmp, content, 'utf8');
  try {
    // Owner-only mode where the platform supports it (POSIX). Windows
    // ignores the numeric mode entirely — this is a best-effort call, not a
    // guarantee, and nothing downstream treats it as one.
    chmodSync(tmp, 0o600);
  } catch {
    // degrade honestly: no owner-only enforcement available on this platform
  }
  renameSync(tmp, path);
}

export class ReceiptStore {
  #root;
  #receiptsPath;
  #quarantinePath;
  #headPath;

  constructor({ root }) {
    if (!root || typeof root !== 'string') {
      throw new ArcaneError('ARC_STORE_CORRUPT', 'ReceiptStore requires a root directory path', {});
    }
    this.#root = root;
    mkdirSync(root, { recursive: true });
    mkdirSync(join(root, 'objects'), { recursive: true });
    this.#receiptsPath = join(root, 'receipts.jsonl');
    this.#quarantinePath = join(root, 'quarantine.jsonl');
    this.#headPath = join(root, 'chain-head.json');
    if (!existsSync(this.#receiptsPath)) writeAtomic(root, this.#receiptsPath, '');
    if (!existsSync(this.#quarantinePath)) writeAtomic(root, this.#quarantinePath, '');
  }

  /**
   * The head anchor: `{sequence, entryDigest}` for the newest appended entry.
   *
   * A forward-only hash chain cannot detect two attacks, because nothing links
   * *to* the newest entry:
   *   - rewriting the last entry and recomputing its own recordDigest;
   *   - truncating entries off the end.
   * The second is exactly what detailed plan §5.3 forbids ("never truncate
   * history merely to get a green result"), so silent truncation would defeat
   * the store's whole purpose.
   *
   * The anchor closes both by recording the expected head out of band.
   *
   * HONEST LIMIT: the anchor lives in the same directory under the same
   * ownership, so an adversary who can rewrite `receipts.jsonl` can also
   * rewrite `chain-head.json`. This raises the bar against accidental
   * truncation, partial writes, and careless tampering — it is NOT a defence
   * against a same-user adversary, which KEY-CUSTODY.md already states is out
   * of scope for v1. Real defence needs the anchor somewhere Arcane does not
   * control (Kernel event store, or an external notary).
   */
  #readHead() {
    if (!existsSync(this.#headPath)) return null;
    try {
      return JSON.parse(readFileSync(this.#headPath, 'utf8'));
    } catch {
      return null;
    }
  }

  #writeHead(sequence, entryDigest) {
    writeAtomic(this.#root, this.#headPath, `${JSON.stringify({ sequence, entryDigest })}\n`);
  }

  /**
   * @param {object} record any Arcane record (effect receipt, evidence
   *   receipt, etc.) — this store is generic over payload shape.
   * @returns {{sequence: number, recordDigest: string, prevDigest: string|null}}
   */
  append(record) {
    const lines = readLines(this.#receiptsPath);
    const nextSequence = lines.length + 1;

    let prevDigest = null;
    if (lines.length > 0) {
      let lastEntry;
      try {
        lastEntry = JSON.parse(lines[lines.length - 1]);
      } catch (err) {
        throw new ArcaneError('ARC_STORE_CORRUPT', 'cannot append: last stored entry is unreadable', {
          sequence: lines.length,
          parseError: String(err && err.message),
        });
      }
      prevDigest = digestValue(lastEntry);
    }

    const recordDigest = digestValue(record);
    const entry = { sequence: nextSequence, at: new Date().toISOString(), recordDigest, prevDigest, record };

    lines.push(JSON.stringify(entry));
    writeAtomic(this.#root, this.#receiptsPath, lines.join('\n') + '\n');
    this.#writeHead(nextSequence, digestValue(entry));

    return { sequence: nextSequence, recordDigest, prevDigest };
  }

  /** @returns {object|null} the record whose own id field matches `receiptId`. */
  get(receiptId) {
    for (const line of readLines(this.#receiptsPath)) {
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue; // unreadable line — surfaced by verifyChain(), not get()
      }
      if (entry.quarantined || !entry.record) continue;
      const r = entry.record;
      if (r.receiptId === receiptId || r.evidenceId === receiptId || r.id === receiptId) return r;
    }
    return null;
  }

  /** @returns {object[]} records in sequence order, optionally filtered by runId. */
  list({ runId } = {}) {
    const out = [];
    for (const line of readLines(this.#receiptsPath)) {
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue;
      }
      if (entry.quarantined || !entry.record) continue;
      if (runId !== undefined && entry.record.runId !== runId) continue;
      out.push(entry.record);
    }
    return out;
  }

  /**
   * Independent verification (detailed plan §5.2). Walks the file from the
   * first line, recomputing every per-record digest and chain link. Stops at
   * the first divergence and names its exact sequence — never a range, never
   * "somewhere near".
   * @returns {{ok: boolean, length: number, corruptAt: number|null, reason: string|null}}
   */
  verifyChain() {
    const lines = readLines(this.#receiptsPath);
    let prevExpected = null;
    let afterQuarantineBoundary = false;

    for (let i = 0; i < lines.length; i++) {
      const seqExpected = i + 1;
      let entry;
      try {
        entry = JSON.parse(lines[i]);
      } catch (err) {
        return { ok: false, length: i, corruptAt: seqExpected, reason: `unparseable JSONL line: ${err.message}` };
      }

      if (typeof entry.sequence !== 'number' || entry.sequence !== seqExpected) {
        return { ok: false, length: i, corruptAt: seqExpected, reason: 'sequence is missing or out of order' };
      }

      // A tombstone intentionally breaks chain continuity at this boundary
      // (see quarantine() below) — its own prevDigest still had to match
      // what came before it, but nothing downstream may re-derive its
      // content, so we do not require the chain to "explain" it further.
      if (!afterQuarantineBoundary) {
        if (entry.prevDigest !== prevExpected) {
          return { ok: false, length: i, corruptAt: seqExpected, reason: 'prevDigest chain is broken' };
        }
      }

      if (entry.quarantined) {
        afterQuarantineBoundary = true;
      } else {
        const expectedRecordDigest = digestValue(entry.record);
        if (entry.recordDigest !== expectedRecordDigest) {
          return { ok: false, length: i, corruptAt: seqExpected, reason: 'recordDigest does not match record content' };
        }
        afterQuarantineBoundary = false;
      }

      prevExpected = digestValue(entry);
    }

    // Head-anchor check. The walk above cannot catch anything done to the
    // NEWEST entry, because no later entry links to it — so a rewritten tail
    // (with its own recordDigest recomputed) or a truncated tail both look
    // like a perfectly valid shorter chain. The anchor is what makes those
    // visible. See #readHead for the honest limit on how much this buys.
    const head = this.#readHead();
    if (head) {
      if (head.sequence > lines.length) {
        return {
          ok: false,
          length: lines.length,
          corruptAt: lines.length + 1,
          reason: `history truncated: head anchor expects ${head.sequence} entries, found ${lines.length}`,
        };
      }
      if (head.sequence === lines.length && lines.length > 0) {
        const tailDigest = digestValue(JSON.parse(lines[lines.length - 1]));
        if (tailDigest !== head.entryDigest) {
          return {
            ok: false,
            length: lines.length,
            corruptAt: lines.length,
            reason: 'newest entry does not match the head anchor (tail rewritten)',
          };
        }
      }
    }

    return { ok: true, length: lines.length, corruptAt: null, reason: null };
  }

  /**
   * Move the corrupt unit at `sequence` aside. The line is replaced in place
   * with a tombstone (never removed — line positions of every other entry
   * are preserved, and history before it stays fully readable); the original
   * raw bytes are preserved in `<root>/quarantine.jsonl` for forensics.
   */
  quarantine(sequence, reason) {
    const lines = readLines(this.#receiptsPath);
    const idx = sequence - 1;
    if (idx < 0 || idx >= lines.length) {
      throw new ArcaneError('ARC_STORE_CORRUPT', `cannot quarantine unknown sequence ${sequence}`, { sequence });
    }

    const rawLine = lines[idx];
    const quarantinedAt = new Date().toISOString();

    let preservedAt = null;
    let preservedPrevDigest = null;
    try {
      const parsed = JSON.parse(rawLine);
      preservedAt = typeof parsed.at === 'string' ? parsed.at : null;
      preservedPrevDigest = parsed.prevDigest ?? null;
    } catch {
      // raw line unparseable — tombstone still records the incident cleanly
    }

    const tombstone = {
      sequence,
      at: preservedAt ?? quarantinedAt,
      prevDigest: preservedPrevDigest,
      quarantined: true,
      reason,
      quarantinedAt,
    };
    lines[idx] = JSON.stringify(tombstone);
    writeAtomic(this.#root, this.#receiptsPath, lines.join('\n') + '\n');
    // Quarantine is a legitimate, Arcane-performed rewrite. Re-anchor the head
    // so a tombstoned newest entry is not later mistaken for tail tampering.
    this.#writeHead(lines.length, digestValue(JSON.parse(lines[lines.length - 1])));

    const qLines = readLines(this.#quarantinePath);
    const qEntry = { sequence, reason, quarantinedAt, raw: rawLine };
    qLines.push(JSON.stringify(qEntry));
    writeAtomic(this.#root, this.#quarantinePath, qLines.join('\n') + '\n');

    return qEntry;
  }

  /** @returns {object[]} every quarantine entry recorded so far. */
  quarantined() {
    return readLines(this.#quarantinePath)
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  }
}

/**
 * S03 §3.3 capability binding: issuer; run/task/workspace/subject; operation
 * and argument constraints; target/resource constraints; issuance/expiry;
 * use count; revocation state. Delegation/transfer and policy-digest binding
 * are recorded on the capability but this store does not itself interpret a
 * policy bundle (that is S02's job) — `policyDigest` is carried opaquely.
 */
class LegacyCapabilityStore {
  #caps = new Map();

  #require(capabilityId) {
    const rec = this.#caps.get(capabilityId);
    if (!rec) {
      throw new ArcaneError('ARC_CAPABILITY_UNKNOWN', `unknown capability: ${capabilityId}`, { capabilityId });
    }
    return rec;
  }

  issue({ capabilityId, runId, taskId, workspace, operation, effectClass, targets, policyDigest, expiresAt = null, maxUses = null }) {
    if (!capabilityId) {
      throw new ArcaneError('ARC_CAPABILITY_UNKNOWN', 'issue() requires a capabilityId', {});
    }
    this.#caps.set(capabilityId, {
      capabilityId,
      runId,
      taskId,
      workspace,
      operation,
      effectClass,
      targets: Array.isArray(targets) ? [...targets] : null,
      policyDigest: policyDigest ?? null,
      issuedAt: new Date().toISOString(),
      expiresAt,
      maxUses,
      usedCount: 0,
      status: 'active',
      revokedAt: null,
      revokedReason: null,
    });
    return capabilityId;
  }

  /**
   * @returns a decision(...) with code one of ARC_CAPABILITY_{UNKNOWN,
   *   EXPIRED,EXHAUSTED,REVOKED} or ARC_BINDING_MISMATCH. Never throws — a
   *   denial is data the caller must record.
   */
  check(capabilityId, { operation, effectClass, target, runId, taskId, workspace, now = new Date().toISOString() } = {}) {
    const rec = this.#caps.get(capabilityId);
    if (!rec) {
      return decision({
        allowed: false,
        code: 'ARC_CAPABILITY_UNKNOWN',
        message: `unknown capability: ${capabilityId}`,
        detail: { capabilityId },
      });
    }
    if (rec.status === 'revoked') {
      return decision({
        allowed: false,
        code: 'ARC_CAPABILITY_REVOKED',
        message: `capability ${capabilityId} is revoked`,
        detail: { capabilityId, reason: rec.revokedReason },
      });
    }
    if (rec.expiresAt && now >= rec.expiresAt) {
      return decision({
        allowed: false,
        code: 'ARC_CAPABILITY_EXPIRED',
        message: `capability ${capabilityId} expired at ${rec.expiresAt}`,
        detail: { capabilityId, expiresAt: rec.expiresAt, now },
      });
    }
    if (rec.maxUses !== null && rec.usedCount >= rec.maxUses) {
      return decision({
        allowed: false,
        code: 'ARC_CAPABILITY_EXHAUSTED',
        message: `capability ${capabilityId} has no uses remaining`,
        detail: { capabilityId, usedCount: rec.usedCount, maxUses: rec.maxUses },
      });
    }

    const bindingChecks = [
      ['runId', runId, rec.runId],
      ['taskId', taskId, rec.taskId],
      ['workspace', workspace, rec.workspace],
      ['operation', operation, rec.operation],
      ['effectClass', effectClass, rec.effectClass],
    ];
    for (const [field, actual, expected] of bindingChecks) {
      if (actual === undefined || expected === undefined || expected === null) continue;
      if (actual !== expected) {
        return decision({
          allowed: false,
          code: 'ARC_BINDING_MISMATCH',
          message: `capability ${capabilityId} is bound to a different ${field}`,
          detail: { capabilityId, field, expected, actual },
        });
      }
    }
    if (target !== undefined && Array.isArray(rec.targets)) {
      if (!rec.targets.includes(target)) {
        return decision({
          allowed: false,
          code: 'ARC_BINDING_MISMATCH',
          message: `capability ${capabilityId} does not grant target ${target}`,
          detail: { capabilityId, field: 'target', expected: rec.targets, actual: target },
        });
      }
    }

    return decision({ allowed: true, detail: { capabilityId } });
  }

  /** Increments use count. Throws the same typed codes check() would deny on. */
  consume(capabilityId, { now = new Date().toISOString() } = {}) {
    const rec = this.#require(capabilityId);
    if (rec.status === 'revoked') {
      throw new ArcaneError('ARC_CAPABILITY_REVOKED', `capability ${capabilityId} is revoked`, { capabilityId });
    }
    if (rec.expiresAt && now >= rec.expiresAt) {
      throw new ArcaneError('ARC_CAPABILITY_EXPIRED', `capability ${capabilityId} expired at ${rec.expiresAt}`, { capabilityId });
    }
    if (rec.maxUses !== null && rec.usedCount >= rec.maxUses) {
      throw new ArcaneError('ARC_CAPABILITY_EXHAUSTED', `capability ${capabilityId} has no uses remaining`, { capabilityId });
    }
    rec.usedCount += 1;
    return { capabilityId, usedCount: rec.usedCount, maxUses: rec.maxUses };
  }

  revoke(capabilityId, reason = 'revoked') {
    const rec = this.#require(capabilityId);
    rec.status = 'revoked';
    rec.revokedAt = new Date().toISOString();
    rec.revokedReason = reason;
  }
}

export { CapabilityStore } from './capability-store.mjs';
