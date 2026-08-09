// EC-5 item 1 — session -> {runId, taskId, contractId} pointer store.
//
// H-11 named the real gap: nothing in Legion materialises a run as machine
// state, so a hook event's `sessionId` has no way to carry `runId`/`taskId`/
// `contractId` forward. `SessionBindingStore` is that pointer store. It is
// deliberately ROUTING-GRADE, not evidence-grade (H-11's own note, carried
// forward here): a forged or corrupt binding can only misfile a genuine
// signed receipt into the wrong runId bucket — it can never mint one, because
// receipt authenticity is verified independently via keyring signature
// (`receipt-auth.mjs` / `#resolveHostTrust`). There is deliberately no
// hash-chain or tamper-evidence here (unlike `ReceiptStore`); that is not an
// oversight, it is the tier this store lives at.
//
// Shape mirrors `ReceiptStore` (`constructor({root})`) but NOT its failure
// discipline: `ReceiptStore` throws on a broken store because a receipt that
// silently vanished would be a false-clean. A session binding is convenience
// routing for an ambient run — losing it just means the next hook event goes
// back to being unbound (the honest, already-supported `null` case every
// caller of this store must already handle), so every method here degrades
// to `null` on any I/O failure instead of throwing.
//
// Race discipline (the load-bearing part of this file): two hosts can each
// spawn a fresh hook subprocess for the SAME session's SessionStart at
// close to the same instant (Claude Code and Codex both spawn one process
// per hook invocation — see `forge/hooks/dispatcher.js`'s `spawnSync` per
// event). Both processes may observe "no binding yet" before either has
// written one. `ensureBinding` closes that window with the filesystem's own
// atomic exclusive-create (`flag: 'wx'`, POSIX O_EXCL / Windows
// CREATE_NEW): exactly one writer's `wx` call can succeed for a given path;
// every other concurrent writer gets `EEXIST` and reads back the winner's
// record instead of overwriting it. Two concurrent `ensureBinding` calls for
// one session therefore always converge on the SAME `runId` — never a second
// mint, never a silent overwrite of the winner.
//
// `putBinding` is a different operation (upgrading an ALREADY-known binding
// with a contract/task — `legion run open`, one CLI invocation at a time)
// and is explicitly last-writer-wins: it write-temp + `renameSync`s, the
// same atomic-rename primitive `ReceiptStore` already uses for its own
// files. That is safe here specifically because putBinding never mints —
// it only relabels a runId that already exists — so the worst a lost race
// does is leave the OTHER caller's taskId/contractId as the final label,
// never a corrupt or partially-written file (rename is atomic; there is no
// interleaving of two writers' bytes).

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';

import { mintId } from './ids.mjs';
import { ArcaneError } from './errors.mjs';

/**
 * sha256 hex of the raw session id — never the session id itself. Session
 * ids are host-supplied strings with no shape guarantee this module can
 * trust (see `host-event.mjs`'s `sessionId: { type: ['string','null'],
 * minLength: 1 }` — no pattern), so hashing removes any path-injection
 * surface a crafted session id could otherwise offer, independent of
 * whatever validation the caller did or didn't do upstream.
 */
function bindingFileName(sessionId) {
  return `${createHash('sha256').update(sessionId, 'utf8').digest('hex')}.json`;
}

/** Read + parse a binding record from `path`. Never throws; `null` on any problem. */
function readBinding(path) {
  try {
    if (!existsSync(path)) return null;
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || typeof parsed.runId !== 'string') return null;
    const trio = ['contractId', 'contractVersion', 'contractDigest'];
    if (!trio.every((key) => parsed[key] == null) && !trio.every((key) => parsed[key] != null)) return null;
    return {
      runId: parsed.runId,
      taskId: typeof parsed.taskId === 'string' ? parsed.taskId : null,
      contractId: typeof parsed.contractId === 'string' ? parsed.contractId : null,
      contractVersion: Number.isInteger(parsed.contractVersion) ? parsed.contractVersion : null,
      contractDigest: typeof parsed.contractDigest === 'string' ? parsed.contractDigest : null,
    };
  } catch {
    return null; // corrupt/unreadable file -> honest null, never a thrown parse error
  }
}

export class SessionBindingStore {
  #root;

  constructor({ root }) {
    if (!root || typeof root !== 'string') {
      throw new ArcaneError('ARC_STORE_CORRUPT', 'SessionBindingStore requires a root directory path', {});
    }
    this.#root = root;
  }

  #pathFor(sessionId) {
    return join(this.#root, bindingFileName(sessionId));
  }

  /** @returns {{runId:string, taskId:string|null, contractId:string|null}|null} */
  getBinding(sessionId) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
    try {
      return readBinding(this.#pathFor(sessionId));
    } catch {
      return null;
    }
  }

  /**
   * Get-or-mint, race-safe. See module header for the EEXIST convergence
   * argument. @returns {{runId:string, taskId:string|null, contractId:string|null}|null}
   *   `null` only when every avenue (existing read, mint+create, and the
   *   EEXIST readback) failed — e.g. the root is entirely unwritable/unreadable.
   */
  ensureBinding(sessionId) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) return null;

    const existing = this.getBinding(sessionId);
    if (existing) return existing;

    const record = { runId: mintId('run'), taskId: null, contractId: null, contractVersion: null, contractDigest: null };
    const path = this.#pathFor(sessionId);
    try {
      mkdirSync(this.#root, { recursive: true });
      writeFileSync(path, JSON.stringify(record), { encoding: 'utf8', flag: 'wx' });
      return record;
    } catch (err) {
      if (err && err.code === 'EEXIST') {
        // Lost the race: another writer's file now exists at this exact
        // path. Read back the WINNER's record — never overwrite it, and
        // never mint a second runId for the same session.
        return this.getBinding(sessionId);
      }
      return null; // any other I/O failure (unwritable root, etc.) -> degrade to null
    }
  }

  /**
   * Upgrade an already-known binding (`legion run open`/`close`). Accepted
   * last-writer-wins (see module header) — write-temp + atomic rename,
   * mirroring `ReceiptStore`'s own atomic-write primitive.
   * @returns {{runId:string, taskId:string|null, contractId:string|null}|null}
   *   the record written, or `null` on any I/O failure (degrade, never throw).
   */
  putBinding(sessionId, { runId, taskId = null, contractId = null, contractVersion = null, contractDigest = null }) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
    if (typeof runId !== 'string' || runId.length === 0) return null;

    const trio = [contractId, contractVersion, contractDigest];
    if (!trio.every((value) => value == null) && !trio.every((value) => value != null)) return null;
    const record = { runId, taskId, contractId, contractVersion, contractDigest };
    const path = this.#pathFor(sessionId);
    try {
      mkdirSync(this.#root, { recursive: true });
      const tmp = join(this.#root, `.tmp-${randomBytes(8).toString('hex')}`);
      writeFileSync(tmp, JSON.stringify(record), 'utf8');
      renameSync(tmp, path);
      return record;
    } catch {
      return null;
    }
  }
}
