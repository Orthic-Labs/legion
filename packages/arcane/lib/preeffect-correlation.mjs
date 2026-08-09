// EC-5 item 5 — pre-effect -> post-effect correlation pointer store.
//
// `HostIngestor#ingest` refuses a post-effect event that cannot name the
// pre-effect request it completes (`ARC_INGEST_CORRELATION_MISSING`,
// ingest.mjs). Real hook hosts run PreToolUse and PostToolUse as two
// SEPARATE subprocess invocations (see `forge/hooks/dispatcher.js`'s
// `spawnSync` per event) with no shared memory between them, so something
// has to carry `priorCorrelation.requestId` from the first invocation to the
// second. `PreEffectCorrelationStore` is that carrier: it mints a real
// `req_...` id at PreToolUse, keyed by `tool_use_id` (the one identifier
// both hook events share for a single tool invocation — see
// claude-code-adapter.mjs / codex-adapter.mjs's own `idempotencyKey:
// hookPayload.tool_use_id` mapping), and hands it back at the matching
// PostToolUse/PostToolUseFailure.
//
// EC-5 invariant I-1 (this contract's own numbering — distinct from the
// unrelated "effect stays null on PreToolUse" I-1 already documented in
// claude-code-adapter.mjs, which belongs to EC-2): at most one in-flight
// pre-effect request per `tool_use_id`. This holds structurally, not by
// extra bookkeeping here — Claude Code and Codex both mint a fresh
// `tool_use_id` per tool invocation (never reused across calls), so the
// store's own get-or-mint idempotency (see below) is sufficient. A mispaired
// correlation (a PostToolUse retrieving the WRONG PreToolUse's requestId)
// does not need new detection code either — `HostIngestor#recordEffectReceipt`
// already computes `match: requested.effectClass === observed.effectClass &&
// requested.target === observed.target && requested.operation ===
// observed.operation` (ingest.mjs), so a mispairing self-detects as
// `match:false` on the resulting receipt. That mechanism already exists;
// this store does not rebuild it.
//
// Race/failure discipline mirrors `SessionBindingStore` (lib/session-binding.mjs)
// exactly — same reasoning, so see that file's header for the full argument.
// The short version: filename is `sha256hex(toolUseId)`, never the raw id;
// `ensureRequestId` is get-first then exclusive-create (`flag:'wx'`), and on
// `EEXIST` reads back the winner instead of overwriting or minting a second
// id; every method degrades to `null` on any I/O failure rather than
// throwing. This is routing-grade, not evidence-grade: a forged/corrupt
// correlation record can only misroute which pre-effect request a receipt
// cites, never fabricate a receipt — that still requires independent
// keyring-verified signing (`receipt-auth.mjs`).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import { mintId } from './ids.mjs';
import { ArcaneError } from './errors.mjs';

function keyFileName(toolUseId) {
  return `${createHash('sha256').update(toolUseId, 'utf8').digest('hex')}.json`;
}

function readRequestId(path) {
  try {
    if (!existsSync(path)) return null;
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return parsed && typeof parsed.requestId === 'string' ? parsed.requestId : null;
  } catch {
    return null; // corrupt/unreadable -> honest null, never a thrown parse error
  }
}

export class PreEffectCorrelationStore {
  #root;

  constructor({ root }) {
    if (!root || typeof root !== 'string') {
      throw new ArcaneError('ARC_STORE_CORRUPT', 'PreEffectCorrelationStore requires a root directory path', {});
    }
    this.#root = root;
  }

  #pathFor(toolUseId) {
    return join(this.#root, keyFileName(toolUseId));
  }

  /** @returns {string|null} the requestId minted for this tool_use_id, or null if none. */
  getRequestId(toolUseId) {
    if (typeof toolUseId !== 'string' || toolUseId.length === 0) return null;
    try {
      return readRequestId(this.#pathFor(toolUseId));
    } catch {
      return null;
    }
  }

  /**
   * Get-or-mint, race-safe (see module header). Called at PreToolUse.
   * @returns {string|null} the requestId, or `null` only when every avenue
   *   (existing read, mint+create, EEXIST readback) failed.
   */
  ensureRequestId(toolUseId) {
    if (typeof toolUseId !== 'string' || toolUseId.length === 0) return null;

    const existing = this.getRequestId(toolUseId);
    if (existing) return existing;

    const requestId = mintId('request');
    const path = this.#pathFor(toolUseId);
    try {
      mkdirSync(this.#root, { recursive: true });
      writeFileSync(path, JSON.stringify({ requestId }), { encoding: 'utf8', flag: 'wx' });
      return requestId;
    } catch (err) {
      if (err && err.code === 'EEXIST') {
        return this.getRequestId(toolUseId); // lost the race — read back the winner
      }
      return null;
    }
  }
}
