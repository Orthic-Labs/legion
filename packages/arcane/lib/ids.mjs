// Identifier minting + validation against the frozen ids.md grammar.
//
// packages/contracts/ids.md is the source of truth for ID *shape*; this module
// is the only place Arcane produces or checks one. Sequence IDs (R-#, EC-#,
// T-#.#) are authored upstream by Sage — Arcane validates them, never mints
// them. Opaque runtime handles (run_/req_/eff_/ev_/...) are Kernel-issued in
// production; Arcane mints them only for its own receipts and for fixtures,
// and hands off to the Kernel allocator when one is bound (see
// kernel-binding.mjs) rather than maintaining a private allocator (S01 action 2).

import { randomBytes } from 'node:crypto';
import { ArcaneError } from './errors.mjs';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ULID_RE = '[0-9A-HJKMNP-TV-Z]{26}';

/** Prefixes from packages/contracts/ids.md, "Opaque runtime handles". */
export const HANDLE_PREFIX = Object.freeze({
  run: 'run_',
  request: 'req_',
  kernelTask: 'ktask_',
  artifact: 'art_',
  effectReceipt: 'eff_',
  evidenceReceipt: 'ev_',
  claim: 'clm_',
  workerCapsule: 'wc_',
});

/** Regexes for every ID family Arcane touches. */
export const ID_PATTERN = Object.freeze({
  run: new RegExp(`^run_${ULID_RE}$`),
  request: new RegExp(`^req_${ULID_RE}$`),
  kernelTask: new RegExp(`^ktask_${ULID_RE}$`),
  artifact: new RegExp(`^art_${ULID_RE}$`),
  effectReceipt: new RegExp(`^eff_${ULID_RE}$`),
  evidenceReceipt: new RegExp(`^ev_${ULID_RE}$`),
  claim: new RegExp(`^clm_${ULID_RE}$`),
  workerCapsule: new RegExp(`^wc_${ULID_RE}$`),
  // Sequence IDs (ARCHITECTURE §33) — validated, never minted here.
  requirement: /^R-\d+$/,
  decision: /^D-\d+$/,
  invariant: /^I-\d+$/,
  nonGoal: /^NG-\d+$/,
  acceptanceCriterion: /^AC-\d+$/,
  executionContract: /^EC-\d+$/,
  executionTask: /^T-\d+(\.\d+)*$/,
  finding: /^F-\d+$/,
  blocker: /^B-\d+$/,
  amendment: /^A-\d+$/,
  covenant: /^CV-\d+$/,
});

let lastTime = -1;
let lastRandom = null;

function encodeTime(ms) {
  let out = '';
  let t = ms;
  for (let i = 9; i >= 0; i--) {
    out = CROCKFORD[t % 32] + out;
    t = Math.floor(t / 32);
  }
  return out;
}

function encodeRandom(bytes) {
  // 16 Crockford chars = 80 bits, fed from 10 random bytes.
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let out = '';
  for (let i = 0; i < 16; i++) {
    out = CROCKFORD[Number(bits & 31n)] + out;
    bits >>= 5n;
  }
  return out;
}

function bumpRandom(prev) {
  const next = Buffer.from(prev);
  for (let i = next.length - 1; i >= 0; i--) {
    if (next[i] !== 0xff) {
      next[i] += 1;
      return next;
    }
    next[i] = 0;
  }
  return randomBytes(10);
}

/**
 * Monotonic ULID. Within the same millisecond the random component is
 * incremented rather than redrawn, so ids minted in a tight loop stay
 * lexicographically ordered (ids.md: "monotonic sortability").
 */
export function ulid(now = Date.now()) {
  let rnd;
  if (now === lastTime && lastRandom) {
    rnd = bumpRandom(lastRandom);
  } else {
    rnd = randomBytes(10);
  }
  lastTime = now;
  lastRandom = rnd;
  return encodeTime(now) + encodeRandom(rnd);
}

/** Mint an opaque handle of `family` (see HANDLE_PREFIX). */
export function mintId(family, now = Date.now()) {
  const prefix = HANDLE_PREFIX[family];
  if (!prefix) throw new ArcaneError('ARC_ID_INVALID', `unknown handle family: ${family}`, { family });
  return prefix + ulid(now);
}

/** True when `value` matches the grammar for `family`. */
export function isId(family, value) {
  const re = ID_PATTERN[family];
  if (!re) throw new ArcaneError('ARC_ID_INVALID', `unknown id family: ${family}`, { family });
  return typeof value === 'string' && re.test(value);
}

/** Throws ARC_ID_INVALID unless `value` matches `family`'s grammar. */
export function assertId(family, value, label = family) {
  if (!isId(family, value)) {
    throw new ArcaneError('ARC_ID_INVALID', `${label} does not match the ids.md grammar for ${family}`, {
      family,
      value: typeof value === 'string' ? value : typeof value,
    });
  }
  return value;
}
