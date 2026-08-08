import { randomBytes } from 'node:crypto';

import { KernelError } from './errors.mjs';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PREFIXES = Object.freeze({
  run: 'run_',
  request: 'req_',
  task: 'ktask_',
  artifact: 'art_',
  event: 'evt_',
  effect: 'eff_',
  evidence: 'ev_',
  claim: 'clm_',
  workerCapsule: 'wc_',
});
const ULID_PATTERN = '[0-9A-HJKMNP-TV-Z]{26}';

function encodeUlid(now, entropy) {
  if (!Number.isSafeInteger(now) || now < 0 || now > 281_474_976_710_655) {
    throw new KernelError('INVALID_ARGUMENT', 'ULID timestamp is outside 48-bit range', { category: 'usage' });
  }
  let value = BigInt(now);
  for (const byte of entropy) value = (value << 8n) | BigInt(byte);
  let encoded = '';
  for (let index = 0; index < 26; index += 1) {
    encoded = ALPHABET[Number(value & 31n)] + encoded;
    value >>= 5n;
  }
  return encoded;
}

export function mintId(kind, options = {}) {
  const prefix = PREFIXES[kind];
  if (!prefix) throw new KernelError('INVALID_ARGUMENT', `unknown id kind: ${kind}`, { category: 'usage' });
  const entropy = options.entropy ?? randomBytes(10);
  if (!(entropy instanceof Uint8Array) || entropy.length !== 10) {
    throw new KernelError('INVALID_ARGUMENT', 'ULID entropy must be 10 bytes', { category: 'usage' });
  }
  return `${prefix}${encodeUlid(options.now ?? Date.now(), entropy)}`;
}

export function validateId(kind, value) {
  const prefix = PREFIXES[kind];
  if (!prefix) throw new KernelError('INVALID_ARGUMENT', `unknown id kind: ${kind}`, { category: 'usage' });
  if (typeof value !== 'string' || !(new RegExp(`^${prefix}${ULID_PATTERN}$`)).test(value)) {
    throw new KernelError('INVALID_ARGUMENT', `invalid ${kind} id: ${value}`, { category: 'usage' });
  }
  return value;
}

export function validateExecutionTaskId(value) {
  if (typeof value !== 'string' || !/^T-\d+(\.\d+)*$/.test(value)) {
    throw new KernelError('INVALID_ARGUMENT', `invalid ExecutionTask id: ${value}`, { category: 'usage' });
  }
  return value;
}

export const ID_PREFIXES = PREFIXES;
