import { createHash } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function canonicalJson(value) {
  return encode(value, '');
}

function encode(value, path) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`non-finite number at ${path || '<root>'}`);
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (type === 'string') return JSON.stringify(value);
  if (type === 'undefined' || type === 'bigint' || type === 'function' || type === 'symbol') {
    throw new TypeError(`${type} is not encodable at ${path || '<root>'}`);
  }
  if (Array.isArray(value)) return `[${Array.from({ length: value.length }, (_, index) => { if (!(index in value)) throw new TypeError(`array hole at ${path}[${index}]`); return encode(value[index], `${path}[${index}]`); }).join(',')}]`;
  if (value instanceof Date || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new TypeError(`only plain objects are encodable at ${path || '<root>'}`);
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${encode(value[key], `${path}.${key}`)}`).join(',')}}`;
}

function artifactId(hash) {
  let bits = '';
  for (const byte of hash.subarray(0, 17)) bits += byte.toString(2).padStart(8, '0');
  return `art_${Array.from({ length: 26 }, (_, index) => CROCKFORD[Number.parseInt(bits.slice(index * 5, index * 5 + 5), 2)]).join('')}`;
}

function denominatorDigest(value) {
  const candidates = [
    value?.denominatorDigest,
    value?.coverage?.denominatorDigest,
    value?.coverage?.examinedPathsDigest,
    value?.denominator?.digest,
    value?.denominator?.pathDigest,
    value?.denominator?.fileSetDigest,
    value?.plan?.denominatorDigest,
    value?.plan?.denominator?.digest,
    value?.plan?.denominator?.pathDigest,
    value?.plan?.denominator?.fileSetDigest,
    value?.report?.denominatorDigest,
    value?.report?.coverage?.denominatorDigest,
    value?.report?.coverage?.examinedPathsDigest,
    value?.report?.denominator?.digest,
    value?.report?.denominator?.pathDigest,
    value?.report?.denominator?.fileSetDigest,
    value?.report?.plan?.denominatorDigest,
    value?.report?.plan?.denominator?.digest,
    value?.report?.plan?.denominator?.pathDigest,
    value?.report?.plan?.denominator?.fileSetDigest,
  ];
  return candidates.find((candidate) => /^sha256:[0-9a-f]{64}$/.test(candidate ?? '')) ?? null;
}

export function wrapArtifact({ value, artifactKind, sourceRevision, createdAt }) {
  const snapshot = clone(value);
  const content = canonicalJson(snapshot);
  const hash = createHash('sha256').update(content);
  const digestHex = hash.copy().digest('hex');
  const idHash = createHash('sha256').update(content).digest();
  return deepFreeze({
    record: Object.freeze({
      schemaVersion: 1,
      kind: 'legion-artifact',
      artifactId: artifactId(idHash),
      artifactKind,
      path: null,
      digest: `sha256:${digestHex}`,
      bytes: Buffer.byteLength(content),
      mediaType: 'application/json',
      immutable: true,
      producerAuthority: 'oracle',
      producerVersion: '1.0.0',
      sourceRevision,
      denominatorDigest: denominatorDigest(snapshot),
      sensitivity: 'internal',
      retention: Object.freeze({ policy: 'run', expiresAt: null }),
      redaction: Object.freeze({ applied: false, metadata: Object.freeze([]) }),
      createdAt,
    }),
    value: snapshot,
  });
}

export function clone(value) {
  return value === undefined ? undefined : JSON.parse(canonicalJson(value));
}

export function deepFreeze(value, seen = new WeakSet()) {
  if (value && typeof value === 'object' && !seen.has(value)) {
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && 'value' in descriptor) deepFreeze(descriptor.value, seen);
    }
    Object.freeze(value);
  }
  return value;
}
