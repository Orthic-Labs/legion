#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data = Buffer.alloc(0)) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  typeBuffer.copy(out, 4);
  data.copy(out, 8);
  out.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 8 + data.length);
  return out;
}

export function encodePng({ width, height, rgba }) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) throw new Error('invalid PNG dimensions');
  const pixels = Buffer.from(rgba);
  if (pixels.length !== width * height * 4) throw new Error('RGBA byte length does not match dimensions');
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const rows = [];
  for (let y = 0; y < height; y += 1) rows.push(Buffer.concat([Buffer.from([0]), pixels.subarray(y * width * 4, (y + 1) * width * 4)]));
  return Buffer.concat([PNG_SIGNATURE, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.concat(rows))), chunk('IEND')]);
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

export function decodePng(input) {
  const buffer = Buffer.isBuffer(input) ? input : readFileSync(input);
  if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error('not a PNG file');
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  const idat = [];
  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    offset += 12 + length;
  }
  if (!width || !height || bitDepth !== 8 || interlace !== 0) throw new Error('only non-interlaced 8-bit PNGs are supported');
  const channels = colorType === 6 ? 4 : colorType === 2 ? 3 : colorType === 0 ? 1 : null;
  if (!channels) throw new Error(`unsupported PNG color type ${colorType}`);
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const expected = height * (stride + 1);
  if (raw.length !== expected) throw new Error(`PNG data length mismatch: ${raw.length} != ${expected}`);
  const decoded = Buffer.alloc(height * stride);
  let source = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = raw[source++];
    const rowStart = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const value = raw[source++];
      const left = x >= channels ? decoded[rowStart + x - channels] : 0;
      const up = y > 0 ? decoded[rowStart - stride + x] : 0;
      const upLeft = y > 0 && x >= channels ? decoded[rowStart - stride + x - channels] : 0;
      const recon = filter === 0 ? value
        : filter === 1 ? value + left
          : filter === 2 ? value + up
            : filter === 3 ? value + Math.floor((left + up) / 2)
              : filter === 4 ? value + paeth(left, up, upLeft)
                : Number.NaN;
      if (!Number.isFinite(recon)) throw new Error(`unsupported PNG filter ${filter}`);
      decoded[rowStart + x] = recon & 0xff;
    }
  }
  const rgba = Buffer.alloc(width * height * 4);
  for (let pixel = 0; pixel < width * height; pixel += 1) {
    const src = pixel * channels;
    const dst = pixel * 4;
    if (channels === 4) {
      rgba[dst] = decoded[src]; rgba[dst + 1] = decoded[src + 1]; rgba[dst + 2] = decoded[src + 2]; rgba[dst + 3] = decoded[src + 3];
    } else if (channels === 3) {
      rgba[dst] = decoded[src]; rgba[dst + 1] = decoded[src + 1]; rgba[dst + 2] = decoded[src + 2]; rgba[dst + 3] = 255;
    } else {
      rgba[dst] = decoded[src]; rgba[dst + 1] = decoded[src]; rgba[dst + 2] = decoded[src]; rgba[dst + 3] = 255;
    }
  }
  return { width, height, rgba, digest: sha256(buffer) };
}

function inMask(x, y, masks) {
  return masks.some((mask) => x >= mask.x && y >= mask.y && x < mask.x + mask.width && y < mask.y + mask.height);
}

export function comparePng(expectedInput, actualInput, options = {}) {
  const expected = decodePng(expectedInput);
  const actual = decodePng(actualInput);
  if (expected.width !== actual.width || expected.height !== actual.height) {
    return { status: 'different-dimensions', expected: { width: expected.width, height: expected.height }, actual: { width: actual.width, height: actual.height }, changedPixels: null, changedRatio: 1 };
  }
  const threshold = Number(options.channelThreshold ?? 0);
  const masks = options.masks ?? [];
  let comparedPixels = 0;
  let changedPixels = 0;
  let maxChannelDelta = 0;
  let totalChannelDelta = 0;
  for (let y = 0; y < expected.height; y += 1) {
    for (let x = 0; x < expected.width; x += 1) {
      if (inMask(x, y, masks)) continue;
      comparedPixels += 1;
      const offset = (y * expected.width + x) * 4;
      let changed = false;
      for (let channel = 0; channel < 4; channel += 1) {
        const delta = Math.abs(expected.rgba[offset + channel] - actual.rgba[offset + channel]);
        maxChannelDelta = Math.max(maxChannelDelta, delta);
        totalChannelDelta += delta;
        if (delta > threshold) changed = true;
      }
      if (changed) changedPixels += 1;
    }
  }
  const changedRatio = comparedPixels ? changedPixels / comparedPixels : 0;
  return {
    status: changedRatio <= Number(options.maxChangedRatio ?? 0) ? 'match' : 'different',
    width: expected.width,
    height: expected.height,
    comparedPixels,
    changedPixels,
    changedRatio,
    maxChannelDelta,
    meanChannelDelta: comparedPixels ? totalChannelDelta / (comparedPixels * 4) : 0,
    expectedDigest: expected.digest,
    actualDigest: actual.digest,
    thresholds: { channelThreshold: threshold, maxChangedRatio: Number(options.maxChangedRatio ?? 0) },
    masks,
  };
}

function caseKey(item) {
  return [item.route ?? '/', item.state ?? 'default', item.viewport ?? 'default', item.theme ?? 'default', item.locale ?? 'default', item.platform ?? 'default'].join('|');
}

function cartesian(dimensions) {
  const names = ['routes', 'states', 'viewports', 'themes', 'locales', 'platforms'];
  let rows = [{}];
  for (const name of names) {
    const values = dimensions?.[name]?.length ? dimensions[name] : ['default'];
    rows = rows.flatMap((row) => values.map((value) => ({ ...row, [name.slice(0, -1)]: value })));
    if (rows.length > 10000) throw new Error('visual coverage matrix exceeds 10,000 cases; provide explicit expected.cases');
  }
  return rows;
}

export function buildCoverageMatrix(spec) {
  const expectedCases = spec.expected?.cases ?? cartesian(spec.expected ?? {});
  const captureByKey = new Map((spec.captures ?? []).map((capture) => [caseKey(capture), capture]));
  const cases = expectedCases.map((item) => {
    const normalized = {
      route: item.route ?? '/', state: item.state ?? 'default', viewport: item.viewport ?? 'default',
      theme: item.theme ?? 'default', locale: item.locale ?? 'default', platform: item.platform ?? 'default',
    };
    const capture = captureByKey.get(caseKey(normalized));
    return { ...normalized, covered: Boolean(capture), captureId: capture?.id ?? null };
  });
  return {
    expectedCount: cases.length,
    coveredCount: cases.filter((item) => item.covered).length,
    missingCount: cases.filter((item) => !item.covered).length,
    complete: cases.every((item) => item.covered),
    cases,
  };
}

export function auditVisualArtifacts({ root, spec }) {
  const coverage = buildCoverageMatrix(spec);
  const captures = [];
  const findings = [];
  for (const capture of spec.captures ?? []) {
    const actualPath = resolve(root, capture.path);
    if (!existsSync(actualPath)) {
      captures.push({ id: capture.id, status: 'unproven', reason: 'capture-missing', path: capture.path });
      continue;
    }
    if (!capture.baseline) {
      captures.push({ id: capture.id, status: 'captured-no-baseline', path: capture.path, digest: sha256(readFileSync(actualPath)) });
      continue;
    }
    const baselinePath = resolve(root, capture.baseline);
    if (!existsSync(baselinePath)) {
      captures.push({ id: capture.id, status: 'unproven', reason: 'baseline-missing', path: capture.path, baseline: capture.baseline });
      continue;
    }
    const diff = comparePng(baselinePath, actualPath, capture.diff ?? spec.diff ?? {});
    captures.push({ id: capture.id, status: diff.status, path: capture.path, baseline: capture.baseline, diff });
    if (diff.status !== 'match') {
      findings.push({
        id: sha256(`visual-regression\0${capture.id}`),
        ruleId: 'visual.regression',
        severity: diff.changedRatio >= 0.1 ? 'high' : 'medium',
        title: `Visual regression in ${capture.id}`,
        detail: diff.status === 'different-dimensions' ? 'Rendered dimensions differ from the baseline.' : `${(diff.changedRatio * 100).toFixed(3)}% of compared pixels changed.`,
        evidence: [{ actual: capture.path, baseline: capture.baseline }],
      });
    }
  }
  const reviewRequired = captures.some((capture) => capture.status === 'captured-no-baseline');
  const unproven = captures.some((capture) => capture.status === 'unproven') || !coverage.complete || reviewRequired;
  return {
    schemaVersion: 1,
    kind: 'audit-visual-result',
    status: findings.length ? 'fail' : unproven ? 'unproven' : 'pass',
    complete: !unproven,
    reviewRequired,
    coverage,
    captures,
    findings,
    coverageGaps: [
      ...coverage.cases.filter((item) => !item.covered).map((item) => ({ kind: 'missing-visual-case', case: item })),
      ...captures.filter((item) => item.status === 'unproven').map((item) => ({ kind: item.reason, captureId: item.id })),
      ...captures.filter((item) => item.status === 'captured-no-baseline').map((item) => ({ kind: 'visual-review-or-baseline-required', captureId: item.id })),
    ],
  };
}
export function analyze({root,artifacts}={}){const spec=artifacts?.visualSpec;if(!spec)return{status:'unproven',complete:false,denominator:{kind:'visual-artifacts',expected:0,examined:0},findings:[],coverageGaps:[{kind:'visual-spec-missing'}]};const result=auditVisualArtifacts({root,spec});return{status:result.status,complete:result.complete,denominator:{kind:'visual-artifacts',expected:result.coverage?.cases?.length??0,examined:result.captures?.length??0},findings:result.findings,coverageGaps:result.coverageGaps};}

function main() {
  const [rootArg, specPath, outPath] = process.argv.slice(2);
  if (!rootArg || !specPath) throw new Error('usage: visual-core.mjs <root> <visual-spec.json> [out.json]');
  const root = resolve(rootArg);
  const spec = JSON.parse(readFileSync(resolve(specPath), 'utf8'));
  const result = auditVisualArtifacts({ root, spec });
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  else console.log(JSON.stringify(result, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
