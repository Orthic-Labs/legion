#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function ratio(numerator, denominator) {
  return denominator ? numerator / denominator : null;
}

function indexUnique(rows, label) {
  const map = new Map();
  for (const row of rows ?? []) {
    if (!row?.id) throw new Error(`${label} row is missing id`);
    if (map.has(row.id)) throw new Error(`${label} contains duplicate id ${row.id}`);
    map.set(row.id, row);
  }
  return map;
}

export function calculatePrecisionRecall(labelsInput, detectionsInput) {
  const labels = Array.isArray(labelsInput) ? labelsInput : labelsInput?.samples;
  const detections = Array.isArray(detectionsInput) ? detectionsInput : detectionsInput?.detections;
  const truth = indexUnique(labels, 'labels');
  const observed = indexUnique(detections ?? [], 'detections');
  let truePositive = 0;
  let falsePositive = 0;
  let trueNegative = 0;
  let falseNegative = 0;
  const rows = [];

  for (const [id, sample] of truth) {
    const expected = Boolean(sample.expected);
    const detected = Boolean(observed.get(id)?.detected);
    let classification;
    if (expected && detected) { truePositive += 1; classification = 'TP'; }
    else if (!expected && detected) { falsePositive += 1; classification = 'FP'; }
    else if (!expected && !detected) { trueNegative += 1; classification = 'TN'; }
    else { falseNegative += 1; classification = 'FN'; }
    rows.push({ id, expected, detected, classification });
  }
  const unknownDetections = [...observed.keys()].filter((id) => !truth.has(id)).sort();
  if (unknownDetections.length) {
    throw new Error(`detections contain unlabeled ids: ${unknownDetections.join(', ')}`);
  }
  const precision = ratio(truePositive, truePositive + falsePositive);
  const recall = ratio(truePositive, truePositive + falseNegative);
  const specificity = ratio(trueNegative, trueNegative + falsePositive);
  const f1 = precision === null || recall === null || precision + recall === 0
    ? null
    : (2 * precision * recall) / (precision + recall);
  return {
    schemaVersion: 1,
    kind: 'audit-provider-precision-recall',
    counts: {
      samples: truth.size,
      positive: truePositive + falseNegative,
      negative: trueNegative + falsePositive,
      truePositive,
      falsePositive,
      trueNegative,
      falseNegative,
    },
    metrics: { precision, recall, specificity, f1 },
    rows: rows.sort((left, right) => left.id.localeCompare(right.id)),
  };
}

function arg(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

async function main() {
  const args = process.argv.slice(2);
  const labelsPath = arg(args, '--labels');
  const detectionsPath = arg(args, '--detections');
  const outPath = arg(args, '--out');
  if (!labelsPath || !detectionsPath) {
    console.error('usage: precision-recall.mjs --labels labeled-samples.json --detections detections.json [--out metrics.json]');
    process.exit(2);
  }
  const result = calculatePrecisionRecall(
    JSON.parse(readFileSync(labelsPath, 'utf8')),
    JSON.parse(readFileSync(detectionsPath, 'utf8')),
  );
  const rendered = `${JSON.stringify(result, null, 2)}\n`;
  if (outPath) writeFileSync(outPath, rendered, 'utf8');
  else process.stdout.write(rendered);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
