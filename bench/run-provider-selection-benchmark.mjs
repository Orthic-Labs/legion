#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadProviderRegistry, selectProviders } from '../registry/provider-registry.mjs';
import { calculatePrecisionRecall } from './precision-recall.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LABELS = resolve(HERE, '../evals/ground_truth/labeled_samples.json');

export function runProviderSelectionBenchmark(corpus, registry = loadProviderRegistry()) {
  const labels = [];
  const detections = [];
  for (const sample of corpus.samples ?? []) {
    const selected = selectProviders(registry, sample.projection).selected.map((provider) => provider.id);
    labels.push({ id: sample.id, expected: Boolean(sample.expected) });
    detections.push({ id: sample.id, detected: selected.includes(sample.provider) });
  }
  return {
    ...calculatePrecisionRecall({ samples: labels }, { detections }),
    corpusKind: corpus.kind,
    providerSamples: (corpus.samples ?? []).map((sample) => ({ id: sample.id, provider: sample.provider })),
  };
}

function arg(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

async function main() {
  const args = process.argv.slice(2);
  const labelsPath = resolve(arg(args, '--labels') ?? DEFAULT_LABELS);
  const outPath = arg(args, '--out');
  const result = runProviderSelectionBenchmark(JSON.parse(readFileSync(labelsPath, 'utf8')));
  const rendered = `${JSON.stringify(result, null, 2)}\n`;
  if (outPath) writeFileSync(resolve(outPath), rendered, 'utf8');
  else process.stdout.write(rendered);
  if (result.counts.falsePositive || result.counts.falseNegative) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
