#!/usr/bin/env node
import { basename } from 'node:path';

const COVERED = new Set([
  'js','jsx','mjs','cjs','ts','tsx','cts','mts','astro','vue','py','rs','swift','m','mm',
  'c','cc','cpp','cxx','h','hpp','java','kt','kts','scala','cs','fs','vb','php','go','rb','dart',
  'ex','exs','erl','hrl','sh','bash','zsh','ps1','psm1','bat','vbs','nsh','nsi','sql','html','css',
  'graphql','gql','svelte',
]);

function extension(path) {
  const name = basename(path);
  const dot = name.lastIndexOf('.');
  return dot < 0 ? null : name.slice(dot + 1).toLowerCase();
}

export function runGenericSourceAccounting({ files, parsedExtensions = [] }) {
  const parsed = new Set(parsedExtensions.map((value) => String(value).toLowerCase()));
  const unknown = new Map();
  for (const file of files ?? []) {
    const ext = extension(file);
    if (!ext || !parsed.has(ext) || COVERED.has(ext)) continue;
    if (!unknown.has(ext)) unknown.set(ext, []);
    unknown.get(ext).push(file);
  }
  const coverageGaps = [...unknown.entries()].sort(([a],[b]) => a.localeCompare(b)).map(([ext, paths]) => ({
    kind: 'missing-language-provider', extension: ext, pathCount: paths.length, samplePaths: paths.slice(0, 20),
  }));
  return {
    provider: 'generic.source-accounting', phase: 'runtime', applicable: true, required: true,
    status: coverageGaps.length ? 'unproven' : 'pass', complete: coverageGaps.length === 0,
    coverage: { parsedExtensions: [...parsed].sort(), explicitlyCoveredExtensions: [...COVERED].sort(), fileCount: files?.length ?? 0 },
    findings: [], receipts: [], coverageGaps, degradation: [],
  };
}
