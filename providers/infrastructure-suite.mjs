#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function read(root, path) { try { return readFileSync(join(root, path), 'utf8'); } catch { return ''; } }
function lineAt(text, index) { return text.slice(0, index).split('\n').length; }
function severityHint(level) { return level === 'critical' || level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'low'; }
function candidate(ruleId, level, message, file, line = 1) {
  return {
    id: `sha256:${createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex')}`,
    ruleId, severityHint: severityHint(level), claim: message, file, line,
  };
}
function matchRules(root, files, rules) {
  const candidates = [];
  for (const file of files) {
    const text = read(root, file);
    for (const rule of rules) {
      if (rule.applies && !rule.applies(file, text)) continue;
      rule.pattern.lastIndex = 0;
      for (const match of text.matchAll(rule.pattern)) candidates.push(candidate(rule.id, rule.level, rule.message, file, lineAt(text, match.index ?? 0)));
    }
  }
  return candidates;
}

const RULES = Object.freeze([
  { id: 'container.latest-tag', level: 'warning', applies: (file) => /^Dockerfile/i.test(basename(file)), pattern: /^\s*FROM\s+[^\s:@]+(?::latest)?\s*$/gmi, message: 'Container base image is unpinned or uses latest.' },
  { id: 'container.remote-add', level: 'warning', applies: (file) => /^Dockerfile/i.test(basename(file)), pattern: /^\s*ADD\s+https?:\/\//gmi, message: 'Docker ADD fetches a mutable remote resource without explicit integrity verification.' },
  { id: 'container.curl-pipe-shell', level: 'error', applies: (file) => /^Dockerfile/i.test(basename(file)), pattern: /(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)/gi, message: 'Container build pipes remote content directly to a shell.' },
  { id: 'container-root-user', level: 'warning', applies: (file, text) => /^Dockerfile/i.test(basename(file)) && !/^\s*USER\s+/mi.test(text), pattern: /^\s*FROM\s+/gmi, message: 'Container has no explicit non-root USER.' },
  { id: 'k8s-privileged', level: 'error', applies: (file) => /\.ya?ml$/i.test(file), pattern: /privileged:\s*true/gi, message: 'Kubernetes workload enables privileged mode.' },
  { id: 'k8s-host-namespace', level: 'error', applies: (file) => /\.ya?ml$/i.test(file), pattern: /(?:hostNetwork|hostPID|hostIPC):\s*true/gi, message: 'Kubernetes workload joins a host namespace.' },
  { id: 'k8s-unpinned-image', level: 'warning', applies: (file) => /\.ya?ml$/i.test(file), pattern: /image:\s*[^\s@]+(?::latest)?\s*$/gmi, message: 'Kubernetes image is not digest-pinned.' },
  { id: 'k8s-secret-literal', level: 'error', applies: (file) => /\.ya?ml$/i.test(file), pattern: /(?:password|secret|token|api[_-]?key):\s*['"]?[^\s${][^\n]{5,}/gi, message: 'Secret-like value appears inline in deployment YAML.' },
  { id: 'actions-write-all', level: 'error', applies: (file) => file.startsWith('.github/workflows/'), pattern: /permissions:\s*write-all/gi, message: 'GitHub Actions grants write-all permissions.' },
  { id: 'actions-unpinned', level: 'warning', applies: (file) => file.startsWith('.github/workflows/'), pattern: /uses:\s*[^\s@]+@(?:main|master|latest|v?\d+(?:\.\d+)?)\s*$/gmi, message: 'GitHub Action is not pinned to an immutable commit.' },
  { id: 'actions-expression-in-shell', level: 'error', applies: (file) => file.startsWith('.github/workflows/'), pattern: /run:\s*[^\n]*\$\{\{\s*github\.event\./gi, message: 'Attacker-controlled event data is interpolated directly into a shell command.' },
  { id: 'actions-pr-target-checkout', level: 'critical', applies: (file, text) => file.startsWith('.github/workflows/') && /pull_request_target/.test(text), pattern: /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/gi, message: 'Privileged pull_request_target workflow checks out attacker-controlled head code.' },
  { id: 'terraform-open-ingress', level: 'error', applies: (file) => file.endsWith('.tf'), pattern: /cidr_blocks\s*=\s*\[[^\]]*['"]0\.0\.0\.0\/0['"][^\]]*\]/gi, message: 'Terraform security rule allows global IPv4 access.' },
  { id: 'terraform-public-storage', level: 'error', applies: (file) => file.endsWith('.tf'), pattern: /(?:acl\s*=\s*['"]public|public_access\s*=\s*true|block_public_acls\s*=\s*false)/gi, message: 'Infrastructure configuration enables public storage access.' },
  { id: 'release-mutable-download', level: 'warning', applies: (file) => /\.(?:sh|ps1|mjs|cjs|js|py|rb|yml|yaml|toml|json)$/i.test(file), pattern: /https?:\/\/[^\s'"]+\/(?:latest|releases\/latest|download\/latest)[^\s'"]*/gi, message: 'Release tooling downloads from a mutable latest URL.' },
  { id: 'release-download-no-hash', level: 'warning', applies: (file) => /\.(?:sh|ps1|mjs|cjs|js|py|rb)$/i.test(file), pattern: /(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?:\/\/(?![\s\S]{0,500}(?:sha256|checksum|digest|integrity))/gi, message: 'Downloaded release artifact has no nearby integrity verification.' },
  { id: 'tauri-updater-insecure', level: 'error', applies: (file) => /(?:tauri\.conf\.(?:json|json5)|Tauri\.toml)$/.test(file), pattern: /dangerousInsecureTransportProtocol\s*[:=]\s*true/gi, message: 'Tauri updater permits insecure transport.' },
]);

export function runInfrastructureSuite({ root, files }) {
  const candidates = matchRules(root, files, RULES);
  return {
    schemaVersion: 1,
    provider: 'infrastructure.internal-suite',
    providerVersion: '1.0.0',
    ownerProvider: 'infrastructure.internal-suite',
    phase: 'runtime',
    role: 'candidate-generator',
    status: candidates.length ? 'candidates' : 'pass',
    complete: true, applicable: true, required: true,
    coverage: { pathCount: files.length, rules: RULES.length },
    candidates, findings: [], receipts: [], coverageGaps: [], degradation: [],
  };
}

function main() {
  const [rootArg, planPath, outPath] = process.argv.slice(2);
  if (!rootArg || !planPath) throw new Error('usage: infrastructure-suite.mjs <root> <plan.json> [out.json]');
  const root = resolve(rootArg); const plan = JSON.parse(readFileSync(resolve(planPath), 'utf8'));
  const files = [...new Set((plan.coverageFamilies ?? []).flatMap((family) => family.denominator?.paths ?? []))].sort();
  const result = runInfrastructureSuite({ root, files });
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`); else console.log(JSON.stringify(result, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
