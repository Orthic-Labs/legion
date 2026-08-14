#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const PACK_PROVIDERS = Object.freeze({
  credentials: 'security.credentials',
  'insecure-defaults': 'security.insecure-defaults',
  'misuse-resistance': 'security.misuse-resistance',
  'agentic-ci': 'security.agentic-ci',
  'agent-skill-mcp': 'security.agent-skill-mcp',
  all: 'security.internal-suite',
});

// Compatibility wrapper contract (Security Appendix §63.1): old pack names map
// to the canonical lens IDs. The wrapper invokes the new pack engine and emits
// candidate v2; it is removed after two schema releases.
export function legacyPackMapping() {
  return { ...PACK_PROVIDERS };
}

const RULES = Object.freeze([
  {
    pack: 'insecure-defaults', id: 'security.insecure-default.secret', severityHint: 'high', threatModel: 'deployment-misconfiguration',
    patterns: [
      /(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|JWT_KEY)\s*(?:=|:)\s*(?:process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*)?['"][^'"]{4,}['"]/gi,
      /(?:getenv|env)\s*\([^)]*(?:SECRET|TOKEN|KEY)[^)]*\)\s*(?:\?:|\?\?|or)\s*['"][^'"]+['"]/gi,
    ],
    claim: 'A security-sensitive secret has a tracked fallback value instead of failing closed.',
  },
  {
    pack: 'insecure-defaults', id: 'security.insecure-default.auth-disabled', severityHint: 'high', threatModel: 'remote-unauthenticated',
    patterns: [
      /(?:AUTH|AUTHENTICATION|AUTHORIZATION|REQUIRE_AUTH)\s*(?:=|:)\s*(?:false|0|['"]false['"])/gi,
      /(?:DisableAuth|AllowAnonymousByDefault|PermitAllByDefault)\s*(?:=|:)\s*true/gi,
    ],
    claim: 'Authentication or authorization appears to default to disabled.',
  },
  {
    pack: 'insecure-defaults', id: 'security.tls-verification-disabled', severityHint: 'high', threatModel: 'network-attacker',
    patterns: [
      /rejectUnauthorized\s*:\s*false/gi, /verify\s*=\s*False/g,
      /danger_accept_invalid_certs\s*\(\s*true\s*\)/gi,
      /ServerCertificateCustomValidationCallback\s*=\s*[^;]*(?:true|=>\s*true)/gi,
    ],
    claim: 'TLS certificate verification is explicitly disabled.',
  },
  {
    pack: 'misuse-resistance', id: 'security.command-injection', severityHint: 'critical', threatModel: 'attacker-controlled-input',
    patterns: [
      /(?:exec|execSync|system|popen|Runtime\.getRuntime\(\)\.exec|Process\.Start|Command::new)\s*\([^\n;]*(?:req\.|request\.|params|query|body|argv|input|user)/gi,
      /(?:eval|Function)\s*\([^\n;]*(?:req\.|request\.|params|query|body|input|user)/gi,
    ],
    claim: 'Potentially attacker-controlled input reaches a process or code-execution sink.',
  },
  {
    pack: 'misuse-resistance', id: 'security.path-traversal', severityHint: 'high', threatModel: 'attacker-controlled-file-path',
    patterns: [/(?:readFile|writeFile|open|File::open|Path\.Combine|Paths\.get|send_file|Storage::disk)[^\n;]*(?:req\.|request\.|params|query|body|input|filename|path)/gi],
    claim: 'Potentially attacker-controlled path data reaches a filesystem operation.',
  },
  {
    pack: 'misuse-resistance', id: 'security.unsafe-deserialization', severityHint: 'critical', threatModel: 'attacker-controlled-serialized-data',
    patterns: [/pickle\.loads?\s*\(/g, /yaml\.load\s*\([^)]*(?!SafeLoader)/g, /BinaryFormatter\s*\(/g, /ObjectInputStream\s*\(/g, /Marshal\.load\s*\(/g, /unserialize\s*\(/g],
    claim: 'A deserializer capable of constructing arbitrary object graphs is used.',
  },
  {
    pack: 'agentic-ci', id: 'security.agent.prompt-injection-flow', severityHint: 'high', threatModel: 'malicious-repository-or-ticket-content',
    patterns: [
      /(?:github\.event\.(?:issue|pull_request)|issue\.body|pull_request\.body|comment\.body)[\s\S]{0,500}(?:prompt|instructions|messages)/gi,
      /(?:prompt|instructions|messages)[\s\S]{0,500}(?:github\.event\.(?:issue|pull_request)|issue\.body|pull_request\.body|comment\.body)/gi,
    ],
    claim: 'Untrusted issue, pull-request, or comment content appears to enter an agent prompt.',
  },
  {
    pack: 'agentic-ci', id: 'security.agent.unsafe-execution', severityHint: 'critical', threatModel: 'malicious-model-output',
    patterns: [
      /(?:model|assistant|completion|llm)[A-Za-z0-9_.]*[\s\S]{0,300}(?:eval|exec|spawn|system|bash|sh -c|powershell)/gi,
      /(?:eval|exec|spawn|system|bash|sh -c|powershell)[\s\S]{0,300}(?:model|assistant|completion|llm)/gi,
    ],
    claim: 'Model output appears to reach a code or shell execution sink.',
  },
  {
    pack: 'agentic-ci', id: 'security.agent.tool-boundary-taint', severityHint: 'high', threatModel: 'malicious-prompt-or-request-content',
    custom(path, text) {
      const sourcePattern = /github\.event\.(?:issue|pull_request|comment)|(?:issue|pull_request|comment)\.body|request\.(?:body|query|params)|req\.(?:body|query|params)|userContent|untrusted(?:Input|Text)|promptInput/gi;
      const sinkPattern = /@tool\b|\b(?:callTool|invokeTool|executeTool|runTool)\s*\(|\bmcp\.(?:callTool|invoke)\s*\(|\btool_calls?\b|\btools\s*\[[^\]]+\]\s*\(/gi;
      const source = sourcePattern.exec(text);
      const sink = sinkPattern.exec(text);
      if (!source || !sink) return [];
      const start = Math.min(source.index, sink.index);
      const end = Math.max(source.index, sink.index);
      const between = text.slice(start, end);
      const validationVisible = /(?:schema\.(?:parse|safeParse)|validate|sanitize|allowlist|whitelist|authorization|permission|policyCheck|approvedTool)/i.test(between);
      return [{
        index: source.index,
        metadata: {
          source: source[0], sourceLine: lineAt(text, source.index),
          sink: sink[0], sinkLine: lineAt(text, sink.index),
          validationVisible,
          boundary: 'agent-to-tool',
        },
      }];
    },
    claim: 'Potentially untrusted prompt or request content crosses an agent tool boundary; adjudicate validation, authorization, and sink reachability.',
  },
  {
    pack: 'agent-skill-mcp', id: 'security.skill.exfiltration-chain', severityHint: 'critical', threatModel: 'malicious-skill-or-hook',
    custom(path, text) {
      const readsSecrets = /(?:process\.env|os\.environ|std::env|GetEnvironmentVariable|\.ssh|\.aws|credentials|keychain|secret)/i.test(text);
      const sendsNetwork = /(?:fetch\s*\(|axios\.|requests\.|httpx\.|curl\s|Invoke-WebRequest|TcpStream|HttpClient)/i.test(text);
      if (readsSecrets && sendsNetwork) return [{ index: Math.min(indexOfAny(text, ['process.env', 'os.environ', 'credentials', 'secret']), text.length - 1) }];
      return [];
    },
    claim: 'The same skill, hook, or tool file reads credential material and performs network I/O.',
  },
  {
    pack: 'agent-skill-mcp', id: 'security.skill.hidden-unicode', severityHint: 'high', threatModel: 'malicious-skill-content',
    custom(path, text) {
      const matches = [];
      for (let index = 0; index < text.length; index += 1) {
        const code = text.codePointAt(index);
        if ([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x202a, 0x202b, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069].includes(code)) matches.push({ index });
      }
      return matches;
    },
    claim: 'Agent-facing content contains invisible or bidirectional Unicode controls.',
  },
]);

const CREDENTIAL_RULE = Object.freeze({
  pack: 'credentials', id: 'security.credential-literal', severityHint: 'high', threatModel: 'credential-exposure',
  claim: 'A non-placeholder, credential-shaped literal is committed in a security-relevant file context.',
});

function indexOfAny(text, needles) {
  const indexes = needles.map((needle) => text.toLowerCase().indexOf(needle.toLowerCase())).filter((index) => index >= 0);
  return indexes.length ? Math.min(...indexes) : 0;
}
function lineAt(text, index) { return text.slice(0, Math.max(0, index)).split('\n').length; }
function digest(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function readText(root, path) {
  try {
    const buffer = readFileSync(join(root, path));
    if (buffer.length > MAX_FILE_BYTES || buffer.includes(0)) return null;
    return buffer.toString('utf8');
  } catch { return null; }
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
function isPlaceholder(value) {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
  return !normalized
    || /^(?:example|sample|dummy|test|testing|changeme|placeholder|notasecret|development|developmentsecret|devsecret|secret|password|token|apikey|your[a-z0-9]*)$/.test(normalized)
    || normalized.includes('replacewith') || normalized.includes('insert') || normalized.includes('xxxxx');
}
function knownCredentialFormat(value) {
  return /^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.test(value);
}
function securityRelevantContext(path) {
  const extension = extname(path).toLowerCase();
  const normalized = path.toLowerCase().replaceAll('\\', '/');
  if (/(^|\/)(?:test|tests|fixtures?|examples?|docs?)\//.test(normalized)) return 'low';
  if (['.env', '.ini', '.toml', '.yaml', '.yml', '.json', '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.java', '.kt', '.cs', '.go', '.rs', '.swift', '.sh', '.ps1'].includes(extension) || normalized.endsWith('.env')) return 'high';
  return 'medium';
}
function credentialMatches(path, text) {
  const matches = [];
  const assignment = /(?:api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret)\s*(?:=|:)\s*['"]([^'"\r\n]{8,})['"]/gi;
  const context = securityRelevantContext(path);
  for (const match of text.matchAll(assignment)) {
    const value = match[1];
    const format = knownCredentialFormat(value);
    const entropy = shannonEntropy(value);
    if (isPlaceholder(value)) continue;
    if (!format && entropy < 3.2) continue;
    if (context === 'low' && !format && entropy < 4.0) continue;
    matches.push({ index: match.index ?? 0, metadata: { filterStages: { regexTier: format ? 'known-format' : 'named-assignment', entropy: Number(entropy.toFixed(3)), placeholderRejected: false, fileContext: context } } });
  }
  const known = /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;
  for (const match of text.matchAll(known)) {
    matches.push({ index: match.index ?? 0, metadata: { filterStages: { regexTier: 'known-format', entropy: Number(shannonEntropy(match[0]).toFixed(3)), placeholderRejected: false, fileContext: context } } });
  }
  return matches;
}

function candidate(rule, provider, path, text, match) {
  const index = match?.index ?? 0;
  const line = lineAt(text, index);
  return {
    id: digest(`${provider}\0${rule.id}\0${path}:${line}`),
    ruleId: rule.id, provider, role: 'candidate-generator', claim: rule.claim,
    severityHint: rule.severityHint, threatModel: rule.threatModel,
    evidence: [{ file: path, line }], evidenceStrength: 'candidate', verdict: 'UNADJUDICATED', adjudicationRequired: true,
    ...(match?.metadata ? { detectorMetadata: match.metadata } : {}),
  };
}
function rulesForPack(pack) {
  if (pack === 'all') return RULES;
  if (!Object.hasOwn(PACK_PROVIDERS, pack)) throw new Error(`unknown security rule pack ${pack}`);
  return RULES.filter((rule) => rule.pack === pack);
}

export function generateSecurityCandidates({ root, files, pack = 'all', provider = PACK_PROVIDERS[pack] ?? `security.${pack}` }) {
  const candidates = [];
  const scanned = [];
  const rules = rulesForPack(pack);
  for (const path of [...new Set(files)].sort()) {
    const text = readText(root, path);
    if (text === null) continue;
    scanned.push(path);
    if (pack === 'credentials' || pack === 'all') {
      for (const match of credentialMatches(path, text)) candidates.push(candidate(CREDENTIAL_RULE, provider, path, text, match));
    }
    for (const rule of rules) {
      if (rule.custom) {
        for (const match of rule.custom(path, text) ?? []) candidates.push(candidate(rule, provider, path, text, match));
        continue;
      }
      for (const pattern of rule.patterns ?? []) {
        pattern.lastIndex = 0;
        for (const match of text.matchAll(pattern)) candidates.push(candidate(rule, provider, path, text, match));
      }
    }
  }
  const unique = [...new Map(candidates.map((item) => [item.id, item])).values()];
  return {
    schemaVersion: 1, kind: 'audit-security-candidates', provider, rulePack: pack,
    complete: scanned.length === files.length,
    coverage: { expectedFiles: files.length, scannedFiles: scanned.length, scanned, rules: [...(pack === 'credentials' ? [CREDENTIAL_RULE.id] : []), ...rules.map((rule) => rule.id)] },
    candidates: unique,
    coverageGaps: scanned.length === files.length ? [] : [{ kind: 'unreadable-or-binary-files', count: files.length - scanned.length }],
  };
}

export function mergeSecurityCandidateReports(reports) {
  const candidates = [...new Map((reports ?? []).flatMap((report) => report.candidates ?? []).map((item) => [item.id, item])).values()];
  return {
    schemaVersion: 1, kind: 'audit-security-candidates', provider: 'security.multi-provider',
    complete: (reports ?? []).every((report) => report.complete !== false),
    coverage: { providerReports: (reports ?? []).map((report) => ({ provider: report.provider, rulePack: report.rulePack, expectedFiles: report.coverage?.expectedFiles ?? 0, scannedFiles: report.coverage?.scannedFiles ?? 0, rules: report.coverage?.rules ?? [] })) },
    candidates,
    coverageGaps: (reports ?? []).flatMap((report) => (report.coverageGaps ?? []).map((gap) => ({ ...gap, provider: report.provider }))),
  };
}

export function deriveVariantQueries(confirmedFinding) {
  if (!confirmedFinding?.ruleId || !confirmedFinding?.evidence?.length) throw new Error('confirmed finding requires ruleId and evidence');
  return {
    schemaVersion: 1, kind: 'security-variant-plan', findingId: confirmedFinding.id, ruleId: confirmedFinding.ruleId,
    queries: [
      { level: 'exact', key: `${confirmedFinding.ruleId}:${confirmedFinding.evidence[0].file}:${confirmedFinding.evidence[0].line}` },
      { level: 'same-rule', key: confirmedFinding.ruleId },
      { level: 'same-sink-class', key: confirmedFinding.ruleId.split('.').slice(0, 2).join('.') },
    ],
  };
}

function planFiles(plan) { return [...new Set((plan.coverageFamilies ?? []).flatMap((family) => family.denominator?.paths ?? []))].sort(); }
function arg(args, name) { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : null; }
function positional(args) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (['--pack', '--provider'].includes(args[index])) { index += 1; continue; }
    if (!args[index].startsWith('--')) values.push(args[index]);
  }
  return values;
}
function main() {
  const args = process.argv.slice(2);
  const [rootArg, planPath, outPath] = positional(args);
  if (!rootArg || !planPath) throw new Error('usage: security-suite.mjs <root> <plan.json> [out.json] [--pack <pack>] [--provider <id>]');
  const root = resolve(rootArg);
  const plan = JSON.parse(readFileSync(resolve(planPath), 'utf8'));
  const pack = arg(args, '--pack') ?? 'all';
  const result = generateSecurityCandidates({ root, files: planFiles(plan), pack, provider: arg(args, '--provider') ?? PACK_PROVIDERS[pack] });
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  else console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
