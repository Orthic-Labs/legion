#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function read(root, path) { try { return readFileSync(join(root, path), 'utf8'); } catch { return ''; } }
function candidate(ruleId, level, message, file, line = 1) {
  return {
    id: `sha256:${createHash('sha256').update(`${ruleId}\0${file}\0${line}`).digest('hex')}`,
    ruleId, severityHint: severityHint(level), claim: message, file, line,
  };
}
function severityHint(level) {
  if (level === 'critical' || level === 'error' || level === 'high') return 'high';
  if (level === 'warning') return 'medium';
  return 'low';
}
function lineOf(text, pattern) { const match = pattern.exec(text); pattern.lastIndex = 0; return match ? text.slice(0, match.index).split('\n').length : 1; }
function scan(root, files, rules) {
  const candidates = [];
  for (const file of files) {
    const text = read(root, file);
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(text)) candidates.push(candidate(rule.id, rule.level, rule.message, file, lineOf(text, rule.pattern)));
    }
  }
  return candidates;
}

const SPECS = Object.freeze({
  'framework.next': [
    { id: 'next-public-secret', level: 'error', pattern: /NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)/, message: 'Secret-like configuration uses the browser-exposed NEXT_PUBLIC_ prefix.' },
    { id: 'next-unsafe-html', level: 'warning', pattern: /dangerouslySetInnerHTML\s*=/, message: 'Raw HTML rendering requires a proven sanitization boundary.' },
    { id: 'next-unvalidated-redirect', level: 'warning', pattern: /(?:redirect|NextResponse\.redirect)\s*\([^\n]*(?:searchParams|query|request\.url)/, message: 'Request-controlled data may reach a redirect target.' },
  ],
  'framework.vue': [
    { id: 'vue-v-html', level: 'warning', pattern: /\bv-html\s*=/, message: 'v-html renders raw HTML and requires sanitization.' },
  ],
  'framework.nuxt': [
    { id: 'nuxt-public-secret', level: 'error', pattern: /public\s*:\s*\{[\s\S]{0,400}(?:secret|token|password|privateKey)\s*:/i, message: 'Secret-like runtime configuration is placed in Nuxt public config.' },
    { id: 'nuxt-ssr-disabled', level: 'note', pattern: /\bssr\s*:\s*false/, message: 'SSR is disabled; confirm this matches product and security assumptions.' },
  ],
  'framework.angular': [
    { id: 'angular-trust-bypass', level: 'error', pattern: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/, message: 'Angular sanitization is explicitly bypassed.' },
    { id: 'angular-inner-html', level: 'warning', pattern: /\[innerHTML\]\s*=/, message: 'Dynamic HTML binding requires trust and sanitization review.' },
  ],
  'framework.svelte': [
    { id: 'svelte-raw-html', level: 'warning', pattern: /\{@html\s+/, message: 'Svelte raw HTML rendering requires sanitization.' },
  ],
  'framework.sveltekit': [
    { id: 'sveltekit-public-env-secret', level: 'error', pattern: /\$env\/(?:static|dynamic)\/public[\s\S]{0,160}(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)/, message: 'Secret-like value is imported through SvelteKit public environment APIs.' },
    { id: 'sveltekit-unvalidated-redirect', level: 'warning', pattern: /redirect\s*\([^,]+,\s*(?:url|event\.url|searchParams)/, message: 'Request-controlled data may reach a redirect target.' },
  ],
  'framework.express': [
    { id: 'express-trust-proxy-all', level: 'warning', pattern: /set\s*\(\s*['"]trust proxy['"]\s*,\s*true\s*\)/, message: 'Express trusts every proxy; verify deployment boundaries.' },
    { id: 'express-open-cors', level: 'warning', pattern: /cors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*['"]\*['"]|$)/, message: 'Express CORS appears broadly permissive.' },
    { id: 'express-error-leak', level: 'warning', pattern: /res\.(?:send|json)\s*\([^\n]*(?:err\.stack|error\.stack)/, message: 'Server error stack may be returned to clients.' },
  ],
  'framework.fastify': [
    { id: 'fastify-open-cors', level: 'warning', pattern: /register\s*\([^\n]*cors[\s\S]{0,250}origin\s*:\s*(?:true|['"]\*['"])/, message: 'Fastify CORS accepts arbitrary origins.' },
    { id: 'fastify-schema-missing', level: 'note', pattern: /\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?\(/, message: 'Route declaration has no visible validation schema.' },
  ],
  'framework.nest': [
    { id: 'nest-open-cors', level: 'warning', pattern: /enableCors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*(?:true|['"]\*['"])|$)/, message: 'Nest CORS appears broadly permissive.' },
    { id: 'nest-validation-missing-transform', level: 'note', pattern: /useGlobalPipes\s*\(\s*new\s+ValidationPipe\s*\(\s*\{(?![\s\S]{0,200}transform\s*:\s*true)/, message: 'Nest ValidationPipe does not visibly enable transformation.' },
  ],
  'framework.electron': [
    { id: 'electron-node-integration', level: 'error', pattern: /nodeIntegration\s*:\s*true/, message: 'Electron renderer has Node integration enabled.' },
    { id: 'electron-context-isolation', level: 'error', pattern: /contextIsolation\s*:\s*false/, message: 'Electron context isolation is disabled.' },
    { id: 'electron-web-security', level: 'error', pattern: /webSecurity\s*:\s*false/, message: 'Electron web security is disabled.' },
    { id: 'electron-shell-open-external', level: 'warning', pattern: /shell\.openExternal\s*\([^\n]*(?:url|href|input|request)/, message: 'Potentially untrusted URL reaches shell.openExternal.' },
  ],
  'framework.django': [
    { id: 'django-debug', level: 'error', pattern: /^\s*DEBUG\s*=\s*True\b/m, message: 'Django DEBUG is enabled in tracked configuration.' },
    { id: 'django-hosts-all', level: 'warning', pattern: /^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]/m, message: 'Django accepts every Host header.' },
    { id: 'django-csrf-exempt', level: 'warning', pattern: /@csrf_exempt\b/, message: 'Django CSRF protection is bypassed for this view.' },
    { id: 'django-mark-safe', level: 'warning', pattern: /\bmark_safe\s*\(/, message: 'Django output is explicitly marked safe.' },
  ],
  'framework.fastapi': [
    { id: 'fastapi-open-cors', level: 'warning', pattern: /allow_origins\s*=\s*\[[^\]]*['"]\*['"]/, message: 'FastAPI CORS accepts every origin.' },
    { id: 'fastapi-no-response-model', level: 'note', pattern: /@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+/, message: 'FastAPI route has no visible response_model contract.' },
  ],
  'framework.flask': [
    { id: 'flask-debug', level: 'error', pattern: /app\.run\s*\([^)]*debug\s*=\s*True/, message: 'Flask debug mode is enabled.' },
    { id: 'flask-secret-fallback', level: 'high', pattern: /SECRET_KEY['"]?\s*\]\s*=\s*(?:os\.environ\.get\([^)]*\)\s+or\s+)?['"][^'"]+['"]/, message: 'Flask secret key has a tracked fallback value.' },
    { id: 'flask-render-template-string', level: 'warning', pattern: /render_template_string\s*\([^\n]*(?:request|input|user)/, message: 'Request-controlled data may reach a Jinja template source.' },
  ],
  'framework.spring': [
    { id: 'spring-csrf-disabled', level: 'warning', pattern: /csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*\{[^}]*disable\s*\(/s, message: 'Spring Security CSRF protection is disabled; prove the application is stateless.' },
    { id: 'spring-sensitive-permit-all', level: 'error', pattern: /requestMatchers\s*\([^)]*(?:admin|internal|actuator)[^)]*\)\s*\.permitAll\s*\(/is, message: 'Sensitive-looking Spring route is configured permitAll.' },
    { id: 'spring-spel-input', level: 'error', pattern: /SpelExpressionParser[\s\S]{0,500}parseExpression\s*\(\s*(?:request|input|value|expression)/, message: 'Potentially variable input reaches a SpEL parser.' },
  ],
  'framework.ktor': [
    { id: 'ktor-any-host', level: 'warning', pattern: /anyHost\s*\(\s*\)/, message: 'Ktor CORS permits any host.' },
    { id: 'ktor-forwarded-headers', level: 'note', pattern: /XForwardedHeaders/, message: 'Forwarded headers are trusted; verify proxy boundaries.' },
  ],
  'framework.rails': [
    { id: 'rails-forgery-skip', level: 'warning', pattern: /skip_(?:before_action|before_filter)\s+:verify_authenticity_token|skip_forgery_protection/, message: 'Rails request forgery protection is bypassed.' },
    { id: 'rails-html-safe', level: 'warning', pattern: /\.html_safe\b|raw\s*\(/, message: 'Rails output is explicitly marked HTML-safe.' },
    { id: 'rails-constantize-input', level: 'error', pattern: /(?:params|request)[^\n]*\.constantize\b/, message: 'Request-controlled value may select a Ruby constant.' },
  ],
  'framework.phoenix': [
    { id: 'phoenix-check-origin-disabled', level: 'warning', pattern: /check_origin:\s*false/, message: 'Phoenix origin checks are disabled.' },
    { id: 'phoenix-raw-html', level: 'warning', pattern: /raw\s*\(/, message: 'Phoenix template emits raw HTML.' },
  ],
  'framework.flutter': [
    { id: 'flutter-bad-cert-callback', level: 'error', pattern: /badCertificateCallback\s*=\s*[^;]*=>\s*true/, message: 'Flutter/Dart accepts every TLS certificate.' },
    { id: 'flutter-webview-js-unrestricted', level: 'warning', pattern: /JavaScriptMode\.unrestricted/, message: 'Flutter WebView enables unrestricted JavaScript.' },
  ],
  'framework.go-web': [
    { id: 'go-http-no-timeouts', level: 'warning', pattern: /http\.Server\s*\{(?![\s\S]{0,500}(?:ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout))/, message: 'Go HTTP server has no visible timeout configuration.' },
    { id: 'go-template-html', level: 'warning', pattern: /template\.HTML\s*\([^\n]*(?:request|input|user)/, message: 'Potentially untrusted content is cast to trusted template HTML.' },
  ],
  'framework.rust-web': [
    { id: 'rust-web-unbounded-body', level: 'note', pattern: /(?:axum|actix_web|warp|rocket)[\s\S]{0,800}(?:Bytes|String|Json)<|web::Payload/, message: 'Request body handling should have an explicit size bound.' },
    { id: 'rust-web-command-input', level: 'error', pattern: /Command::new\s*\([^)]*\)[\s\S]{0,200}arg\s*\([^\n]*(?:query|path|body|input)/, message: 'Request-derived data may reach a process argument.' },
  ],
});

function familyFiles(plan, id) {
  return (plan.coverageFamilies ?? []).find((family) => family.id === id)?.denominator?.paths ?? [];
}

export function runFrameworkSuite({ root, plan }) {
  const results = [];
  for (const [family, rules] of Object.entries(SPECS)) {
    const files = familyFiles(plan, family);
    if (!files.length) continue;
    const candidates = scan(root, files, rules);
    results.push({
      schemaVersion: 1,
      provider: `framework.${family}`,
      providerVersion: '1.0.0',
      ownerProvider: 'framework.major-suite',
      family,
      applicable: true,
      required: true,
      role: 'candidate-generator',
      status: candidates.length ? 'candidates' : 'pass',
      complete: true,
      coverage: { pathCount: files.length, paths: files, rules: rules.length },
      receipts: [], candidates, findings: [], coverageGaps: [], degradation: [],
    });
  }
  return results;
}
export function analyze({root,plan}={}){const results=runFrameworkSuite({root,plan});const gaps=results.flatMap((result)=>result.coverageGaps??[]);if(!results.length)gaps.push({kind:'framework-denominator-zero'});return{status:gaps.length?'unproven':results.some(({status})=>status==='candidates')?'candidates':'pass',complete:gaps.length===0,denominator:{kind:'framework-provider-results',expected:results.length,examined:results.filter(({complete})=>complete).length},findings:[],candidates:results.flatMap((result)=>result.candidates??[]),coverageGaps:gaps};}

function main() {
  const [rootArg, planPath, outPath] = process.argv.slice(2);
  if (!rootArg || !planPath) throw new Error('usage: framework-suite.mjs <root> <plan.json> [out.json]');
  const root = resolve(rootArg);
  const plan = JSON.parse(readFileSync(resolve(planPath), 'utf8'));
  const result = { schemaVersion: 1, kind: 'audit-framework-results', results: runFrameworkSuite({ root, plan }) };
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`);
  else console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
