#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function sha256(value) {
  return `sha256:${createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex')}`;
}

function pathDigest(paths) {
  return sha256([...paths].sort().join('\0'));
}

const FAMILY_SPECS = Object.freeze({
  'language.javascript-typescript': {
    commands(root) {
      const manager = existsSync(join(root, 'pnpm-lock.yaml')) ? 'pnpm'
        : existsSync(join(root, 'yarn.lock')) ? 'yarn'
          : 'npm';
      const pkg = safeJson(join(root, 'package.json'));
      const scripts = pkg?.scripts ?? {};
      const commands = [];
      const runScript = (id, names) => {
        const name = names.find((candidate) => scripts[candidate]);
        if (!name) return;
        if (manager === 'npm') commands.push({ id, command: 'npm', args: ['run', name, '--if-present'] });
        else commands.push({ id, command: manager, args: ['run', name] });
      };
      runScript('types', ['typecheck', 'types', 'check']);
      runScript('lint', ['lint']);
      runScript('test', ['test', 'test:unit']);
      runScript('build', ['build']);
      return commands;
    },
  },
  'language.python': {
    commands(root, files) {
      const commands = [{ id: 'compile', command: 'python', args: ['-m', 'compileall', '-q', '.'] }];
      const hasTests = files.some((file) => /(^|\/)(tests?|test_.*)\//.test(file) || /(^|\/)test_.*\.py$/.test(file) || /_test\.py$/.test(file));
      if (hasTests) commands.push({ id: 'test', command: 'python', args: ['-m', 'pytest', '-q'] });
      return commands;
    },
  },
  'language.rust': {
    commands(root, files) {
      const manifest = files.find((file) => /(^|\/)Cargo\.toml$/.test(file));
      if (!manifest) return [];
      const manifestArgs = ['--manifest-path', manifest];
      return [
        { id: 'metadata', command: 'cargo', args: ['metadata', '--format-version', '1', ...manifestArgs] },
        { id: 'check', command: 'cargo', args: ['check', '--workspace', '--all-targets', ...manifestArgs] },
        { id: 'clippy', command: 'cargo', args: ['clippy', '--workspace', '--all-targets', ...manifestArgs, '--', '-D', 'warnings'] },
        { id: 'test', command: 'cargo', args: ['test', '--workspace', ...manifestArgs] },
      ];
    },
  },
  'language.swift-objective-c': {
    commands(root, files) {
      if (files.some((file) => /(^|\/)Package\.swift$/.test(file))) {
        return [{ id: 'build', command: 'swift', args: ['build'] }, { id: 'test', command: 'swift', args: ['test'] }];
      }
      return files.filter((file) => file.endsWith('.swift')).map((file) => ({ id: `typecheck:${file}`, command: 'swiftc', args: ['-typecheck', file], timeoutMs: 60000 }));
    },
  },
  'language.shell-powershell': {
    commands(root, files) {
      const commands = [];
      for (const file of files) {
        if (/\.(sh|bash|zsh)$/.test(file)) commands.push({ id: `syntax:${file}`, command: 'bash', args: ['-n', file], timeoutMs: 30000 });
        if (/\.(ps1|psm1)$/.test(file)) commands.push({ id: `syntax:${file}`, command: process.platform === 'win32' ? 'powershell' : 'pwsh', args: ['-NoProfile', '-NonInteractive', '-Command', `$errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('${file.replaceAll("'", "''")}', [ref]$null, [ref]$errors); if($errors.Count){$errors | Out-String; exit 1}`], timeoutMs: 30000 });
      }
      return commands;
    },
  },
  'language.java-kotlin-scala': {
    commands(root, files) {
      const commands = [];
      if (existsSync(join(root, process.platform === 'win32' ? 'gradlew.bat' : 'gradlew'))) {
        const wrapper = process.platform === 'win32' ? 'gradlew.bat' : './gradlew';
        commands.push({ id: 'build', command: wrapper, args: ['build', '--no-daemon'] });
        commands.push({ id: 'test', command: wrapper, args: ['test', '--no-daemon'] });
      } else if (existsSync(join(root, process.platform === 'win32' ? 'mvnw.cmd' : 'mvnw'))) {
        const wrapper = process.platform === 'win32' ? 'mvnw.cmd' : './mvnw';
        commands.push({ id: 'verify', command: wrapper, args: ['-B', 'verify'] });
      } else if (files.some((file) => /(^|\/)pom\.xml$/.test(file))) {
        commands.push({ id: 'verify', command: 'mvn', args: ['-B', 'verify'] });
      } else if (files.some((file) => /(^|\/)build\.gradle(?:\.kts)?$/.test(file))) {
        commands.push({ id: 'build', command: 'gradle', args: ['build', '--no-daemon'] });
      }
      return commands;
    },
  },
  'language.dotnet': {
    commands(root, files) {
      const target = files.find((file) => /\.(sln|slnx)$/.test(file))
        ?? files.find((file) => /\.(csproj|fsproj|vbproj)$/.test(file));
      if (!target) return [];
      return [
        { id: 'restore', command: 'dotnet', args: ['restore', target] },
        { id: 'build', command: 'dotnet', args: ['build', target, '--no-restore'] },
        { id: 'test', command: 'dotnet', args: ['test', target, '--no-build'] },
      ];
    },
  },
  'language.php': {
    commands(root, files) {
      const commands = files.filter((file) => file.endsWith('.php')).map((file) => ({
        id: `syntax:${file}`, command: 'php', args: ['-l', file], timeoutMs: 30000,
      }));
      if (files.some((file) => /(^|\/)composer\.json$/.test(file))) {
        commands.unshift({ id: 'composer-validate', command: 'composer', args: ['validate', '--no-interaction', '--strict'] });
      }
      return commands;
    },
  },
  'language.go': {
    commands() {
      return [
        { id: 'test', command: 'go', args: ['test', './...'] },
        { id: 'vet', command: 'go', args: ['vet', './...'] },
      ];
    },
  },
  'language.c-cpp': {
    commands(root, files) {
      if (existsSync(join(root, 'build')) && files.some((file) => /(^|\/)CMakeLists\.txt$/.test(file))) {
        return [{ id: 'build', command: 'cmake', args: ['--build', 'build'] }];
      }
      if (files.some((file) => /(^|\/)(Makefile|makefile)$/.test(file))) {
        return [{ id: 'build-plan', command: 'make', args: ['-n'] }];
      }
      return [];
    },
  },
  'language.ruby': {
    commands(root, files) {
      const commands = files.filter((file) => file.endsWith('.rb')).map((file) => ({
        id: `syntax:${file}`, command: 'ruby', args: ['-c', file], timeoutMs: 30000,
      }));
      if (files.some((file) => /(^|\/)Gemfile$/.test(file)) && files.some((file) => /(^|\/)Rakefile$/.test(file))) {
        commands.push({ id: 'test', command: 'bundle', args: ['exec', 'rake', 'test'] });
      }
      return commands;
    },
  },
  'language.dart': {
    commands(root, files) {
      const flutter = files.some((file) => /(^|\/)android\/|(^|\/)ios\/|(^|\/)lib\/main\.dart$/.test(file));
      return flutter
        ? [{ id: 'analyze', command: 'flutter', args: ['analyze'] }, { id: 'test', command: 'flutter', args: ['test'] }]
        : [{ id: 'analyze', command: 'dart', args: ['analyze'] }, { id: 'test', command: 'dart', args: ['test'] }];
    },
  },
  'language.elixir-erlang': {
    commands(root, files) {
      if (files.some((file) => /(^|\/)mix\.exs$/.test(file))) {
        return [
          { id: 'compile', command: 'mix', args: ['compile', '--warnings-as-errors'] },
          { id: 'test', command: 'mix', args: ['test'] },
        ];
      }
      if (files.some((file) => /(^|\/)rebar\.config$/.test(file))) {
        return [{ id: 'test', command: 'rebar3', args: ['eunit'] }];
      }
      return [];
    },
  },
});

const FRAMEWORK_SPECS = Object.freeze({
  'framework.react': {
    inspect({ root, files }) {
      const findings = [];
      for (const file of files.filter((file) => /\.(jsx?|tsx?)$/.test(file))) {
        const text = safeRead(join(root, file));
        if (/dangerouslySetInnerHTML\s*=/.test(text)) findings.push(finding('react-dangerous-html', 'warning', 'dangerouslySetInnerHTML requires a proven sanitization boundary.', file));
        if (/localStorage\.(?:setItem|getItem)\s*\(\s*['"](?:token|auth|jwt|session)/i.test(text)) findings.push(finding('react-auth-localstorage', 'warning', 'Authentication material appears to be stored in localStorage.', file));
        if (/useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]*?(addEventListener|setInterval|setTimeout)\s*\(/.test(text) && !/return\s*\(\)\s*=>[\s\S]*?(removeEventListener|clearInterval|clearTimeout)/.test(text)) findings.push(finding('react-effect-cleanup', 'warning', 'Effect creates a listener or timer without visible cleanup.', file));
        if (/\.map\s*\([^)]*=>[\s\S]{0,300}<[A-Za-z][^>]*>/m.test(text) && !/key\s*=/.test(text)) findings.push(finding('react-list-key', 'warning', 'Rendered collection has no visible stable key.', file));
      }
      return findings;
    },
  },
  'framework.tauri': {
    inspect({ root, files }) {
      const findings = [];
      const configs = files.filter((file) => /(?:tauri\.conf\.(?:json|json5)|Tauri\.toml)$/.test(file));
      if (!configs.length) findings.push(finding('tauri-config-missing', 'error', 'Tauri source is present but no supported configuration file is in the denominator.'));
      for (const file of files.filter((file) => /capabilities\/.*\.(json|toml)$/.test(file))) {
        const text = safeRead(join(root, file));
        if (/(shell:allow-execute|shell:allow-spawn|fs:allow-write|fs:allow-remove)/.test(text) && !/(windows|webviews|platforms)/.test(text)) findings.push(finding('tauri-broad-capability', 'warning', 'Powerful Tauri permission has no visible window, webview, or platform restriction.', file));
      }
      const frontend = new Set();
      const backend = new Set();
      for (const file of files.filter((file) => /\.(js|jsx|ts|tsx|rs)$/.test(file))) {
        const text = safeRead(join(root, file));
        for (const match of text.matchAll(/invoke\s*\(\s*['"]([^'"]+)['"]/g)) frontend.add(match[1]);
        if (file.endsWith('.rs')) {
          for (const match of text.matchAll(/#\[tauri::command\][\s\S]{0,200}?fn\s+([A-Za-z0-9_]+)/g)) backend.add(match[1]);
        }
      }
      for (const command of frontend) if (!backend.has(command)) findings.push(finding('tauri-unregistered-command', 'error', `Frontend invokes ${command} but no matching Tauri command was found.`));
      return findings;
    },
  },
  'framework.tailwind': {
    inspect({ root, files }) {
      const findings = [];
      const configs = files.filter((file) => /(^|\/)tailwind\.config\.(js|cjs|mjs|ts)$/.test(file));
      if (!configs.length) findings.push(finding('tailwind-config-missing', 'warning', 'Tailwind dependency exists but no Tailwind config is in the Cortex denominator.'));
      for (const file of files.filter((file) => /\.(jsx?|tsx?|vue|svelte|html)$/.test(file))) {
        const text = safeRead(join(root, file));
        if (/class(?:Name)?\s*=\s*\{[^}]*[`'"][^`'"]*\$\{/.test(text)) findings.push(finding('tailwind-dynamic-class', 'warning', 'Runtime-built Tailwind class may be absent from generated CSS.', file));
        if (/\btransition-all\b/.test(text)) findings.push(finding('tailwind-transition-all', 'note', 'transition-all broadens animation work and can hide unintended transitions.', file));
      }
      return findings;
    },
  },
  'framework.laravel': {
    inspect({ root, files }) {
      const findings = [];
      for (const file of files.filter((file) => file.endsWith('.php'))) {
        const text = safeRead(join(root, file));
        if (/\bModel::unguard\s*\(/.test(text)) findings.push(finding('laravel-unguard', 'error', 'Global mass-assignment protection is disabled.', file));
        if (/\bDB::(?:select|statement|unprepared)\s*\(\s*\$/.test(text)) findings.push(finding('laravel-raw-sql', 'error', 'Variable input is passed directly to a raw SQL API.', file));
        if (/\{!![\s\S]*?!!\}/.test(text)) findings.push(finding('blade-raw-output', 'warning', 'Blade raw-output syntax requires explicit trust justification.', file));
        if (/APP_DEBUG\s*=\s*true/i.test(text)) findings.push(finding('laravel-debug-enabled', 'error', 'Laravel debug mode is enabled in a tracked configuration.', file));
      }
      return findings;
    },
  },
  'framework.aspnet': {
    inspect({ root, files }) {
      const findings = [];
      for (const file of files.filter((file) => file.endsWith('.cs'))) {
        const text = safeRead(join(root, file));
        if (/AllowAnyOrigin\s*\(\)/.test(text) && /AllowCredentials\s*\(\)/.test(text)) findings.push(finding('aspnet-cors-credentials', 'error', 'CORS combines any origin with credentials.', file));
        if (/\[AllowAnonymous\]/.test(text) && /(Delete|Admin|Billing|Payment|Token)/i.test(text)) findings.push(finding('aspnet-sensitive-anonymous', 'warning', 'A sensitive-looking endpoint is explicitly anonymous.', file));
        if (/UseDeveloperExceptionPage\s*\(\)/.test(text) && !/IsDevelopment\s*\(\)/.test(text)) findings.push(finding('aspnet-dev-errors', 'warning', 'Developer exception page is not visibly guarded by development environment.', file));
      }
      return findings;
    },
  },
  'framework.spring': {
    inspect({ root, files }) {
      const findings = [];
      for (const file of files.filter((file) => /\.(java|kt)$/.test(file))) {
        const text = safeRead(join(root, file));
        if (/csrf\s*\([^)]*\)\s*\.disable\s*\(/s.test(text) || /csrf\s*\{[^}]*disable\s*\(/s.test(text)) findings.push(finding('spring-csrf-disabled', 'warning', 'Spring Security CSRF protection is disabled; verify the application is strictly stateless.', file));
        if (/requestMatchers\s*\([^)]*\)\s*\.permitAll\s*\(/s.test(text) && /(admin|internal|actuator)/i.test(text)) findings.push(finding('spring-sensitive-permit-all', 'error', 'Sensitive-looking Spring route is configured permitAll.', file));
        if (/SpelExpressionParser/.test(text) && /parseExpression\s*\(\s*\w+/.test(text)) findings.push(finding('spring-spel-input', 'error', 'Potentially variable input reaches a SpEL parser.', file));
      }
      return findings;
    },
  },
});

function safeJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

function safeRead(path) {
  try { return readFileSync(path, 'utf8'); } catch { return ''; }
}

function finding(ruleId, level, message, file = null, line = 1) {
  return { ruleId, level, message, file, line };
}

function commandExists(command) {
  const probe = spawnSync(command, ['--version'], { encoding: 'utf8', shell: false, windowsHide: true, timeout: 10000 });
  return !probe.error && probe.status === 0;
}

function runCommand(root, spec) {
  if (!commandExists(spec.command)) {
    return { id: spec.id, command: [spec.command, ...spec.args].join(' '), status: 'unproven', exitCode: null, reason: 'toolchain-missing' };
  }
  const result = spawnSync(spec.command, spec.args, {
    cwd: root,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
    timeout: spec.timeoutMs ?? 180000,
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    id: spec.id,
    command: [spec.command, ...spec.args].join(' '),
    status: result.error ? 'error' : result.status === 0 ? 'pass' : 'fail',
    exitCode: result.status,
    stdout: String(result.stdout ?? '').slice(0, 200000),
    stderr: String(result.stderr ?? result.error?.message ?? '').slice(0, 200000),
  };
}

function applicableFiles(plan, familyId) {
  const family = (plan.coverageFamilies ?? []).find((item) => item.id === familyId);
  if (!family) return [];
  return family.denominator?.paths ?? [];
}

export function runNativeFamilies({ root, plan }) {
  const allPlanPaths = new Set((plan.denominator?.paths ?? []).map((p) => String(p).replaceAll('\\', '/')));
  const results = [];
  for (const [familyId, spec] of Object.entries(FAMILY_SPECS)) {
    const files = applicableFiles(plan, familyId);
    if (!files.length) continue;
    const commands = spec.commands(root, files);
    const receipts = commands.map((command) => runCommand(root, command));
    const unavailable = receipts.some((receipt) => receipt.status === 'unproven');
    const failed = receipts.some((receipt) => receipt.status === 'fail' || receipt.status === 'error');
    const examined = new Set(files);
    const unexamined = [...allPlanPaths].filter((p) => !examined.has(p)).sort();
    results.push({
      provider: `native.${familyId}`,
      family: familyId,
      applicable: true,
      required: true,
      status: failed ? 'fail' : unavailable || !commands.length ? 'unproven' : 'pass',
      complete: commands.length > 0 && !unavailable,
      coverage: { paths: files, pathCount: files.length, examinedPaths: files, examinedPathsDigest: pathDigest(files), unexaminedPaths: unexamined, commandsPlanned: commands.length, commandsCompleted: receipts.filter((receipt) => receipt.status !== 'unproven').length },
      receipts,
      findings: [],
      coverageGaps: !commands.length ? [{ kind: 'native-command', detail: 'No safe project-native build/test command could be derived.' }] : unavailable ? [{ kind: 'toolchain', detail: 'A required project-native toolchain is unavailable.' }] : [],
      degradation: [],
    });
  }
  for (const [familyId, spec] of Object.entries(FRAMEWORK_SPECS)) {
    const files = applicableFiles(plan, familyId);
    if (!files.length) continue;
    const findings = spec.inspect({ root, files });
    const examined = new Set(files);
    const unexamined = [...allPlanPaths].filter((p) => !examined.has(p)).sort();
    results.push({
      provider: `native.${familyId}`,
      family: familyId,
      applicable: true,
      required: true,
      status: findings.some((item) => item.level === 'error') ? 'fail' : 'pass',
      complete: true,
      coverage: { paths: files, pathCount: files.length, examinedPaths: files, examinedPathsDigest: pathDigest(files), unexaminedPaths: unexamined, inspected: files.length },
      receipts: [],
      findings,
      coverageGaps: [],
      degradation: [],
    });
  }
  return results;
}

function main() {
  const [rootArg, planPath, outPath] = process.argv.slice(2);
  if (!rootArg || !planPath) throw new Error('usage: native-family-runner.mjs <root> <plan.json> [out.json]');
  const root = resolve(rootArg);
  const plan = JSON.parse(readFileSync(resolve(planPath), 'utf8'));
  const result = { schemaVersion: 1, kind: 'audit-native-family-results', generatedAt: new Date().toISOString(), results: runNativeFamilies({ root, plan }) };
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  else console.log(JSON.stringify(result, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
