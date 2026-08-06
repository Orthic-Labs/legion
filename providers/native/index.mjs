// Native provider matrix: lint/type/build/test/dead-code/duplication/
// architecture/test-quality/AI-shortcut checks per language family. Command
// availability is evidence, not a clean claim; missing tools are typed gaps.

export const NATIVE_PROVIDERS = Object.freeze({
  'native.javascript': {
    id: 'native.javascript', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['javascript', 'typescript'],
    commands: { lint: 'eslint', type: 'tsc', test: 'node --test', build: 'npm run build' },
    hostCapabilities: ['process'],
  },
  'native.python': {
    id: 'native.python', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['python'],
    commands: { lint: 'ruff', type: 'basedpyright', test: 'pytest', build: 'python -m compileall' },
    hostCapabilities: ['process'],
  },
  'native.rust': {
    id: 'native.rust', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['rust'],
    commands: { lint: 'cargo clippy', type: 'cargo check', test: 'cargo test', build: 'cargo build' },
    hostCapabilities: ['process'],
  },
  'native.go': {
    id: 'native.go', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['go'],
    commands: { lint: 'go vet', type: 'go build', test: 'go test' },
    hostCapabilities: ['process'],
  },
  'native.jvm': {
    id: 'native.jvm', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['java', 'kotlin', 'scala'],
    commands: { lint: 'gradle lint', type: 'gradle compileJava', test: 'gradle test' },
    hostCapabilities: ['process'],
  },
  'native.dotnet': {
    id: 'native.dotnet', providerVersion: '1.0.0', role: 'deterministic', phase: 'facts',
    languages: ['csharp', 'fsharp', 'vb'],
    commands: { lint: 'dotnet format', type: 'dotnet build', test: 'dotnet test' },
    hostCapabilities: ['process'],
  },
});

export function nativeProviderFor(extension) {
  const map = {
    js: 'native.javascript', ts: 'native.javascript', mjs: 'native.javascript', cjs: 'native.javascript',
    py: 'native.python', rs: 'native.rust', go: 'native.go',
    java: 'native.jvm', kt: 'native.jvm', scala: 'native.jvm',
    cs: 'native.dotnet', fs: 'native.dotnet', vb: 'native.dotnet',
  };
  return NATIVE_PROVIDERS[map[extension]] ?? null;
}
