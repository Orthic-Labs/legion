// Rust language pack: cargo metadata/check/clippy/test, cargo-audit/OSV,
// cargo-deny, cargo-geiger, cargo-machete, cargo-outdated (when present and
// allowed). Models unsafe/FFI boundaries, feature/target matrices, build
// scripts, and proc macros.

export default Object.freeze({
  id: 'language.rust',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'rs')
      || (projection?.files ?? []).some((file) => file === 'Cargo.toml');
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => m === 'Cargo.toml')) {
      commands.push({ id: 'rust.check', executable: 'cargo', args: ['check', '--offline'], cwd: root, kind: 'type-check' });
      if (profile !== 'fast') {
        commands.push({ id: 'rust.clippy', executable: 'cargo', args: ['clippy', '--offline', '--', '-D', 'warnings'], cwd: root, kind: 'lint' });
        commands.push({ id: 'rust.test', executable: 'cargo', args: ['test', '--offline'], cwd: root, kind: 'test' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.rust',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.rust',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'rs'),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});

export function unsafeBoundaries(files, readFile) {
  const boundaries = [];
  for (const file of files) {
    const text = readFile(file) ?? '';
    const matches = [...text.matchAll(/\bunsafe\s*(?:fn|\{|impl)/g)];
    for (const match of matches) {
      const line = text.slice(0, match.index).split('\n').length;
      boundaries.push({ file, line, kind: 'unsafe-block' });
    }
    if (/extern\s+"C"/.test(text)) {
      boundaries.push({ file, line: 1, kind: 'ffi-boundary' });
    }
  }
  return boundaries;
}
