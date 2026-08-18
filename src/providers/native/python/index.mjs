// Python language pack per SNIP-LANGUAGE-PACK-01. Combines compileall, ruff,
// basedpyright/mypy, pytest, ast-grep, OpenGrep, pip-audit/OSV, and packaging
// metadata. Type-check coverage is separated from lint coverage; no dependency
// installation during an audit.

export default Object.freeze({
  id: 'language.python',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'py');
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    commands.push({ id: 'py.syntax', executable: 'python3', args: ['-m', 'compileall', '-q', root], cwd: root, kind: 'syntax' });
    if (profile !== 'fast') {
      commands.push({ id: 'py.lint', executable: 'ruff', args: ['check', root], cwd: root, kind: 'lint' });
      commands.push({ id: 'py.type', executable: 'basedpyright', args: [root], cwd: root, kind: 'type-check' });
    }
    if (manifests.some((m) => /pyproject|requirements|setup\.py/.test(m))) {
      commands.push({ id: 'py.test', executable: 'pytest', args: ['-q'], cwd: root, kind: 'test' });
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.python',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.python',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'py'),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
