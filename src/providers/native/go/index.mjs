// Go language pack: go list/test/vet, staticcheck and govulncheck when
// available/approved, plus ast-grep/OpenGrep. Models module/workspace/build
// tags. No online module resolution during offline runs.

export default Object.freeze({
  id: 'language.go',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'go')
      || (projection?.files ?? []).some((file) => file === 'go.mod');
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => m === 'go.mod')) {
      commands.push({ id: 'go.vet', executable: 'go', args: ['vet', './...'], cwd: root, kind: 'lint' });
      if (profile !== 'fast') {
        commands.push({ id: 'go.test', executable: 'go', args: ['test', './...'], cwd: root, kind: 'test' });
        commands.push({ id: 'go.vuln', executable: 'govulncheck', args: ['./...'], cwd: root, kind: 'vulnerability' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.go',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.go',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'go'),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
