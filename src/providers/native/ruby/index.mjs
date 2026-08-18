// Ruby language pack: bundle/rubocop/brakeman/test only when present. No
// bundle install during an audit.

export default Object.freeze({
  id: 'language.ruby',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'rb')
      || (projection?.files ?? []).some((file) => /(Gemfile|\.gemspec)$/.test(file));
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => /Gemfile/.test(m))) {
      commands.push({ id: 'ruby.test', executable: 'bundle', args: ['exec', 'rspec'], cwd: root, kind: 'test' });
      if (profile !== 'fast') {
        commands.push({ id: 'ruby.lint', executable: 'bundle', args: ['exec', 'rubocop'], cwd: root, kind: 'lint' });
        commands.push({ id: 'ruby.security', executable: 'bundle', args: ['exec', 'brakeman', '-q'], cwd: root, kind: 'security' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.ruby',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return { provider: 'language.ruby', examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'rb'), complete: true };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
