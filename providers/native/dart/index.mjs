// Dart language pack: dart/flutter analyze/test for configured projects.

export default Object.freeze({
  id: 'language.dart',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.dart$/.test(file))
      || files.some((file) => /(pubspec\.yaml|analysis_options\.yaml)$/.test(file));
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => /pubspec\.yaml/.test(m))) {
      commands.push({ id: 'dart.analyze', executable: 'dart', args: ['analyze'], cwd: root, kind: 'static' });
      if (profile !== 'fast') {
        commands.push({ id: 'dart.test', executable: 'dart', args: ['test'], cwd: root, kind: 'test' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.dart',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return { provider: 'language.dart', examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'dart'), complete: true };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
