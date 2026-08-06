// Swift/Objective-C language pack: SwiftPM/Xcode project evidence, swiftc/
// swift build/test/swiftlint, clang/SourceKit/SCIP where available. Records
// host limitations (non-macOS degradation).

export default Object.freeze({
  id: 'language.swift-objc',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.(swift|m|mm)$/.test(file))
      || files.some((file) => /(Package\.swift|\.xcodeproj|\.xcworkspace)/.test(file));
  },
  commands({ root, files, manifests, profile, platform }) {
    const commands = [];
    if (platform !== 'darwin') {
      return [{ id: 'swift.degraded', executable: null, args: [], cwd: root, kind: 'degraded', reason: 'Swift toolchain requires macOS' }];
    }
    if (manifests.some((m) => m === 'Package.swift')) {
      commands.push({ id: 'swift.build', executable: 'swift', args: ['build'], cwd: root, kind: 'build' });
      if (profile !== 'fast') {
        commands.push({ id: 'swift.test', executable: 'swift', args: ['test'], cwd: root, kind: 'test' });
        commands.push({ id: 'swift.lint', executable: 'swiftlint', args: ['lint'], cwd: root, kind: 'lint' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    if (execution?.degraded) {
      return { provider: 'language.swift-objc', status: 'unproven', complete: false, coverageGaps: [{ kind: 'host-limited', reason: execution.reason }] };
    }
    return {
      provider: 'language.swift-objc',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return { provider: 'language.swift-objc', examined: (projection?.parsedExtensions ?? []).filter((ext) => ['swift', 'm', 'mm'].includes(ext)), complete: true };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
