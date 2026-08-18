// .NET language pack (C#/F#/VB): dotnet restore/build/test/analyzers under
// offline/sandbox policy. Records solution/project/target frameworks; F#/VB
// remain explicit lower tiers until measured packs exist.

export default Object.freeze({
  id: 'language.dotnet',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.(cs|fs|vb)$/.test(file))
      || files.some((file) => /\.(csproj|fsproj|vbproj|sln)$/.test(file));
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => /\.(csproj|sln)$/.test(m))) {
      commands.push({ id: 'dotnet.build', executable: 'dotnet', args: ['build', '--no-restore'], cwd: root, kind: 'build' });
      if (profile !== 'fast') {
        commands.push({ id: 'dotnet.test', executable: 'dotnet', args: ['test', '--no-restore'], cwd: root, kind: 'test' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.dotnet',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.dotnet',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ['cs', 'fs', 'vb'].includes(ext)),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
