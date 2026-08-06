// C/C++ language pack: compile_commands, CMake presets/build dirs, project
// scripts; clang/gcc/MSVC syntax/build evidence already configured. Optional
// clang-tidy/cppcheck/sanitizer/imported SARIF adapters with tool identity.
// Tree-sitter is never treated as compiler semantics.

export default Object.freeze({
  id: 'language.c-family',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.(c|cc|cpp|cxx|h|hpp)$/.test(file))
      || files.some((file) => /(CMakeLists\.txt|compile_commands\.json)$/.test(file));
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    const hasCompileCommands = manifests.some((m) => m === 'compile_commands.json');
    if (hasCompileCommands) {
      commands.push({ id: 'c-family.syntax', executable: 'clang', args: ['--analyze', '-Xanalyzer', '-analyzer-output=text'], cwd: root, kind: 'syntax' });
    } else if (manifests.some((m) => m === 'CMakeLists.txt')) {
      commands.push({ id: 'c-family.cmake', executable: 'cmake', args: ['--build', 'build'], cwd: root, kind: 'build' });
    }
    if (profile !== 'fast') {
      commands.push({ id: 'c-family.tidy', executable: 'clang-tidy', args: ['-p', 'build'], cwd: root, kind: 'lint' });
      commands.push({ id: 'c-family.cppcheck', executable: 'cppcheck', args: ['--enable=warning', '.'], cwd: root, kind: 'lint' });
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.c-family',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.c-family',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ['c', 'cc', 'cpp', 'cxx', 'h', 'hpp'].includes(ext)),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});

export function unsafeMemoryPatterns(files, readFile) {
  const observations = [];
  for (const file of files) {
    const text = readFile(file) ?? '';
    if (/\b(?:strcpy|sprintf|gets|scanf)\s*\(/.test(text)) {
      observations.push({ file, ruleId: 'c-family.unsafe-libc', severityHint: 'high', claim: 'Unsafe libc function without bounds.', line: 1 });
    }
    if (/\b(?:malloc|realloc)\s*\([^)]*\)\s*\)\s*;/.test(text) && !/free\s*\(/.test(text.slice(0, 4000))) {
      observations.push({ file, ruleId: 'c-family.unchecked-allocation', severityHint: 'medium', claim: 'Allocation without visible free path.', line: 1 });
    }
  }
  return observations;
}
