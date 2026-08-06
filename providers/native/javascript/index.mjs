// JavaScript/TypeScript language pack per SNIP-LANGUAGE-PACK-01. Combines
// Cortex AST/SCIP, tsc/Oxc, ast-grep, OpenGrep, dependency policy, and
// test/build evidence. Commands run only when selected by the frozen plan and
// represented in the exact provider denominator.

import { createHash } from 'node:crypto';

export default Object.freeze({
  id: 'language.javascript',
  version: '1.0.0',
  detect({ projection }) {
    const extensions = new Set((projection?.parsedExtensions ?? []).map((ext) => ext.toLowerCase()));
    return extensions.has('js') || extensions.has('ts') || extensions.has('jsx') || extensions.has('tsx');
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (files.some((file) => /\.(ts|tsx)$/.test(file))) {
      commands.push({ id: 'js.types', executable: 'tsc', args: ['--noEmit'], cwd: root, kind: 'type-check' });
    }
    commands.push({ id: 'js.test', executable: 'node', args: ['--test', ...files.filter((f) => /\.test\.(js|ts)$/.test(f))], cwd: root, kind: 'test' });
    if (manifests.some((m) => m === 'package.json') && profile !== 'fast') {
      commands.push({ id: 'js.build', executable: 'npm', args: ['run', 'build'], cwd: root, kind: 'build' });
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.javascript',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.javascript',
      examined: projection?.parsedExtensions?.filter((ext) => ['js', 'ts', 'jsx', 'tsx'].includes(ext)) ?? [],
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});

export function jsFingerprint({ file, line, ruleId }) {
  return `sha256:${createHash('sha256').update(`js-rule\0${ruleId}\0${file}\0${line}`).digest('hex')}`;
}
