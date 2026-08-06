// PHP language pack: composer validate/test/phpstan/psalm/phpunit only when
// present/configured. No composer install during an audit.

export default Object.freeze({
  id: 'language.php',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.parsedExtensions ?? []).some((ext) => ext.toLowerCase() === 'php')
      || (projection?.files ?? []).some((file) => file === 'composer.json');
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    if (manifests.some((m) => m === 'composer.json')) {
      commands.push({ id: 'php.validate', executable: 'composer', args: ['validate', '--no-check-publish'], cwd: root, kind: 'validate' });
      if (profile !== 'fast') {
        commands.push({ id: 'php.test', executable: 'vendor/bin/phpunit', args: [], cwd: root, kind: 'test' });
        commands.push({ id: 'php.static', executable: 'vendor/bin/phpstan', args: ['analyse', 'src'], cwd: root, kind: 'static' });
      }
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.php',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return { provider: 'language.php', examined: (projection?.parsedExtensions ?? []).filter((ext) => ext === 'php'), complete: true };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
