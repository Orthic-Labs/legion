// JavaScript language bench: type-check/test/build command selection from the
// frozen denominator, plus normalization of synthetic executions.
import jsPack from '../../../providers/native/javascript/index.mjs';

const commands = jsPack.commands({
  root: '/repo',
  files: ['src/a.ts', 'src/a.test.ts'],
  manifests: ['package.json'],
  profile: 'standard',
});
const normalized = commands.map((command) => jsPack.normalize({
  commandId: command.id,
  execution: { exitCode: 0, toolVersion: '1.0' },
  artifacts: {},
}));
console.log(`javascript language bench: ${commands.length} commands, ${normalized.filter((n) => n.status === 'pass').length} pass`);
if (commands.length < 2) process.exit(1);
if (normalized.some((n) => n.status !== 'pass')) process.exit(1);
console.log('GATE: PASS');
