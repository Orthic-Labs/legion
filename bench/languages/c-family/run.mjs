// C/C++ language bench: command selection and unsafe-memory modeling.
import cPack, { unsafeMemoryPatterns } from '../../../providers/native/c-family/index.mjs';

const commands = cPack.commands({ root: '/repo', files: ['a.c'], manifests: ['compile_commands.json'], profile: 'standard' });
const unsafe = unsafeMemoryPatterns(['a.c'], () => 'strcpy(dst, src);\nvoid *p = malloc(10);').length;

console.log(`c-family bench: ${commands.length} commands, ${unsafe} unsafe observations`);
if (commands.length < 3) process.exit(1);
if (unsafe < 1) process.exit(1);
console.log('GATE: PASS');
