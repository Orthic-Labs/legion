// Long-tail bench: lexical accounting over a synthetic mixed corpus and
// monorepo component reconciliation.
import { lexicalAccounting } from '../../providers/generic/index.mjs';
import { componentDenominator, componentIdentity, reconcileComponents } from '../../providers/monorepo/index.mjs';

const accounting = lexicalAccounting({ files: ['a.zig', 'b.cob', 'c.ts', 'd.wat'], parsedExtensions: ['ts'] });
const a = componentIdentity({ repoId: 'r', manifestPath: 'packages/a/package.json', packageName: 'a' });
const b = componentIdentity({ repoId: 'r', manifestPath: 'packages/b/package.json', packageName: 'b' });
const denominator = componentDenominator([a, b]);
const reconciliation = reconcileComponents([a, b], [{ componentId: a.id, complete: true }, { componentId: b.id, complete: false, status: 'error' }]);

console.log(`long-tail bench: ${accounting.unsupportedExtensions.length} unsupported exts, ${denominator.componentCount} components, incomplete=${reconciliation.incomplete.length}`);
if (accounting.unsupportedExtensions.length < 3) process.exit(1);
if (denominator.componentCount !== 2) process.exit(1);
if (reconciliation.complete !== false) process.exit(1);
console.log('GATE: PASS');
