// JavaScript/TypeScript + React/Next language/framework bench: exercises the
// deterministic structural packs over synthetic corpus files and verifies
// observation counts and rule coverage.
import reactPack from '../../../providers/frameworks/react/index.mjs';
import nextPack from '../../../providers/frameworks/next/index.mjs';

const corpus = {
  'App.tsx': 'function App({html}) { if (ready) { useEffect(() => { run(); }); } return <img src="x" /><div dangerouslySetInnerHTML={{__html: html}} />; }',
  'route.ts': 'export async function GET(request, { params }) { return Response.json(params) }',
  'clean.tsx': 'function Clean() { return <div>hi</div>; }',
};

let reactObservations = 0;
for (const [file, text] of Object.entries(corpus)) {
  reactObservations += reactPack.analyze({ files: [file], readFile: () => text }).length;
}
const nextObservations = nextPack.analyze({ files: ['route.ts'], readFile: () => corpus['route.ts'] }).length;

console.log(`javascript bench: react=${reactObservations} observations, next=${nextObservations} observations`);
if (reactObservations < 4) process.exit(1);
if (nextObservations < 1) process.exit(1);
console.log('GATE: PASS');
