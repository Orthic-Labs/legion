// Python language bench: command selection, normalization, and framework pack
// observations over a synthetic corpus.
import pythonPack from '../../../providers/native/python/index.mjs';
import djangoPack from '../../../providers/frameworks/django/index.mjs';
import fastapiPack from '../../../providers/frameworks/fastapi/index.mjs';

const commands = pythonPack.commands({ root: '/repo', files: ['a.py'], manifests: ['pyproject.toml'], profile: 'standard' });
const djangoObs = djangoPack.analyze({ files: ['settings.py'], readFile: () => 'DEBUG = True' }).length;
const fastapiObs = fastapiPack.analyze({ files: ['app.py'], readFile: () => 'app.add_middleware(CORSMiddleware, allow_origins=["*"])' }).length;

console.log(`python bench: ${commands.length} commands, django=${djangoObs}, fastapi=${fastapiObs}`);
if (commands.length < 3) process.exit(1);
if (djangoObs < 1 || fastapiObs < 1) process.exit(1);
console.log('GATE: PASS');
