import assert from 'node:assert/strict';
import test from 'node:test';
import pythonPack from '../../../providers/native/python/index.mjs';
import djangoPack from '../../../providers/frameworks/django/index.mjs';
import fastapiPack from '../../../providers/frameworks/fastapi/index.mjs';
import flaskPack from '../../../providers/frameworks/flask/index.mjs';
import sqlalchemyPack from '../../../providers/frameworks/sqlalchemy/index.mjs';

const projection = (deps = []) => ({ parsedExtensions: ['py'], auditFacts: { packageManifests: deps } });

test('python pack detects py extensions', () => {
  assert.equal(pythonPack.detect({ projection: projection() }), true);
  assert.equal(pythonPack.detect({ projection: { parsedExtensions: ['ts'] } }), false);
});

test('python pack separates type-check from lint coverage', () => {
  const commands = pythonPack.commands({ root: '/repo', files: ['a.py'], manifests: ['pyproject.toml'], profile: 'standard' });
  assert.ok(commands.some((c) => c.kind === 'type-check'));
  assert.ok(commands.some((c) => c.kind === 'lint'));
  assert.ok(commands.some((c) => c.kind === 'syntax'));
  // fast profile drops lint/type.
  const fast = pythonPack.commands({ root: '/repo', files: ['a.py'], manifests: ['pyproject.toml'], profile: 'fast' });
  assert.ok(!fast.some((c) => c.kind === 'lint'));
  assert.ok(!fast.some((c) => c.kind === 'type-check'));
});

test('python pack normalizes and reports command failures as gaps', () => {
  const ok = pythonPack.normalize({ commandId: 'py.syntax', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(ok.status, 'pass');
  const fail = pythonPack.normalize({ commandId: 'py.lint', execution: { exitCode: 1 }, artifacts: {} });
  assert.equal(fail.status, 'error');
  assert.ok(fail.coverageGaps.some((g) => g.kind === 'command-failed'));
});

test('django pack flags debug and csrf bypass', () => {
  const files = ['settings.py', 'views.py'];
  const readFile = (f) => f === 'settings.py' ? 'DEBUG = True\nALLOWED_HOSTS = ["*"]' : '@csrf_exempt\ndef hook(request): pass';
  const observations = djangoPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'django.settings.debug'));
  assert.ok(observations.some((o) => o.ruleId === 'django.csrf-exempt'));
});

test('django pack flags raw ORM SQL', () => {
  const observations = djangoPack.analyze({ files: ['queries.py'], readFile: () => 'items = Item.objects.raw(f"SELECT * FROM items WHERE id = {request.GET[\'id\']}")' });
  assert.ok(observations.some((o) => o.ruleId === 'django.orm.raw-sql'));
});

test('django pack stays clean for safe code', () => {
  const observations = djangoPack.analyze({ files: ['views.py'], readFile: () => 'def home(request): return render(request, "home.html")' });
  assert.deepEqual(observations, []);
});

test('fastapi pack flags open CORS and missing response model', () => {
  const files = ['app.py'];
  const readFile = () => 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n\n@app.post("/items")\ndef create(item: Item):\n    return item';
  const observations = fastapiPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'fastapi.cors-all-origins'));
});

test('flask pack flags debug and secret fallback', () => {
  const observations = flaskPack.analyze({ files: ['app.py'], readFile: () => 'app.run(debug=True)\napp.secret_key = os.environ.get("K") or "fallback-secret"' });
  assert.ok(observations.some((o) => o.ruleId === 'flask.debug-enabled'));
  assert.ok(observations.some((o) => o.ruleId === 'flask.secret-fallback'));
});

test('sqlalchemy pack flags raw SQL and missing tenant filter', () => {
  const files = ['repo.py'];
  const readFile = () => 'rows = db.execute(text(f"SELECT * FROM t WHERE id = {uid}"))\nitems = db.query(Item).all()';
  const observations = sqlalchemyPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'sqlalchemy.raw-sql-interpolation'));
  assert.ok(observations.some((o) => o.ruleId === 'sqlalchemy.missing-tenant-filter'));
});
