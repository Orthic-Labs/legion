import assert from 'node:assert/strict';
import test from 'node:test';
import phpPack from '../../../providers/native/php/index.mjs';
import rubyPack from '../../../providers/native/ruby/index.mjs';
import laravelPack from '../../../providers/frameworks/laravel/index.mjs';
import symfonyPack from '../../../providers/frameworks/symfony/index.mjs';
import railsPack from '../../../providers/frameworks/rails/index.mjs';

const projection = (files = [], deps = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: { packageManifests: deps } });

test('php pack detects composer projects', () => {
  assert.equal(phpPack.detect({ projection: projection(['composer.json']) }), true);
  assert.equal(phpPack.detect({ projection: projection(['a.py']) }), false);
});

test('php pack emits configured-only commands', () => {
  const commands = phpPack.commands({ root: '/repo', files: ['a.php'], manifests: ['composer.json'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'php.validate'));
  assert.ok(commands.some((c) => c.id === 'php.test'));
  assert.ok(commands.some((c) => c.id === 'php.static'));
});

test('ruby pack detects Gemfile projects', () => {
  assert.equal(rubyPack.detect({ projection: projection(['Gemfile']) }), true);
});

test('ruby pack emits brakeman security command', () => {
  const commands = rubyPack.commands({ root: '/repo', files: ['a.rb'], manifests: ['Gemfile'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'ruby.security'));
});

test('laravel pack flags raw SQL and unescaped Blade', () => {
  const observations = laravelPack.analyze({
    files: ['routes.php', 'view.blade.php'],
    readFile: (f) => f.includes('blade') ? '{!! $user->bio !!}' : 'DB::select("SELECT * FROM x WHERE id = $id")',
  });
  assert.ok(observations.some((o) => o.ruleId === 'laravel.raw-sql-interpolation'));
  assert.ok(observations.some((o) => o.ruleId === 'laravel.unescaped-blade'));
});

test('laravel pack flags mass assignment', () => {
  const observations = laravelPack.analyze({ files: ['UserController.php'], readFile: () => 'User::create($request->all())' });
  assert.ok(observations.some((o) => o.ruleId === 'laravel.mass-assignment'));
});

test('symfony pack flags untrusted binds', () => {
  const observations = symfonyPack.analyze({ files: ['Controller.php'], readFile: () => '$form->bind($request)' });
  assert.ok(observations.some((o) => o.ruleId === 'symfony.untrusted-bind'));
});

test('rails pack flags forgery bypass and constantize', () => {
  const observations = railsPack.analyze({ files: ['ApplicationController.rb'], readFile: () => 'skip_forgery_protection\nmodel = params[:type].constantize' });
  assert.ok(observations.some((o) => o.ruleId === 'rails.forgery-bypass'));
  assert.ok(observations.some((o) => o.ruleId === 'rails.constantize-input'));
});

test('rails pack stays clean for permitted params', () => {
  const observations = railsPack.analyze({ files: ['UsersController.rb'], readFile: () => 'User.where(strong_params)' });
  assert.ok(!observations.some((o) => o.ruleId === 'rails.mass-assignment-query'));
});
