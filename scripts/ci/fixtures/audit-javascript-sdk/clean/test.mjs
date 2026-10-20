import test from 'node:test';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const output = process.env.LEGION_AUDIT_JS_OUTPUT;
if (!output || !path.isAbsolute(output)) throw new Error('explicit scratch output required');
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_js.js')).href);
  test('answer_js.js', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_cjs.cjs')).href);
  test('answer_cjs.cjs', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_mjs.mjs')).href);
  test('answer_mjs.mjs', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_ts.js')).href);
  test('answer_ts.ts', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_cts.cjs')).href);
  test('answer_cts.cts', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_mts.mjs')).href);
  test('answer_mts.mts', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_jsx.js')).href);
  test('answer_jsx.jsx', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
{
  const loaded = await import(pathToFileURL(path.join(output, 'answer_tsx.js')).href);
  test('answer_tsx.tsx', {plan:1}, (/** @type {import('node:test').TestContext} */ t) => {
    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);
  });
}
