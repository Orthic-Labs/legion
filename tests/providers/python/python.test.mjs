import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/python/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/python/', import.meta.url)),
  analyze,
  config,
});
