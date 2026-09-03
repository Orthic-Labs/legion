import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/javascript/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/javascript/', import.meta.url)),
  analyze,
  config,
});
