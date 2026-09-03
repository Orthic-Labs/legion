import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/php/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/php-ruby/', import.meta.url)),
  analyze,
  config,
});
