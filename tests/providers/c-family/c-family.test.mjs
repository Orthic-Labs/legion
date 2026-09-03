import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/c-family/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/c-family/', import.meta.url)),
  analyze,
  config,
});
