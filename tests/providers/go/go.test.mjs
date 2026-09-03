import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/go/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/go/', import.meta.url)),
  analyze,
  config,
});
