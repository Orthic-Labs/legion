import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/jvm/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/jvm/', import.meta.url)),
  analyze,
  config,
});
