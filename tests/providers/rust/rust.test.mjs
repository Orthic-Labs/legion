import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/rust/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/rust/', import.meta.url)),
  analyze,
  config,
});
