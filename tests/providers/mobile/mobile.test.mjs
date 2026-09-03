import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/apple/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/mobile/', import.meta.url)),
  analyze,
  config,
});
