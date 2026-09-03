import { fileURLToPath } from 'node:url';
import { analyze, config } from '../../../src/providers/code/dotnet/index.mjs';
import { runLanguageCorpus } from '../corpus-harness.mjs';

runLanguageCorpus({
  corpusRoot: fileURLToPath(new URL('../../../bench/corpora/dotnet/', import.meta.url)),
  analyze,
  config,
});
