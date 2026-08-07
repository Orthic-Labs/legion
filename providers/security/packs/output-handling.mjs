import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.output-handling', family: 'output-handling', description: 'Untrusted output crossing HTML, header, redirect, and command boundaries.', rules: [
  { id: 'output.untrusted-html', pattern: /(?:innerHTML|dangerouslySetInnerHTML)\s*[=:][^\n]*(?:input|request|body|content|output)/i, claim: 'Untrusted content may reach an HTML interpretation sink.', effectKind: 'code-execution' },
  { id: 'output.open-redirect', pattern: /(?:redirect|location\.href)\s*\(?[^\n]*(?:request|query|params|next)/i, claim: 'Request-controlled data may reach a redirect target.', effectKind: 'control-bypass' },
  { id: 'output.header-injection', pattern: /setHeader\s*\([^\n]*(?:request|query|params|body)/i, claim: 'Request-controlled data may reach an HTTP response header.', effectKind: 'control-bypass' },
] });
