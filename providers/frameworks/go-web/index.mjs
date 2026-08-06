// Go web framework pack (Gin/Echo/Fiber/Chi): route/middleware/authz/binding/
// context/cancellation, HTTP server timeouts, request/body bounds, and
// process/file/network sinks.

export default Object.freeze({
  id: 'framework.go-web',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /gin|echo|fiber|chi/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.go$/.test(file)) continue;
      const text = readFile(file) ?? '';
      // HTTP server without timeouts.
      if (/http\.Server\s*\{/.test(text) && !/ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout/.test(text)) {
        observations.push({ ruleId: 'go-web.http-no-timeouts', severityHint: 'medium', claim: 'HTTP server has no visible timeout configuration.', file });
      }
      // Request body without a size bound.
      if (/r\.Body|http\.MaxBytesReader/.test(text) && !/MaxBytesReader|io\.LimitReader/.test(text)) {
        observations.push({ ruleId: 'go-web.unbounded-body', severityHint: 'medium', claim: 'Request body has no visible size bound.', file });
      }
      // Process/command sink with request input.
      if (/exec\.Command(?:Context)?\s*\([^)]*\)/.test(text) && /r\.(?:FormValue|URL|Header)|request|req\./.test(text)) {
        observations.push({ ruleId: 'go-web.command-input', severityHint: 'high', claim: 'Request-derived data may reach a process argument.', file });
      }
      // File sink with request input.
      if (/os\.(?:OpenFile|WriteFile|Create)\s*\(/.test(text) && /r\.(?:FormValue|URL|Header)|request/.test(text)) {
        observations.push({ ruleId: 'go-web.file-sink-input', severityHint: 'high', claim: 'Request-derived data reaches a file sink.', file });
      }
      // Router registration without visible auth middleware.
      if (/(?:r|router|e|app)\.(?:GET|POST|PUT|DELETE|PATCH)\s*\(/.test(text) && !/auth|middleware|jwt/.test(text)) {
        observations.push({ ruleId: 'go-web.route-no-auth', severityHint: 'medium', claim: 'Route has no visible auth middleware.', file });
      }
    }
    return observations;
  },
});
