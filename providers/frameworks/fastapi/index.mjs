// FastAPI framework pack: routes/dependencies/Pydantic/auth/background tasks.

export default Object.freeze({
  id: 'framework.fastapi',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => JSON.stringify(m).includes('fastapi'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/allow_origins\s*=\s*\[[^\]]*['"]\*['"]/.test(text)) {
        observations.push({ ruleId: 'fastapi.cors-all-origins', severityHint: 'medium', claim: 'CORS accepts every origin.', file });
      }
      // Route with request body but no response_model contract.
      if (/@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+[^\n]*\n(?![\s\S]{0,300}response_model)/.test(text)) {
        observations.push({ ruleId: 'fastapi.no-response-model', severityHint: 'low', claim: 'Route has no visible response_model contract.', file });
      }
      // Background task with untrusted input.
      if (/BackgroundTasks\b[\s\S]{0,300}add_task\s*\([^\n]*(?:request|input|user)/.test(text)) {
        observations.push({ ruleId: 'fastapi.background-task-input', severityHint: 'medium', claim: 'Background task consumes request-derived input.', file });
      }
    }
    return observations;
  },
});
