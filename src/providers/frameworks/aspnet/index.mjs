// ASP.NET Core framework pack: endpoint auth/model binding/EF/CORS/data
// protection/config.

export default Object.freeze({
  id: 'framework.aspnet',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /aspnet|microsoft\.aspnetcore/.test(JSON.stringify(m)))
      || (projection?.files ?? []).some((file) => /\.csproj$/.test(file) && true);
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.cs$/.test(file)) continue;
      const text = readFile(file) ?? '';
      if (/AllowAnyOrigin\s*\(\s*\)/.test(text) || /AllowCredentials\s*\(\s*\)/.test(text)) {
        observations.push({ ruleId: 'aspnet.cors-permissive', severityHint: 'medium', claim: 'CORS is broadly permissive.', file });
      }
      if (/\[Authorize\]/.test(text) === false && /Http(Get|Post|Put|Delete)\s*\]/.test(text) && /(?:admin|internal)/i.test(text)) {
        observations.push({ ruleId: 'aspnet.sensitive-route-no-auth', severityHint: 'high', claim: 'Sensitive endpoint lacks [Authorize].', file });
      }
      if (/\.UseDeveloperExceptionPage\s*\(\s*\)/.test(text)) {
        observations.push({ ruleId: 'aspnet.developer-exception-page', severityHint: 'high', claim: 'Developer exception page is enabled.', file });
      }
      if (/Bind\s*\([^)]*\)/.test(text) && !/\[ValidateAntiForgeryToken\]/.test(text)) {
        observations.push({ ruleId: 'aspnet.unvalidated-bind', severityHint: 'medium', claim: 'Model binding without visible anti-forgery validation.', file });
      }
    }
    return observations;
  },
});
