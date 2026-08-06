// Forge CI adapters per PR41. GitLab/Bitbucket/Azure DevOps adapters call the
// same canonical CLI and consume identical JSON/SARIF; no forge adapter may
// alter planner, policy, or report truth.

export function gitlabCiAdapter({ jobName = 'nemesis-audit', profile = 'standard', baseline } = {}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-gitlab-ci-adapter',
    jobName,
    script: [
      `npm install --global @orthic-labs/nemesis`,
      `nemesis audit . --profile ${profile}${baseline ? ` --baseline ${baseline}` : ''} --out .audit`,
    ],
    artifacts: { reports: { sarif: '.audit/report.sarif' }, paths: ['.audit/'] },
    canonicalCli: true,
  };
}

export function bitbucketAdapter({ pipelineName = 'nemesis-audit', profile = 'standard' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-bitbucket-adapter',
    pipelineName,
    steps: [
      { step: { name: 'Nemesis audit', script: [`npm install --global @orthic-labs/nemesis`, `nemesis audit . --profile ${profile} --out .audit`] } },
    ],
    artifacts: { downloads: ['.audit/report.sarif'] },
    canonicalCli: true,
  };
}

export function azureDevopsAdapter({ pipelineName = 'nemesis-audit', profile = 'standard' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-azure-devops-adapter',
    pipelineName,
    steps: [
      { script: `npm install --global @orthic-labs/nemesis`, displayName: 'Install nemesis' },
      { script: `nemesis audit . --profile ${profile} --out .audit`, displayName: 'Run nemesis audit' },
      { task: 'PublishPipelineArtifact@1', inputs: { path: '.audit', artifact: 'nemesis' } },
    ],
    canonicalCli: true,
  };
}
