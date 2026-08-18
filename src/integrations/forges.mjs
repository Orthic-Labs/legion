// Forge CI adapters per PR41. GitLab/Bitbucket/Azure DevOps adapters call the
// same canonical CLI and consume identical JSON/SARIF; no forge adapter may
// alter planner, policy, or report truth.

export function gitlabCiAdapter({ jobName = 'legion-audit', profile = 'standard', baseline } = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-gitlab-ci-adapter',
    jobName,
    script: [
      `npm install --global @orthic-labs/legion`,
      `legion audit . --profile ${profile}${baseline ? ` --baseline ${baseline}` : ''} --out .audit`,
    ],
    artifacts: { reports: { sarif: '.audit/report.sarif' }, paths: ['.audit/'] },
    canonicalCli: true,
  };
}

export function bitbucketAdapter({ pipelineName = 'legion-audit', profile = 'standard' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-bitbucket-adapter',
    pipelineName,
    steps: [
      { step: { name: 'Legion audit', script: [`npm install --global @orthic-labs/legion`, `legion audit . --profile ${profile} --out .audit`] } },
    ],
    artifacts: { downloads: ['.audit/report.sarif'] },
    canonicalCli: true,
  };
}

export function azureDevopsAdapter({ pipelineName = 'legion-audit', profile = 'standard' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-azure-devops-adapter',
    pipelineName,
    steps: [
      { script: `npm install --global @orthic-labs/legion`, displayName: 'Install legion' },
      { script: `legion audit . --profile ${profile} --out .audit`, displayName: 'Run legion audit' },
      { task: 'PublishPipelineArtifact@1', inputs: { path: '.audit', artifact: 'legion' } },
    ],
    canonicalCli: true,
  };
}
