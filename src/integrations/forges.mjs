// Forge CI adapters invoke a preinstalled native Legion command and only
// translate each forge provider's job/artifact shape. Provisioning, policy, routing,
// capability, workflow, receipt, and report semantics belong to Legion core.

export function gitlabCiAdapter({ jobName = 'legion-audit', profile = 'standard', baseline } = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-gitlab-ci-adapter',
    jobName,
    script: [
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
      { step: { name: 'Legion audit', script: [`legion audit . --profile ${profile} --out .audit`] } },
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
      { script: `legion audit . --profile ${profile} --out .audit`, displayName: 'Run legion audit' },
      { task: 'PublishPipelineArtifact@1', inputs: { path: '.audit', artifact: 'legion' } },
    ],
    canonicalCli: true,
  };
}
