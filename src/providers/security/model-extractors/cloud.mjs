// Cloud extractor (B7-007): Terraform/Kubernetes/cloud-config repository text
// plus upstream package-manifest and release-file evidence from the Blueprint
// projection. Extracts cloud identities/roles, public exposure, network
// relations, workload identity, secrets, and deployment contexts.
//
// Repository/config text and upstream projection facts only. No live cloud
// API call, no credential resolution, no network probe, no filesystem read
// outside the frozen denominator text already supplied by the caller.

import { entity, relation, fact, controlEntity } from './common.mjs';
import { assertEntityKind, assertRelationKind, assertFactKind, stableId } from '../contracts.mjs';

function typedEntity(kind, name, attributes, evidenceRefs, opts) {
  assertEntityKind(kind);
  return entity(kind, name, attributes, evidenceRefs, opts);
}

function typedRelation(kind, from, to, evidenceRefs, attributes, opts) {
  assertRelationKind(kind);
  return relation(kind, from, to, evidenceRefs, attributes, opts);
}

function typedFact(kind, fields, evidenceRefs) {
  assertFactKind(kind);
  return fact(kind, fields, evidenceRefs);
}

function typedControlEntity(controlType, name, evidenceRefs, attributes) {
  assertEntityKind('control');
  return controlEntity(controlType, name, evidenceRefs, attributes);
}

const CLOUD_FILE_PATTERN = /\.(tf|tfvars|yaml|yml|json)$/i;
const CLOUD_SDK_PATTERN = /^(?:@?aws-sdk\/|aws-sdk$|@google-cloud\/|@azure\/|kubernetes-client|@kubernetes\/client-node|@pulumi\/|aws-cdk-lib|cdktf)/i;
// Deliberately no \b word-boundary here: Terraform/Kubernetes identifiers are
// underscore-joined (aws_s3_bucket, aws_iam_role) and underscore is a \w
// character, so \b never falls between the keyword and its neighbors. Plain
// substring matching is the correct heuristic for this config-text scan.
const CLOUD_SIGNAL_PATTERN = /terraform|kubernetes|k8s|helm|cloudformation|serverless\.yml|pulumi|iam|role|policy|principal|assume_role|serviceaccount|s3|bucket|storage|blob|ingress|0\.0\.0\.0\/0|secretsmanager|secret_manager|vault|kms/i;
const PUBLIC_EXPOSURE_PATTERN = /0\.0\.0\.0\/0|public/i;
const NETWORK_CONTEXT_PATTERN = /ingress|security_group|firewall|network|expose/i;
const IAM_PATTERN = /iam|role|policy|principal|assume_role|serviceaccount/i;
const POLICY_SCOPE_PATTERN = /action|resource/i;
const WORKLOAD_IDENTITY_PATTERN = /workload[_ -]?identity|irsa|federated[_ -]?identity|oidc[_ -]?provider/i;
const STORAGE_PATTERN = /s3|bucket|storage|blob/i;
const SECRET_PATTERN = /secretsmanager|secret_manager|vault|kms|ssm[_ ]?parameter|parameter[_ -]?store|secret/i;
const SECRET_CONTROL_PATTERN = /kms|encrypt|rotation/i;
const DEPLOYMENT_PATTERN = /dockerfile|docker-compose|kind:\s*deployment|kind:\s*pod|serverless\.yml|\bpulumi\b|\bhelm\b/i;

function cloudSdkDependencies(projection) {
  const manifests = projection?.auditFacts?.packageManifests ?? [];
  const found = [];
  for (const manifest of manifests) {
    for (const dep of manifest.dependencies ?? []) {
      if (CLOUD_SDK_PATTERN.test(dep)) found.push({ manifest: manifest.path, dependency: dep });
    }
  }
  return found;
}

export function extractCloud({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  const sourceText = projection?.sourceText ?? {};
  const releaseFiles = new Set(projection?.auditFacts?.releaseFiles ?? []);
  const cloudSdkDeps = cloudSdkDependencies(projection);

  let sawCloudSignal = cloudSdkDeps.length > 0;

  for (const dep of cloudSdkDeps) {
    const evidenceRef = stableId('cloud-sdk-evidence', dep);
    const svc = typedEntity(
      'service',
      `cloud SDK dependency ${dep.dependency}`,
      { environment: 'cloud', manifest: dep.manifest, dependency: dep.dependency },
      [evidenceRef],
    );
    entities.push(svc);
    evidence.push({ id: evidenceRef, kind: 'source-location', file: dep.manifest, description: `Cloud SDK dependency ${dep.dependency}` });
  }

  for (const file of files ?? []) {
    const looksLikeCloudConfig = CLOUD_FILE_PATTERN.test(file) || (releaseFiles.has(file) && /dockerfile/i.test(file));
    if (!looksLikeCloudConfig) continue;

    const text = sourceText[file];
    if (text === undefined) {
      coverageGaps.push({
        kind: 'missing-rendered-configuration',
        domain: 'cloud',
        file,
        reason: 'file matched a cloud configuration pattern but no source text was projected for it',
      });
      continue;
    }
    const isDeploymentFile = /dockerfile/i.test(file);
    if (!text || !(CLOUD_SIGNAL_PATTERN.test(text) || isDeploymentFile)) continue;
    sawCloudSignal = true;

    if (PUBLIC_EXPOSURE_PATTERN.test(text) && NETWORK_CONTEXT_PATTERN.test(text)) {
      const evidenceRef = stableId('cloud-public-evidence', { file });
      const entrypoint = typedEntity(
        'entrypoint',
        `public cloud entrypoint ${file}`,
        { environment: 'cloud', entrypointType: 'network-ingress' },
        [evidenceRef],
      );
      entities.push(entrypoint);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Public cloud network entrypoint' });
      initialFacts.push(typedFact('network-reachability', {
        subject: 'actor:external', action: 'reach', object: entrypoint.id, scope: 'cloud',
        attributes: { source: file },
      }, [evidenceRef]));
    }

    if (IAM_PATTERN.test(text)) {
      const evidenceRef = stableId('cloud-iam-evidence', { file });
      const principal = typedEntity('principal', `IAM principal ${file}`, { environment: 'cloud' }, [evidenceRef]);
      const role = typedEntity('identity', `IAM role ${file}`, { environment: 'cloud' }, [evidenceRef]);
      entities.push(principal, role);
      relations.push(typedRelation('assumes-role', principal.id, role.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'IAM principal/role' });
      initialFacts.push(typedFact('principal-access', {
        subject: principal.id, action: 'assume', object: role.id, scope: 'cloud',
      }, [evidenceRef]));

      if (POLICY_SCOPE_PATTERN.test(text)) {
        const scopeRef = stableId('cloud-policy-scope-evidence', { file });
        const scope = typedEntity('permission-scope', `IAM policy scope ${file}`, { environment: 'cloud' }, [scopeRef]);
        entities.push(scope);
        relations.push(typedRelation('grants', role.id, scope.id, [scopeRef]));
        evidence.push({ id: scopeRef, kind: 'source-location', file, description: 'IAM policy action/resource scope' });
      }
    }

    if (WORKLOAD_IDENTITY_PATTERN.test(text)) {
      const evidenceRef = stableId('cloud-workload-identity-evidence', { file });
      const workload = typedEntity('identity', `workload identity ${file}`, { environment: 'cloud', workloadIdentity: true }, [evidenceRef]);
      const workloadProcess = typedEntity('process', `cloud workload ${file}`, { environment: 'cloud' }, [evidenceRef]);
      entities.push(workload, workloadProcess);
      relations.push(typedRelation('runs-as', workloadProcess.id, workload.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Workload identity binding' });
    }

    if (STORAGE_PATTERN.test(text)) {
      const evidenceRef = stableId('cloud-storage-evidence', { file });
      const storage = typedEntity('asset', `storage ${file}`, { assetKind: 'storage' }, [evidenceRef]);
      entities.push(storage);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Storage asset' });
    }

    if (SECRET_PATTERN.test(text)) {
      const evidenceRef = stableId('cloud-secret-evidence', { file });
      const secret = typedEntity('asset', `cloud secret ${file}`, { assetKind: 'secret' }, [evidenceRef]);
      const control = typedControlEntity('secret-management', `secret handling ${file}`, [evidenceRef], {
        controlState: SECRET_CONTROL_PATTERN.test(text) ? 'enforced' : 'unknown',
      });
      entities.push(secret, control);
      relations.push(typedRelation('protects', control.id, secret.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Cloud secret reference' });
    }

    if (DEPLOYMENT_PATTERN.test(text) || isDeploymentFile) {
      const evidenceRef = stableId('cloud-deployment-evidence', { file });
      const deployment = typedEntity('deployment-context', `deployment context ${file}`, { environment: 'cloud' }, [evidenceRef]);
      entities.push(deployment);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Deployment context' });
    }
  }

  if (!sawCloudSignal) {
    coverageGaps.push({
      kind: 'cloud-context-not-detected',
      domain: 'cloud',
      reason: 'no infrastructure-as-code, cloud SDK dependency, or cloud deployment file found in the denominator',
    });
  }

  return { entities, relations, evidence, initialFacts, coverageGaps };
}
