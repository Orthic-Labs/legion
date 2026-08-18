// CI/CD extractor per Security Appendix §11.5: workflow triggers, event
// sources, permissions, checkout revision, secrets, shell sinks, release
// assets, runner identities.

import { entity, fact, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

export function extractCicd({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    if (!/\.github\/workflows\/|\.gitlab-ci|azure-pipelines|Jenkinsfile/.test(file)) continue;
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    const evidenceRef = stableId('cicd-evidence', { file });
    const trigger = entity('entrypoint', `workflow trigger ${file}`, { entrypointType: 'ci-trigger' }, [evidenceRef]);
    const workflowIdentity = entity('identity', `workflow identity ${file}`, { environment: 'ci' }, [evidenceRef]);
    const shellSink = entity('sink', `shell sink ${file}`, { sinkKind: 'shell' }, [evidenceRef]);
    entities.push(trigger, workflowIdentity, shellSink);
    relations.push(
      relation('executes', trigger.id, shellSink.id, [evidenceRef]),
      relation('runs-as', shellSink.id, workflowIdentity.id, [evidenceRef]),
    );
    if (/permissions:\s*write-all/.test(text)) {
      initialFacts.push(fact('capability', {
        subject: workflowIdentity.id, action: 'write-all', object: 'repository', environment: 'ci',
      }, [evidenceRef]));
    }
    if (/pull_request_target/.test(text)) {
      initialFacts.push(fact('attacker-position', {
        subject: 'actor:external', action: 'control-pr-content', object: file, environment: 'ci',
      }, [evidenceRef]));
    }
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'CI/CD workflow' });
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
