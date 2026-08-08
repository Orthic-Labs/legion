import { digest } from './binding.mjs';
import { productTopologyStage } from './plan-stages/product-topology.mjs';
import { controlBaselineStage } from './plan-stages/control-baseline.mjs';
import { PLANNING_STAGE_IDS } from './plan-stages/registry.mjs';

const CLAIMS = new Set(['inventory', 'source', 'runtime', 'product', 'release']);
const CLAIM_RANK = Object.freeze({ inventory: 0, source: 1, runtime: 2, product: 3, release: 4 });
const REQUIRED_FOR=Object.freeze({
  'repository-binding':'inventory','cortex-projection':'inventory','product-portfolio':'inventory','component-graph':'source','stack-external-system-graph':'source','release-contract-product-context':'source','control-baseline':'source','evidence-capabilities':'source','scenario-matrices':'source','family-lens-provider-rule-selection':'runtime','provider-dag':'runtime','plan-sealing':'runtime'
});
const stage=(id,run)=>Object.freeze({id,requiredFor:REQUIRED_FOR[id],run});
const passThrough=(id,key)=>stage(id,async(options)=>{const artifact=options[key]??options.artifacts?.[id]??null;return artifact?{complete:true,status:'pass',artifact}:{complete:false,status:'missing',detail:`${id}-required`};});
const DEFAULT_STAGES = Object.freeze([
  passThrough('repository-binding','binding'),passThrough('cortex-projection','projection'),stage('product-portfolio',productTopologyStage.run),
  stage('component-graph',async(options)=>options.artifacts['product-portfolio']?{complete:true,status:'pass',artifact:options.artifacts['product-portfolio'].components}:{complete:false,status:'missing'}),
  stage('stack-external-system-graph',async(options)=>options.artifacts['product-portfolio']?{complete:true,status:'pass',artifact:options.artifacts['product-portfolio'].stacks}:{complete:false,status:'missing'}),
  passThrough('release-contract-product-context','releaseContext'),stage('control-baseline',controlBaselineStage.run),passThrough('evidence-capabilities','evidenceCapabilities'),passThrough('scenario-matrices','scenarioMatrices'),
  passThrough('family-lens-provider-rule-selection','selection'),passThrough('provider-dag','providerDag'),stage('plan-sealing',async()=>({complete:true,status:'pass',artifact:{sealed:true}}))
]);
const deepFreeze=(value)=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const nested of Object.values(value))deepFreeze(nested);Object.freeze(value);}return value;};

function requiredForClaim(stage, requestedClaim) {
  if (!CLAIMS.has(stage.requiredFor ?? 'inventory')) throw new Error(`stage ${stage.id} has unknown required claim level`);
  return CLAIM_RANK[requestedClaim] >= CLAIM_RANK[stage.requiredFor ?? 'inventory'];
}

export async function buildSealedPlan(options, host) {
  const profile = options.profile ?? 'standard';
  const requestedClaim = options.claimLevel ?? (profile === 'release' ? 'release' : profile === 'full' ? 'product' : 'source');
  if (!CLAIMS.has(requestedClaim)) throw new Error(`unknown claim level: ${requestedClaim}`);
  const stages = options.stages ?? DEFAULT_STAGES;
  const stageIds = new Set();
  for (const stage of stages) {
    if (!stage?.id || typeof stage.run !== 'function') throw new Error('plan stage requires id and run');
    if (stageIds.has(stage.id)) throw new Error(`duplicate plan stage: ${stage.id}`);
    stageIds.add(stage.id);
  }
  if(options.stages&&stages.map(({id})=>id).join('|')!==PLANNING_STAGE_IDS.join('|'))throw new Error('custom plan stages must preserve fixed 12-stage order');
  const artifacts = {};
  const gaps = [];
  for (const stage of stages) {
    const result = await stage.run({ ...options, artifacts }, host);
    if (!result?.complete) gaps.push({ stage: stage.id, status: result?.status ?? 'missing', detail: result?.detail ?? null });
    if (result?.artifact) artifacts[stage.id] = result.artifact;
  }
  const requiredStageIds = stages.filter((stage) => requiredForClaim(stage, requestedClaim)).map((stage) => stage.id);
  const claimGaps = gaps.filter((gap) => requiredStageIds.includes(gap.stage));
  const plan = {
    schemaVersion: 1, kind: 'nemesis-sealed-plan', root: options.root, profile, requestedClaim,
    binding: options.binding ?? options.repositoryBinding ?? null, stages: stages.map(({ id, requiredFor = 'inventory' }) => ({ id, requiredFor })), artifacts,
    providers: options.providers ?? [], gaps, requiredStageIds, claimGaps,
    completeForRequestedClaim: claimGaps.length === 0,
    config: options.config ?? {}, generatedAt: host.clock.now().toISOString(),
  };
  plan.planDigest = digest({ ...plan, generatedAt: undefined, planDigest: undefined });
  return deepFreeze(plan);
}
