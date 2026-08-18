import {resolve} from 'node:path';
import {RunArtifactStore} from '../artifacts/run-store.mjs';
import {inspectProduct} from './inspect-product.mjs';
import {buildSealedPlan} from './build-plan.mjs';
import {executePlan} from './execute-plan.mjs';
import {reconcileRun} from './reconcile-run.mjs';
import {adjudicateSubjects} from './adjudicate-run.mjs';
import {finalizeRun} from './finalize-run.mjs';
import {bindRepository} from './repository-binding.mjs';

const select=(providers,{only=[],skip=[]})=>{const include=new Set(only),exclude=new Set(skip);return providers.filter((provider)=>{const names=[provider.id,provider.runner?.check].filter(Boolean);return(!include.size||names.some((name)=>include.has(name)))&&!names.some((name)=>exclude.has(name));});};
const write=(store,path,kind,binding,value)=>store.writeJson({path,kind,producer:'legion.core',schemaVersion:1,binding,value});

export async function audit(options,host){
  const root=resolve(options.root);const runDir=resolve(root,options.outDir??'.audit/legion-run');
  const binding=options.binding??await bindRepository(root,options.bindingOptions??{});
  const store=new RunArtifactStore(runDir);await store.init();
  const projection=options.projection??await host.cortex?.project?.({root})??{schemaVersion:1,state:'unproven',files:[],reason:'cortex-projection-unavailable'};
  const productInspection=await inspectProduct({projection,binding,contract:options.releaseContract??{}},host);
  const providers=select(options.providers??[],options);
  const plan=await buildSealedPlan({...options,root,projection,productInspection,binding,providers,releaseContext:productInspection.releaseContract,evidenceCapabilities:productInspection.capabilities,scenarioMatrices:productInspection.scenarios,selection:options.selection??null,providerDag:options.providerDag??null},host);
  const planRecord=await write(store,'plan.json','plan',binding,plan);
  if(options.planOnly){const report={schemaVersion:1,kind:'repository-audit-report',audit_status:'incomplete',quality_gate:'unproven',incomplete:true,coverage_gaps:[{kind:'plan-only'}],findings:[],plan};const reportRecord=await write(store,'reports/report.json','report',binding,report);return{plan,execution:null,facts:null,judgments:null,report,artifacts:{runDir,plan:planRecord,report:reportRecord,records:store.records()}};}
  const execution=await executePlan(plan,host);const receiptsRecord=await write(store,'receipts.json','execution-receipts',binding,execution.receipts);
  const facts=reconcileRun({plan,receipts:execution.receipts,artifacts:{root:runDir}},host);const factsRecord=await write(store,'facts.json','facts',binding,facts);
  const judgments=await adjudicateSubjects(options.reviewSubjects??[],{mode:options.reasoning??'disabled',reviewer:options.reviewer??null,budget:options.reviewBudget??{maxTokens:0},contextPrefix:'audit',binding},host);const judgmentsRecord=await write(store,'judgments.json','judgments',binding,judgments);
  const report=await finalizeRun({plan,facts,results:{adjudication:{complete:judgments.complete,verdicts:judgments.receipts.filter(({complete})=>complete)}},policy:options.policy??{}},host);const reportRecord=await write(store,'reports/report.json','report',binding,report);
  return{plan,execution,facts,judgments,report,artifacts:{runDir,plan:planRecord,receipts:receiptsRecord,facts:factsRecord,judgments:judgmentsRecord,report:reportRecord,records:store.records()}};
}
