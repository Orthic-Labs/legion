// Reconcile only receipts bound to selected providers, sealed repository state,
// and declared denominators. Invalid receipts remain visible but cannot close a run.
import { sameBinding } from './binding.mjs';

const receiptBinding=(receipt)=>receipt.binding??receipt.providerResult?.binding??null;
const receiptDenominator=(receipt)=>receipt.denominatorDigest??receipt.providerResult?.coverage?.denominatorDigest??null;
const expectedDenominator=(plan,provider)=>provider.denominatorDigest??provider.denominator?.digest??plan.denominator?.providerDigests?.[provider.id]??null;

export function reconcileRun({ plan, receipts = [], artifacts = null }, host) {
  const planned=new Map((plan.providers??[]).map((provider)=>[provider.id,provider]));
  const grouped=new Map();for(const receipt of receipts){const rows=grouped.get(receipt.provider)??[];rows.push(receipt);grouped.set(receipt.provider,rows);}
  const duplicateChecks=[...grouped].filter(([,rows])=>rows.length!==1&&planned.has(rows[0]?.provider)).map(([id])=>id).sort();
  const unplannedChecks=[...grouped.keys()].filter((id)=>!planned.has(id)).sort();
  const bindingMismatches=[];const denominatorMismatches=[];
  for(const receipt of receipts){const provider=planned.get(receipt.provider);if(!provider)continue;if(plan.binding&&!sameBinding(receiptBinding(receipt),plan.binding))bindingMismatches.push({provider:receipt.provider,expected:plan.binding,actual:receiptBinding(receipt)});const expected=expectedDenominator(plan,provider);if(expected&&receiptDenominator(receipt)!==expected)denominatorMismatches.push({provider:receipt.provider,expected,actual:receiptDenominator(receipt)});if(receipt.providerResult?.provider&&receipt.providerResult.provider!==receipt.provider)bindingMismatches.push({provider:receipt.provider,kind:'provider-result-mismatch',actual:receipt.providerResult.provider});}
  const invalidProviders=new Set([...duplicateChecks,...bindingMismatches.map(({provider})=>provider),...denominatorMismatches.map(({provider})=>provider)]);
  const providerResults=(plan.providers??[]).map((provider)=>{
    const receipt=grouped.get(provider.id)?.[0];
    if(!receipt||invalidProviders.has(provider.id))return{provider:provider.id,phase:provider.phase,status:invalidProviders.has(provider.id)?'invalid':'missing',complete:false,benchmark:provider.benchmark,coverageGaps:[{kind:invalidProviders.has(provider.id)?'invalid-terminal-receipt':'missing-terminal-receipt'}]};
    return{provider:provider.id,phase:provider.phase,status:receipt.providerResult?.status??'unproven',complete:receipt.providerResult?.complete===true,spawnStatus:receipt.spawnStatus??null,exitCode:receipt.exitCode??null,benchmark:provider.benchmark,coverageGaps:receipt.providerResult?.coverageGaps??[]};
  });
  const capabilityGaps=plan.capabilityImpacts??[];
  const baselineGaps=(plan.controlBaseline?.controls??[]).filter((control)=>control.unimplemented||!(control.providers??[]).length).map((control)=>({kind:'unmapped-control',controlId:control.id}));
  const topologyGaps=plan.productInspection?.portfolio?.coverage?.unknownDeliverables?.map((targetId)=>({kind:'unknown-deliverable',targetId}))??[];
  const integrityGaps=[...duplicateChecks.map((provider)=>({kind:'duplicate-terminal-receipt',provider})),...unplannedChecks.map((provider)=>({kind:'unplanned-terminal-receipt',provider})),...bindingMismatches.map((row)=>({kind:'binding-mismatch',...row})),...denominatorMismatches.map((row)=>({kind:'denominator-mismatch',...row}))];
  const incomplete=providerResults.some((result)=>!result.complete||['unproven','missing','invalid','error','blocked','pending','skipped'].includes(result.status))||integrityGaps.length>0;
  const executionFailed=providerResults.some((result)=>['fail','error'].includes(result.status));
  return{schemaVersion:1,kind:'audit-facts',workspace:plan.root,out_dir:artifacts?.root??null,generated_at:host.clock.now().toISOString(),checks:receipts.map((receipt)=>({check:receipt.provider,status:receipt.providerResult?.status??receipt.spawnStatus,execution_status:receipt.spawnStatus,verdict:receipt.providerResult?.status==='pass'&&!invalidProviders.has(receipt.provider)?'pass':'unproven',exit_code:receipt.exitCode,findings_count:null})),incomplete:incomplete||capabilityGaps.length>0||baselineGaps.length>0||topologyGaps.length>0,executionFailed,provider_reconciliation:{providerResults,missingChecks:providerResults.filter(({status})=>status==='missing').map(({provider})=>provider),duplicateChecks,unplannedChecks,bindingMismatches,denominatorMismatches,unresolvedCoverage:[...capabilityGaps,...baselineGaps,...topologyGaps,...integrityGaps],missingRuntimeProviders:[]},plan};
}
