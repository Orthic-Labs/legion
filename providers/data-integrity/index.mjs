export function integrityFacts(operations=[]){return operations.map((operation)=>({operation,kind:'integrity',evidenceRequired:true}));}
