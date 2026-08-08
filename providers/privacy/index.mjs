export function privacyFacts(records=[]){return records.map((record)=>({...record,kind:'privacy',legalConclusion:false}));}
