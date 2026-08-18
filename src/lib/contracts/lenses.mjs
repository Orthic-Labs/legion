import { validateFamilies } from './families.mjs';
export function validateLenses(records) { for (const item of records) for (const key of ['family','denominatorKind','evidence','cleanClaim','decisionMode','reasoning','benchmark']) if (item[key] == null) throw new TypeError(`lens ${item.id} missing ${key}`); validateFamilies(records); return records; }
