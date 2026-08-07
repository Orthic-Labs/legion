import { digest } from '../core/binding.mjs';
export function validateControl(control) { for (const key of ['id','version','selector','denominator','evidence','claimLevels']) if (control[key] == null) throw new Error(`control missing ${key}`); return control; }
export function validatePack(pack) { if (!pack.id || !pack.version || !Array.isArray(pack.controls)) throw new Error('invalid control pack'); return pack; }
export function controlDigest(control) { return digest(validateControl(control)); }
