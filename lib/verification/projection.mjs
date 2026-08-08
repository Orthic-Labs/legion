import { canonicalize } from '../core/binding.mjs';
const OMIT = new Set(['generatedAt','timestamp','outputDir','temporaryPath','presentationOrder','scheduleOrder']);
function project(value) { if (Array.isArray(value)) { const items = value.map(project); return items.every((item) => item && typeof item === 'object' && 'id' in item) ? items.sort((a, b) => String(a.id).localeCompare(String(b.id))) : items; } if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => !OMIT.has(key)).map(([key, item]) => [key, project(item)])); return value; }
export const semanticProjection = (value) => canonicalize(project(value));
