import { analyzeColorPairs } from '../visual/color.mjs';
export function analyzeContrast(pairs) { const result = analyzeColorPairs(pairs); return { ...result, provider: 'accessibility.contrast' }; }
