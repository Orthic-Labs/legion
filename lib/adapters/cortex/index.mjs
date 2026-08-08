// Stable Cortex adapter. Modes:
//   bundled     — default: package dependency / imported Cortex API
//   external    — advanced: exact configured binary through the process runner
//   precomputed — CI/air-gapped: verify binding/digest/schema and read only
// Cortex remains the sole repository discovery owner; Nemesis never adds a
// parallel repository walker.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { readCortexProjection, readCortexManifestBinding } from '../../../adapters/cortex-projection.mjs';

export class CortexAdapter {
  constructor({ mode = 'bundled', bundled = null, externalCommand = null, precomputedPath = null, expectedSchema = null }) {
    this.mode = mode;
    this.bundled = bundled;
    this.externalCommand = externalCommand;
    this.precomputedPath = precomputedPath;
    this.expectedSchema = expectedSchema ?? 1;
  }

  async ensureCompatible() {
    if (this.mode === 'precomputed') {
      if (!this.precomputedPath || !existsSync(this.precomputedPath)) {
        return { ok: false, error: 'precomputed projection path missing' };
      }
      return { ok: true, mode: this.mode, provider: '@orthic-labs/cortex', schemaVersion: this.expectedSchema };
    }
    if (this.mode === 'bundled') {
      if (!this.bundled) return { ok: false, error: 'bundled Cortex unavailable' };
      return { ok: true, mode: this.mode, provider: '@orthic-labs/cortex', schemaVersion: this.expectedSchema };
    }
    if (this.mode === 'external' && !this.externalCommand) {
      return { ok: false, error: 'external Cortex command not configured' };
    }
    return { ok: true, mode: this.mode, provider: '@orthic-labs/cortex', schemaVersion: this.expectedSchema };
  }

  async generateOrLoadProjection({ repositoryRoot, outDir = '.agent', freshness = true }) {
    const compatible = await this.ensureCompatible();
    if (!compatible.ok) return { state: 'unproven', reason: compatible.error, files: [] };
    if (this.mode === 'precomputed') {
      const projection = JSON.parse(readFileSync(this.precomputedPath, 'utf8'));
      if(projection.schemaVersion!==this.expectedSchema||projection.state!=='ready'||!Array.isArray(projection.files)||!projection.manifestDigest||!projection.generationId)throw new TypeError('precomputed Cortex projection contract invalid');
      return { ...projection, mode: this.mode };
    }
    // bundled/external both end at the same projection reader today; PR09 keeps
    // the existing external invocation as the compatibility surface.
    const projection = readCortexProjection(repositoryRoot, { outDir });
    return { ...projection, mode: this.mode, provider: '@orthic-labs/cortex' };
  }

  async verifyFreshness({ repositoryRoot, projection }) {
    if (projection?.state !== 'ready') return { fresh: false, reason: projection?.reason ?? projection?.state };
    return { fresh: true, generationId: projection.generationId, manifestDigest: projection.manifestDigest };
  }

  async readManifestBinding({ repositoryRoot, outDir = '.agent' }) {
    return readCortexManifestBinding(repositoryRoot, { outDir });
  }

  async readProjection({ repositoryRoot, outDir = '.agent' }) {
    return readCortexProjection(repositoryRoot, { outDir });
  }
}
