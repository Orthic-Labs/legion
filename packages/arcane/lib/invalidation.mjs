// Dependency-invalidation cascade — G11 ("Evidence follows dependencies",
// ARCHITECTURE.md §1786) and detailed plan §6.3.
//
// S00 finding (legacy-semantic-inventory.json, dependency_invalidation_mechanics):
// Forge's own invalidation is caller-driven string-equality plus a
// locator-file re-hash, and explicitly has NO cascade — invalidating one
// evidence/claim row never propagates to anything that depended on it
// indirectly. This module is new work, not a port: it builds a real
// dependency graph and cascades transitively through `dimension: 'evidence'`
// edges.
//
// Historical-preservation rule (detailed plan §6.3 rule 7): staleness is
// appended as a new fact. A record's originally-bound dependency digests are
// never overwritten — `register()`'s stored dependency list is immutable
// after registration; `observeChange()` only ever flips a `stale` flag and
// appends to `staleEvents`.

import { ArcaneError } from './errors.mjs';
import { ulid } from './ids.mjs';

function depKey(dimension, ref) {
  return `${dimension}::${ref}`;
}

export class DependencyLedger {
  constructor({ clock = () => new Date().toISOString() } = {}) {
    this._clock = clock;

    /** @type {Map<string, object>} evidenceId -> record */
    this._evidence = new Map();
    /** @type {Map<string, Set<string>>} "dimension::ref" -> Set<evidenceId> directly bound to it */
    this._depIndex = new Map();
    /** @type {Map<string, Set<string>>} evidenceId (a dependency target) -> Set<evidenceId> that depend on it via dimension:'evidence' */
    this._evidenceDependents = new Map();
    /** @type {Map<string, string>} "dimension::ref" -> last-known digest observed for that key */
    this._currentDigest = new Map();

    /** @type {Map<string, Set<string>>} criterionId -> Set<evidenceId> */
    this._criterionEvidence = new Map();
    /** @type {Map<string, Set<string>>} claimId -> Set<criterionId> */
    this._claimCriteria = new Map();

    this._quarantine = [];
  }

  /**
   * Register an evidence record's dependency edges.
   * @param {string} evidenceId
   * @param {Array<{dimension:string, ref:string, digest:string}>} dependencies
   * @param {{trusted?: boolean}} [meta] `trusted:false` (legacy/unauthenticated
   *   evidence) means this record can be linked and cascaded against, but can
   *   never make a criterion `proven` — see proofEligibility. Additive over
   *   the binding 2-arg signature; existing 2-arg callers get trusted:true.
   */
  register(evidenceId, dependencies = [], { trusted = true } = {}) {
    if (typeof evidenceId !== 'string' || evidenceId.length === 0) {
      throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', 'register requires a non-empty evidenceId', { evidenceId });
    }
    const record = {
      evidenceId,
      dependencies: dependencies.map((d) => Object.freeze({ dimension: d.dimension, ref: d.ref, digest: d.digest })),
      stale: false,
      staleEvents: [],
      corrupt: false,
      corruptReason: null,
      trusted,
      registeredAt: this._clock(),
    };
    this._evidence.set(evidenceId, record);

    for (const dep of dependencies) {
      const key = depKey(dep.dimension, dep.ref);
      if (!this._depIndex.has(key)) this._depIndex.set(key, new Set());
      this._depIndex.get(key).add(evidenceId);
      if (!this._currentDigest.has(key)) this._currentDigest.set(key, dep.digest);

      if (dep.dimension === 'evidence') {
        // dep.ref is the evidenceId this record transitively depends on.
        if (!this._evidenceDependents.has(dep.ref)) this._evidenceDependents.set(dep.ref, new Set());
        this._evidenceDependents.get(dep.ref).add(evidenceId);
      }
    }
    return { evidenceId };
  }

  /**
   * Bind an evidence record to a proof/claim eligibility edge.
   * @param {string} evidenceId
   * @param {{criterionId?: string|null, claimId?: string|null}} edges
   */
  link(evidenceId, { criterionId = null, claimId = null } = {}) {
    if (!this._evidence.has(evidenceId)) {
      throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', `link: unknown evidenceId ${evidenceId}`, { evidenceId });
    }
    if (!criterionId) {
      if (claimId) {
        throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', 'link: claimId requires criterionId', { evidenceId, claimId });
      }
      return;
    }
    if (!this._criterionEvidence.has(criterionId)) this._criterionEvidence.set(criterionId, new Set());
    this._criterionEvidence.get(criterionId).add(evidenceId);

    if (claimId) {
      if (!this._claimCriteria.has(claimId)) this._claimCriteria.set(claimId, new Set());
      this._claimCriteria.get(claimId).add(criterionId);
    }
  }

  /**
   * A dependency changed. Stales exactly the evidence bound to it, cascades
   * transitively through `dimension:'evidence'` edges, recomputes affected
   * criteria/claims, and returns exactly ONE structured invalidation event.
   * @returns {object} InvalidationEvent
   */
  observeChange({ dimension, ref, digest }) {
    const key = depKey(dimension, ref);
    const from = this._currentDigest.has(key) ? this._currentDigest.get(key) : null;
    this._currentDigest.set(key, digest);

    // --- direct staling: exactly the evidence bound to (dimension, ref) ---
    const directIds = this._depIndex.get(key) ?? new Set();
    const staledEvidence = [];
    for (const id of directIds) {
      const rec = this._evidence.get(id);
      if (!rec || rec.stale) continue;
      const dep = rec.dependencies.find((d) => d.dimension === dimension && d.ref === ref);
      if (dep && dep.digest !== digest) {
        rec.stale = true;
        rec.staleEvents.push({ at: this._clock(), reason: 'dependency-changed', dimension, ref, from: dep.digest, to: digest });
        staledEvidence.push(id);
      }
    }

    // --- transitive cascade through 'evidence' edges (G11) ---
    const cascadedEvidence = [];
    const touched = new Set(staledEvidence);
    const queue = [...staledEvidence];
    while (queue.length) {
      const current = queue.shift();
      const dependents = this._evidenceDependents.get(current);
      if (!dependents) continue;
      for (const depId of dependents) {
        if (touched.has(depId)) continue;
        touched.add(depId);
        const rec = this._evidence.get(depId);
        if (!rec) continue; // dangling reference; nothing to stale
        if (!rec.stale) {
          rec.stale = true;
          rec.staleEvents.push({ at: this._clock(), reason: 'cascaded-from-evidence', dimension: 'evidence', ref: current, from: null, to: null });
        }
        cascadedEvidence.push(depId);
        queue.push(depId);
      }
    }

    const touchedAll = new Set([...staledEvidence, ...cascadedEvidence]);

    // --- affected criteria: any criterion with at least one touched evidence id ---
    const affectedCriteria = [];
    for (const [criterionId, evSet] of this._criterionEvidence) {
      for (const id of evSet) {
        if (touchedAll.has(id)) {
          affectedCriteria.push(criterionId);
          break;
        }
      }
    }
    const affectedCriteriaSet = new Set(affectedCriteria);

    // --- affected claims: any claim resting on an affected criterion ---
    const affectedClaims = [];
    for (const [claimId, critSet] of this._claimCriteria) {
      for (const c of critSet) {
        if (affectedCriteriaSet.has(c)) {
          affectedClaims.push(claimId);
          break;
        }
      }
    }

    // --- unaffected: every registered evidence id this event did not touch ---
    const unaffected = [...this._evidence.keys()].filter((id) => !touchedAll.has(id));

    return Object.freeze({
      eventId: `invevt_${ulid()}`,
      at: this._clock(),
      changed: { dimension, ref, from, to: digest },
      staledEvidence,
      cascadedEvidence,
      affectedCriteria,
      affectedClaims,
      unaffected,
    });
  }

  isStale(evidenceId) {
    const rec = this._evidence.get(evidenceId);
    if (!rec) throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', `isStale: unknown evidenceId ${evidenceId}`, { evidenceId });
    return rec.stale;
  }

  /** Read back a registered evidence record (historical preservation check). Never throws for a corrupt record — corruption is reported, not hidden. */
  getEvidence(evidenceId) {
    const rec = this._evidence.get(evidenceId);
    if (!rec) throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', `getEvidence: unknown evidenceId ${evidenceId}`, { evidenceId });
    return { ...rec, dependencies: rec.dependencies.map((d) => ({ ...d })), staleEvents: rec.staleEvents.map((e) => ({ ...e })) };
  }

  /**
   * Mark an evidence entry corrupt/unreadable (detailed plan §5.3, WP4 action 9).
   * The record is never dropped — it stays in the ledger, quarantined, and
   * readable, but blocks any criterion it supports from becoming `proven`.
   */
  markCorrupt(evidenceId, reason) {
    const rec = this._evidence.get(evidenceId);
    if (!rec) throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', `markCorrupt: unknown evidenceId ${evidenceId}`, { evidenceId });
    rec.corrupt = true;
    rec.corruptReason = reason;
    this._quarantine.push({ evidenceId, reason, at: this._clock() });
  }

  quarantined() {
    return this._quarantine.map((q) => ({ ...q }));
  }

  /**
   * Recompute proof/claim eligibility for a criterion.
   * @returns {{status: 'proven'|'unproven'|'insufficient', reasons: string[], staleEvidence: string[]}}
   */
  proofEligibility(criterionId) {
    const evSet = this._criterionEvidence.get(criterionId);
    if (!evSet || evSet.size === 0) {
      return { status: 'insufficient', reasons: ['no evidence linked to criterion'], staleEvidence: [] };
    }

    const reasons = [];
    const staleEvidence = [];
    let anyCorrupt = false;
    let anyUntrusted = false;

    for (const id of evSet) {
      const rec = this._evidence.get(id);
      if (!rec) {
        anyCorrupt = true;
        reasons.push(`evidence ${id} missing from ledger`);
        continue;
      }
      if (rec.corrupt) {
        anyCorrupt = true;
        reasons.push(`evidence ${id} corrupt: ${rec.corruptReason}`);
      }
      if (!rec.trusted) {
        anyUntrusted = true;
        reasons.push(`evidence ${id} untrusted (legacy/unauthenticated import can never qualify)`);
      }
      if (rec.stale) {
        staleEvidence.push(id);
        reasons.push(`evidence ${id} stale`);
      }
    }

    let status;
    if (anyCorrupt || anyUntrusted) status = 'insufficient';
    else if (staleEvidence.length > 0) status = 'unproven';
    else status = 'proven';

    return { status, reasons, staleEvidence };
  }

  snapshot() {
    return {
      evidence: [...this._evidence.values()].map((r) => ({
        ...r,
        dependencies: r.dependencies.map((d) => ({ ...d })),
        staleEvents: r.staleEvents.map((e) => ({ ...e })),
      })),
      criteria: [...this._criterionEvidence.entries()].map(([criterionId, evSet]) => ({ criterionId, evidence: [...evSet] })),
      claims: [...this._claimCriteria.entries()].map(([claimId, critSet]) => ({ claimId, criteria: [...critSet] })),
      quarantined: this.quarantined(),
    };
  }
}
