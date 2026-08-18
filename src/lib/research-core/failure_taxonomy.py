#!/usr/bin/env python3
"""Deterministic Research failure classification from real stage receipts."""
from __future__ import annotations

CLASSES = {
    'route_unresolved', 'approval_pending', 'gate_block', 'budget_exceeded',
    'provider_unavailable', 'primary_source_missing', 'source_independent_lt_2',
    'retracted_doi_undisclosed', 'retraction_unknown', 'notebooklm_answer_ledger',
    'patch_hunk_overflow', 'criminal_consumer_cross', 'personal_medical_default',
    'citation_unbound', 'citation_unsupported', 'gap_unresolved',
}


def classify(stage: str, payload: dict) -> list[str]:
    out = []
    if stage == 'route':
        if not payload.get('route'):
            out.append('route_unresolved')
        if any(v.get('verdict') == 'ask' for v in payload.get('gate_verdicts', [])):
            out.append('approval_pending')
        if any(v.get('verdict') == 'block' for v in payload.get('gate_verdicts', [])):
            out.append('gate_block')
    if stage == 'budget' and not payload.get('ok', True):
        out.append('budget_exceeded')
    if stage == 'provider' and payload.get('status') == 'unavailable':
        out.append('provider_unavailable')
    if stage == 'ledger':
        for v in payload.get('verdicts', []):
            text = ' '.join(v.get('reasons', [])) + ' ' + str(v.get('reason', ''))
            if 'primary-source' in text:
                out.append('primary_source_missing')
            if v.get('verdict') == 'downgrade' and 'independent' in text:
                out.append('source_independent_lt_2')
    if stage == 'retraction':
        for row in payload.get('results', []):
            if row.get('retracted') and not row.get('disclosed'):
                out.append('retracted_doi_undisclosed')
            if row.get('status') == 'unknown':
                out.append('retraction_unknown')
    if stage == 'notebooklm' and payload.get('promoted_to_ledger') and not payload.get('underlying_opened'):
        out.append('notebooklm_answer_ledger')
    if stage == 'patch' and not payload.get('ok') and ('hunk' in str(payload.get('reason', '')).lower()):
        out.append('patch_hunk_overflow')
    if stage == 'domain':
        if payload.get('criminal') and payload.get('consumer_refs_loaded'):
            out.append('criminal_consumer_cross')
        if payload.get('patient_kind') == 'anonymous' and payload.get('history_loaded'):
            out.append('personal_medical_default')
    if stage == 'citecheck':
        if payload.get('unbound'):
            out.append('citation_unbound')
        if payload.get('unsupported') or payload.get('dangling'):
            out.append('citation_unsupported')
    if stage == 'gap' and not payload.get('complete', True):
        out.append('gap_unresolved')
    return sorted(set(out))
