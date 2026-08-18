#!/usr/bin/env python3
"""Detection primitives for the least-privilege ResearchRoute."""
from __future__ import annotations

import re

DOMAIN_VALUES = {'general', 'market', 'technical', 'scientific', 'medical', 'legal'}
OPERATIONS = {'discover', 'compare', 'verify', 'analyze', 'advise', 'review', 'draft', 'procedure', 'manage-corpus', 'generate-artifact'}
METHODS = {'web', 'competitor', 'reddit', 'audience', 'trends', 'scholarly', 'document', 'authority'}
PROVIDERS = {'browser', 'local-corpus', 'notebooklm', 'domain-default'}
ASSURANCE = {'quick', 'standard', 'verified'}
SCALE = {'focused', 'broad', 'dossier'}
SENSITIVITY = {'public', 'private', 'highly-sensitive'}

PERSONAL_FIRST_PERSON = re.compile(r"\b(my|mine|i\s+(?:am|have|take|use|was|were|got)|i'm|i've|me)\b", re.I)
OTHER_PATIENT = re.compile(r"\b(my\s+(?:wife|husband|mother|father|friend|child|son|daughter)|his|her)\b", re.I)
COUNTRY_PATTERNS = [
    ('IN', re.compile(r"\b(india|indian|ipc|bns|bnss|crpc|e-?jagriti|e-?daakhil|consumer commission|ncdrc|rbi|sebi|mca)\b", re.I)),
    ('US', re.compile(r"\b(united states|u\.s\.|usa|federal court|ftc|sec|fda)\b", re.I)),
    ('GB', re.compile(r"\b(united kingdom|u\.k\.|england|wales|scotland|cma|fca uk)\b", re.I)),
    ('EU', re.compile(r"\b(european union|eu law|gdpr|european commission|ecj|cjeu)\b", re.I)),
]
LEGAL_AREA_PATTERNS = [
    ('criminal', re.compile(r"\b(criminal|fir|bail|chargesheet|charge sheet|ipc|bns|bnss|crpc|offence|accused|arrest|quash)\b", re.I)),
    ('consumer', re.compile(r"\b(consumer|refund|defective product|deficiency in service|unfair trade|e-?jagriti|e-?daakhil|consumer commission)\b", re.I)),
    ('contract', re.compile(r"\b(contract|agreement|msa|nda|terms|clause|redline|indemnity|limitation of liability)\b", re.I)),
    ('employment', re.compile(r"\b(employment|employee|employer|termination|severance|workplace|labour|labor law)\b", re.I)),
    ('tax', re.compile(r"\b(tax|gst|income tax|irs|assessment)\b", re.I)),
    ('ip', re.compile(r"\b(trademark|copyright|patent|intellectual property)\b", re.I)),
    ('privacy', re.compile(r"\b(privacy|gdpr|dpdp|data protection|personal data)\b", re.I)),
    ('family', re.compile(r"\b(divorce|custody|maintenance|alimony|family law)\b", re.I)),
    ('immigration', re.compile(r"\b(visa|immigration|citizenship|residency permit)\b", re.I)),
    ('corporate', re.compile(r"\b(company law|corporate|shareholder|director|mca|sebi)\b", re.I)),
    ('regulatory', re.compile(r"\b(regulatory|regulator|compliance|licence|license|notification)\b", re.I)),
    ('civil', re.compile(r"\b(civil suit|injunction|damages|decree|plaintiff|defendant|tort)\b", re.I)),
]
MEDICAL_SIGNALS = re.compile(r"\b(medical|doctor|patient|drug|dose|dosing|medicine|medication|interaction|side effect|lab|blood test|diagnosis|symptom|[redacted-drug]|semaglutide|trt|testosterone|statin|[redacted-drug]|thyroid|insulin|hba1c|ldl|apo(?:b|a)|peptide|supplement|clinical trial)\b", re.I)
LEGAL_SIGNALS = re.compile(r"\b(legal|law|court|judgment|statute|regulation|consumer|criminal|bail|fir|contract|clause|lawsuit|complaint|appeal|tribunal|police|refund|trademark|copyright|tax)\b", re.I)
SCIENTIFIC_SIGNALS = re.compile(r"\b(study|paper|doi|pubmed|trial|meta-analysis|systematic review|scientific literature)\b", re.I)
TECHNICAL_SIGNALS = re.compile(r"\b(benchmark|latency|throughput|architecture|framework|library|runtime|compiler|api)\b", re.I)
MARKET_SIGNALS = re.compile(r"\b(market|competitor|positioning|pricing|audience|customer|icp|jtbd|lead|trend|reddit)\b", re.I)


def _unique(values: list[str]) -> list[str]:
    out = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def detect_domain(text: str) -> str:
    if MEDICAL_SIGNALS.search(text): return 'medical'
    if LEGAL_SIGNALS.search(text): return 'legal'
    if SCIENTIFIC_SIGNALS.search(text): return 'scientific'
    if TECHNICAL_SIGNALS.search(text): return 'technical'
    if MARKET_SIGNALS.search(text): return 'market'
    return 'general'


def detect_operation(text: str) -> str:
    lower = text.lower()
    checks = [
        ('generate-artifact', ('podcast', 'audio overview', 'slide deck', 'quiz', 'flashcards', 'infographic')),
        ('manage-corpus', ('create notebook', 'add these sources', 'upload these', 'index these documents')),
        ('procedure', ('how do i file', 'help me file', 'filing pack', 'consumer complaint', 'procedure')),
        ('draft', ('draft ', 'write a notice', 'write a complaint', 'prepare a memo', 'redline')),
        ('review', ('review ', 'audit ', 'check this agreement', 'review this document')),
        ('verify', ('verify', 'fact-check', 'fact check', 'are these claims accurate')),
        ('compare', ('compare', ' versus ', ' vs ', 'alternative to')),
        ('discover', ('find ', 'look up', 'discover', 'what is out there')),
        ('advise', ('what should i do', 'recommend', 'advise')),
    ]
    for operation, needles in checks:
        if any(needle in lower for needle in needles): return operation
    return 'analyze'


def detect_methods(text: str) -> list[str]:
    lower = text.lower(); found = []
    mapping = [
        ('reddit', ('reddit', 'subreddit')), ('competitor', ('competitor', ' vs ', ' versus ', 'alternative')),
        ('audience', ('audience', 'pain point', 'exact words', 'comments', 'customer', 'customers', 'customer interview', 'jtbd', 'jobs to be done', 'voc', 'survey')),
        ('trends', ('trend', 'last 30 days', 'last30days', 'gaining traction')),
        ('scholarly', ('paper', 'study', 'doi', 'pubmed', 'trial', 'meta-analysis', 'scientific literature')),
        ('document', ('document', 'pdf', 'transcript', 'agreement', 'contract', 'report')),
        ('authority', ('law', 'statute', 'regulation', 'judgment', 'court', 'official source', 'guideline', 'regulator')),
    ]
    for method, needles in mapping:
        if any(needle in lower for needle in needles): found.append(method)
    if not found or any(x in lower for x in ('web', 'online', 'search')): found.append('web')
    return _unique(found)


def detect_provider(text: str, domain: str, methods: list[str]) -> str:
    lower = text.lower()
    if 'notebooklm' in lower: return 'notebooklm'
    if methods == ['document'] or ('document' in methods and 'web' not in methods): return 'local-corpus'
    if any(x in lower for x in ('force browser', 'browser provider', 'live browser')): return 'browser'
    return 'domain-default'


def detect_assurance(text: str, domain: str, operation: str) -> str:
    lower = text.lower()
    if any(x in lower for x in ('quick', 'quickly', 'brief answer', 'rough scan', 'triage only')): return 'quick'
    if any(x in lower for x in ('verified', 'fact-check', 'fact check', 'publication', 'cite every', 'court filing', 'doctor-ready')): return 'verified'
    if domain in {'medical', 'legal'} or operation in {'verify', 'procedure'}: return 'verified'
    return 'standard'


def detect_scale(text: str) -> str:
    lower = text.lower()
    if any(x in lower for x in ('dossier', 'dissertation', 'chaptered', 'full investigation')): return 'dossier'
    if any(x in lower for x in ('landscape', 'broad', 'comprehensive', 'across the market', 'all competitors')): return 'broad'
    return 'focused'


def detect_sensitivity(text: str, domain: str, patient_kind: str | None = None) -> str:
    lower = text.lower()
    if any(x in lower for x in ('confidential', 'privileged', 'highly sensitive', 'patient id')): return 'highly-sensitive'
    if patient_kind in {'self', 'other-identified'} or any(x in lower for x in ('my private', 'my clinic', 'my case', 'my contract')): return 'private'
    return 'public'


def _country(text: str) -> str | None:
    hits = [code for code, pattern in COUNTRY_PATTERNS if pattern.search(text)]
    return hits[0] if len(set(hits)) == 1 else None


def _legal_area(text: str) -> str | None:
    hits = [area for area, pattern in LEGAL_AREA_PATTERNS if pattern.search(text)]
    return hits[0] if len(set(hits)) == 1 else None


def _issue(text: str) -> str:
    return re.sub(r'\s+', ' ', text).strip()[:500]
