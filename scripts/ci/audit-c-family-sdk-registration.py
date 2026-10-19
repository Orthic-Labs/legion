#!/usr/bin/env python3
"""Dedicated C-family registration adapter metadata; never enrolls or promotes.

Shared registration gate must still enforce authenticated source-bound CI/log
retrieval. Every validate call derives eligibility from retained native semantics.
"""
from pathlib import PurePosixPath
import runpy

PROVIDER = 'code.c-family'
FAMILY = 'code-c-family-sdk'
HARNESS = 'c_family_sdk_accuracy'
VALIDATOR = 'scripts/ci/audit-c-family-sdk-accuracy.py'
SELF = 'scripts/ci/audit-c-family-sdk-registration.py'
SCHEMA = 'scripts/ci/schemas/audit-c-family-sdk-accuracy.schema.json'
SCOPE = 'source-bound CMake/Clang C-family operations/v1 known-answer SDK fixtures'
HARNESS_COMMAND = ['audit_cargo_test', '--test', HARNESS, HARNESS, '--', '--ignored', '--exact', '--nocapture', '--test-threads=1']
ORIGINAL_EMISSION = 'C_FAMILY_SDK_ACCURACY_ARTIFACT'
SUMMARY_EMISSION = 'C_FAMILY_SDK_ACCURACY_SUMMARY'


def adapter(entry):
    if entry['provider'] != PROVIDER or entry['family'] != FAMILY or entry['stage'] != 'finding' or entry['scope'] != SCOPE:
        raise AssertionError('dedicated C-family native SDK adapter scope differs')
    return FAMILY, HARNESS, 'canonical-json', HARNESS


def source_files(root):
    return sorted(set(runpy.run_path(str(root / VALIDATOR))['source_files'](root)) | {SELF, SCHEMA})


def validate_record(root, entry, record):
    adapter(entry)
    if entry['provenance']['platform'] != 'macos-15':
        raise AssertionError('native C-family platform differs')
    return runpy.run_path(str(root / VALIDATOR))['validate_record'](root, record, live=False)


def locator(root, record, original_bytes):
    original_path = PurePosixPath(record['cases'][0]['scratchRoot']).parent.parent / 'code-c-family-native-sdk.json'
    return runpy.run_path(str(root / VALIDATOR))['artifact_locator'](record, original_bytes, original_path)


def receipt_root(record):
    return PurePosixPath(record['cases'][0]['scratchRoot']).parents[3]


def qualification_fields():
    return {'productionQualification': False, 'selfProducerQualification': False, 'fixtureScope': SCOPE,
            'admissionScope': 'exact constructed SDK fixture authorizer; installed owner admission remains denied',
            'coverageScope': 'frozen executable-only CMake C/CPP operations/v1; unsupported project contexts remain gaps'}
