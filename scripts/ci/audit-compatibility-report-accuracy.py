#!/usr/bin/env python3
"""Invoke exact CI-built native controls; root integration owns compilation & admission."""
import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess


def main():
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--test-binary', type=Path)
    inputs.add_argument('--build-messages', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    api = runpy.run_path(str(Path(__file__).with_name('validate-compatibility-report-accuracy.py')))
    binary = args.test_binary
    if args.build_messages:
        rows = [api['parsed'](line) for line in args.build_messages.read_bytes().splitlines() if line]
        artifacts = [row for row in rows if row.get('reason') == 'compiler-artifact'
                     and row.get('target', {}).get('name') == 'compatibility_report_accuracy'
                     and row.get('target', {}).get('kind') == ['test']
                     and row.get('profile', {}).get('test') is True and row.get('executable')]
        if len(artifacts) != 1 or not rows or rows[-1] != {'reason': 'build-finished', 'success': True}:
            parser.error('exact successful prebuilt compatibility test artifact required')
        binary = Path(artifacts[0]['executable'])
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        parser.error('explicit existing native test binary required')
    output = args.output.resolve()
    if output == root or root in output.parents or output.exists():
        parser.error('fresh external retained output required')
    output.mkdir(parents=True)
    if args.build_messages:
        with (output / 'build-messages.jsonl').open('xb') as destination:
            destination.write(args.build_messages.read_bytes())
    manifest = api['source_manifest'](root)
    source_path = output / 'source-manifest.json'
    with source_path.open('xb') as destination:
        destination.write(api['encoded'](manifest))
    controls = output / 'controls'
    env = dict(os.environ)
    env.update(LEGION_COMPATIBILITY_REPORT_SOURCE_MANIFEST=str(source_path), LEGION_COMPATIBILITY_REPORT_OUTPUT=str(controls))
    command = [str(binary.resolve()), '--exact', 'compatibility_report_native_known_answers', '--ignored',
               '--nocapture', '--test-threads=1']
    with (output / 'harness.log').open('xb') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, cwd=root, timeout=300, check=False)
    execution = {'schema': 'legion-compatibility-report-control-execution/1', 'command': command,
                 'exitCode': result.returncode, 'success': result.returncode == 0,
                 'testBinaryDigest': api['digest'](binary.read_bytes()), 'sourceManifest': manifest,
                 'productionQualification': False, 'wholeProviderQualified': False}
    with (output / 'execution.json').open('xb') as destination:
        destination.write(api['encoded'](execution))
    print((output / 'harness.log').read_text(), end='')
    if result.returncode != 0:
        return 1
    row = api['parsed']((controls / 'compatibility.core.json').read_bytes())
    api['validate'](root, row)
    api['rejection_controls'](root, row)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
