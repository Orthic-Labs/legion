#!/usr/bin/env python3
"""Run prebuilt genuine owner controls; provisioning & build admission stay with root integration."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-binary', required=True, type=Path)
    parser.add_argument('--owner-binary', required=True, type=Path)
    parser.add_argument('--fixture-identities', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('current controls require native macOS production ownership trust')
    for source in [args.test_binary, args.owner_binary, args.fixture_identities]:
        if not source.is_absolute() or not source.is_file():
            parser.error(f'explicit existing absolute file required: {source}')
    source_root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output == source_root or source_root in output.parents:
        parser.error('retained output must stay outside repository')
    if output.exists() and any(output.iterdir()):
        parser.error('output must be new or empty; never replace evidence')
    output.mkdir(parents=True, exist_ok=True)
    fixture = json.loads(args.fixture_identities.read_bytes())
    for name in ['positive', 'clean']:
        row = fixture[name]
        if set(row) != {'root', 'repositoryIdentity', 'commit', 'tree'}:
            parser.error('fixture source identity requires exactly root/repositoryIdentity/commit/tree')
        root = Path(row['root'])
        if not root.is_absolute() or root.resolve() != root:
            parser.error('fixture root must be absolute & canonical')
        if root == source_root or source_root in root.parents:
            parser.error('constructed fixture must stay outside canonical repository')
    env = dict(os.environ)
    env.update(LEGION_OWNERSHIP_NATIVE_OWNER=str(args.owner_binary.resolve()),
               LEGION_OWNERSHIP_FIXTURE_IDENTITIES=str(args.fixture_identities.resolve()),
               LEGION_OWNERSHIP_ACCURACY_OUTPUT=str(output / 'controls'))
    command = [str(args.test_binary.resolve()), '--exact', 'ownership_native_sdk_known_answers',
               '--ignored', '--nocapture', '--test-threads=1']
    with (output / 'harness.log').open('xb') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                cwd=source_root, timeout=900, check=False)
    receipt = {'schema': 'legion-ownership-native-control-execution/1',
               'success': result.returncode == 0, 'exitCode': result.returncode,
               'productionQualification': False, 'qualificationEligible': False,
               'command': command,
               'files': {str(p.resolve()): 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [args.test_binary, args.owner_binary, args.fixture_identities]}}
    (output / 'execution.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    return 0 if result.returncode == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
