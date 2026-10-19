#!/usr/bin/env python3
"""Create literal committed fixture repos, then observe actual production owner trust.

Origin is an explicit constructed fixture declaration, never upstream provenance.
This command creates no enrollment, keys, protected policy, approvals or verdicts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

IDENTITY = 'https://github.com/orthic-labs/legion'
SOURCES = {'positive': b'let first = AXUIElementCreateSystemWide()\nlet second = AXUIElementCreateSystemWide()\n',
           'clean': b'let first = 42\nlet second = 43\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--owner-binary', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('native macOS production trust required')
    source = Path(__file__).resolve().parents[2]
    output = args.output
    if not output.is_absolute() or output.exists() or output.parent.resolve() != output.parent:
        parser.error('fresh absolute output with existing canonical parent required')
    if source == output or source in output.parents:
        parser.error('fixtures must stay outside repository')
    binary = args.owner_binary
    if not binary.is_absolute() or binary.resolve() != binary or not binary.is_file() or binary.is_symlink():
        parser.error('canonical native owner binary required')
    output.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')

    def git(root, *argv):
        result = subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                                 '-c', 'user.name=Legion constructed fixture', '-c', 'user.email=fixture@invalid.example',
                                 '-C', str(root), *argv], env=env, capture_output=True, timeout=60, check=True)
        return result.stdout.decode().strip()

    identities, observations = {}, {}
    for name, data in SOURCES.items():
        root = output / name
        root.mkdir(mode=0o700)
        git(root, 'init', '--quiet')
        # Production owner resolves this declared identity & enforces its protected registration.
        git(root, 'remote', 'add', 'origin', IDENTITY)
        (root / 'src').mkdir()
        (root / 'src/duplicate.swift').write_bytes(data)
        git(root, 'add', '--', 'src/duplicate.swift')
        git(root, 'commit', '--quiet', '-m', 'Constructed ownership known-answer ' + name)
        if git(root, 'status', '--porcelain'):
            raise AssertionError('fixture checkout not clean')
        identities[name] = {'root': str(root), 'repositoryIdentity': IDENTITY,
                            'commit': git(root, 'rev-parse', 'HEAD'), 'tree': git(root, 'rev-parse', 'HEAD^{tree}')}
        observations[name] = {}
        for mode in ('inputs', 'scan'):
            argv = [str(binary), str(root)] + (['--inputs'] if mode == 'inputs' else [])
            result = subprocess.run(argv, cwd=root, capture_output=True, timeout=180, check=False)
            (output / (name + '-' + mode + '.stdout.json')).write_bytes(result.stdout)
            (output / (name + '-' + mode + '.stderr.log')).write_bytes(result.stderr)
            if result.returncode != 0 or len(result.stdout) > 64 * 1024 * 1024:
                raise AssertionError('native owner process failed')
            observed = json.loads(result.stdout)
            observations[name][mode] = observed
    (output / 'identities.json').write_text(json.dumps(identities, indent=2) + '\n')
    (output / 'construction.json').write_text(json.dumps({
        'schema': 'legion-ownership-constructed-fixtures/1', 'sourceIdentityMeaning': 'constructed local commits with declared registered origin; no upstream commit authentication',
        'ownerBinaryDigest': 'sha256:' + hashlib.sha256(binary.read_bytes()).hexdigest(),
        'fixtures': identities, 'sourceDigests': {k: 'sha256:' + hashlib.sha256(v).hexdigest() for k, v in SOURCES.items()},
        'productionQualification': False, 'qualificationEligible': False}, indent=2) + '\n')
    (output / 'preflight.json').write_text(json.dumps({
        'schema': 'legion-ownership-native-preflight-observation/1', 'productionQualification': False,
        'qualificationEligible': False, 'observations': observations}, indent=2) + '\n')
    # Do not replace refusals with an admitted envelope. Preserve raw observations first.
    for name, modes in observations.items():
        for mode, document in modes.items():
            if document.get('inputInventory', {}).get('sourceIdentity') != identities[name]:
                raise AssertionError('native owner did not observe actual constructed source')
            owner = document.get('owner', {})
            if owner.get('enrollmentPending') is True or owner.get('code') or owner.get('error'):
                raise AssertionError('production owner enrollment or protected trust unavailable')
            if mode == 'inputs':
                if owner.get('complete') is not True or owner.get('enrollmentPending') is not False:
                    raise AssertionError('native owner inputs incomplete')
            else:
                evidence = owner.get('evidence', {})
                if evidence.get('source') != 'committed-git-tree' or evidence.get('trustEnrolled') is not True or evidence.get('floorOk') is not True:
                    raise AssertionError('authentic protected owner evidence required')
                if owner.get('verdict', {}).get('code') not in ('RK_OWNERSHIP_CLEAN', 'RK_OWNERSHIP_ADVISORY', 'RK_OWNERSHIP_VIOLATION'):
                    raise AssertionError('production owner refused constructed fixture')
    print(str(output / 'identities.json'))


if __name__ == '__main__':
    main()
