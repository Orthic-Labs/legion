#!/usr/bin/env python3
"""Enroll owner-provisioned native C-family tools in managed CI; never install.

This records observed bytes/versions, not official-archive provenance, owner
admission, CI authentication, or qualification. Explicit runtime roots must cover
CMake modules, LLVM tools/resources/runtime & selected macOS SDK. Run outside any
project under audit. Verification is importable, read-only & execution-free.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess

SCHEMA = 'legion-c-family-toolchain/1'
TOOLS = ('cmake', 'ctest', 'clang', 'clang++', 'clang-tidy', 'make')
MAX_FILES = 200000
MAX_BYTES = 8 * 1024 ** 3
MAX_PROJECTED_HASH_BYTES = 512 * 1024 ** 3
CONTROL_COUNT = 14
MAX_NATIVE_REQUESTS_PER_CASE = 24


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def file_digest(path):
    before = path.stat()
    value = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
            count += len(data)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or count != before.st_size:
        raise ValueError('native input changed while reading')
    return 'sha256:' + value.hexdigest()


def homebrew_clang_config_root(clang, homebrew_prefix, runtime_roots):
    """Enroll only selected Homebrew LLVM's expected shared config directory."""
    prefix = Path(homebrew_prefix)
    if not prefix.is_absolute() or prefix.resolve(strict=True) != prefix:
        raise ValueError('Homebrew prefix must be canonical')
    llvm = Path(clang).parent.parent.resolve(strict=True)
    cellar = prefix / 'Cellar' / 'llvm'
    if llvm.parent != cellar or llvm not in runtime_roots:
        raise ValueError('selected LLVM must belong to enrolled Homebrew formula root')
    source = llvm / 'etc' / 'clang'
    target = prefix / 'etc' / 'clang'
    if (source.parent.resolve(strict=True) != source.parent or not source.is_symlink()
            or not target.is_dir() or target.resolve(strict=True) != target
            or source.resolve(strict=True) != target):
        raise ValueError('unexpected Homebrew LLVM shared clang config target')
    return target


def tree(root, allowed_roots=None):
    """Full regular-file tree, including explicit aliases; bounded & no execution."""
    root = Path(root)
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('native runtime root must be canonical')
    allowed_roots = [Path(p) for p in (allowed_roots or [root])]
    files, aliases, total, nodes = {}, {}, 0, 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        if len(Path(directory).relative_to(root).parts) > 32:
            raise ValueError('native runtime depth')
        for name in dirs + names:
            nodes += 1
            if nodes > MAX_FILES * 2:
                raise ValueError('native runtime nodes')
            path = Path(directory) / name
            if any(c in str(path) for c in '\0\r\n'):
                raise ValueError('native runtime path')
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                resolved = path.resolve(strict=True)
                if not any(resolved == p or p in resolved.parents for p in allowed_roots):
                    raise ValueError(f'native alias escapes enrolled roots: {path} -> {resolved}')
                aliases[str(path)] = str(resolved)
            elif stat.S_ISREG(mode):
                total += path.stat().st_size
                if len(files) >= MAX_FILES or total > MAX_BYTES:
                    raise ValueError('native runtime bytes/files')
                files[str(path)] = file_digest(path)
            elif not stat.S_ISDIR(mode):
                raise ValueError('special native runtime input')
    files, aliases = dict(sorted(files.items())), dict(sorted(aliases.items()))
    return {'root': str(root), 'files': files, 'aliases': aliases,
            'digest': digest(encoded({'files': files, 'aliases': aliases}))}


def verify_enrollment(value, live=False):
    if isinstance(value, (str, Path)):
        value = json.loads(Path(value).read_bytes())
    cost = value.get('hashCost')
    if not isinstance(cost, dict) or cost.get('schema') != 'legion-c-family-hash-cost/1' or cost.get('status') != 'admitted' or cost.get('qualificationEligible') is not False:
        raise ValueError('unproven native hash cost')
    if any(type(cost.get(k)) is not int or cost[k] <= 0 for k in ('runtimeBytes', 'sdkBytes', 'runtimeFiles', 'sdkFiles', 'projectedHashBytes')):
        raise ValueError('missing measured native hash cost')
    projected = CONTROL_COUNT * MAX_NATIVE_REQUESTS_PER_CASE * (6 * cost['runtimeBytes'] + 2 * cost['sdkBytes']) + 4 * cost['runtimeBytes']
    if cost.get('controlCount') != CONTROL_COUNT or cost.get('maxNativeRequestsPerCase') != MAX_NATIVE_REQUESTS_PER_CASE or cost.get('runtimeReplaysPerRequest') != 6 or cost.get('sdkReplaysPerRequest') != 2 or cost.get('maxProjectedHashBytes') != MAX_PROJECTED_HASH_BYTES or cost['projectedHashBytes'] != projected or projected > MAX_PROJECTED_HASH_BYTES:
        raise ValueError('native hash I/O ceiling')
    if value['schema'] != SCHEMA or value['productionQualification'] is not False or value['qualificationEligible'] is not False:
        raise ValueError('enrollment is observation only')
    if value['provenance'] != 'managed-ci-observed-native-bytes' or value['officialArchiveAuthentication'] is not False:
        raise ValueError('unproven archive provenance')
    if set(value['tools']) != set(TOOLS) or value['platform']['system'] != 'Darwin':
        raise ValueError('native tool/platform closure')
    def absolute(p):
        path = Path(p)
        if not path.is_absolute() or '..' in path.parts or str(path) != p or any(c in p for c in '\0\r\n'):
            raise ValueError('native closure path')
        return path
    roots = [absolute(part['root']) for part in value['runtimeRoots']]
    if not roots or len(set(roots)) != len(roots):
        raise ValueError('runtime roots')
    files, aliases = {}, {}
    for part in value['runtimeRoots']:
        for p, d in part['files'].items():
            if absolute(part['root']) not in absolute(p).parents or not isinstance(d, str) or len(d) != 71 or not d.startswith('sha256:'):
                raise ValueError('native file closure membership')
        for p, target in part['aliases'].items():
            if absolute(part['root']) not in absolute(p).parents or not any(absolute(target) == r or r in absolute(target).parents for r in roots):
                raise ValueError('native alias closure membership')
        if part['digest'] != digest(encoded({'files': part['files'], 'aliases': part['aliases']})):
            raise ValueError('runtime tree identity')
        if live and tree(Path(part['root']), roots) != part:
            raise ValueError('runtime tree drift')
        for p, d in part['files'].items():
            if p in files and files[p] != d:
                raise ValueError('runtime identity collision')
            files[p] = d
        aliases.update(part['aliases'])
    if value['runtimeFiles'] != dict(sorted(files.items())):
        raise ValueError('full native closure differs')
    sdk = value['sdk']
    if sdk not in value['runtimeRoots'] or value['sdkRoot'] != sdk['root']:
        raise ValueError('SDK root/tree identity')
    if cost['runtimeFiles'] != len(files) or cost['sdkFiles'] != len(sdk['files']):
        raise ValueError('measured native file count differs')
    if live and (cost['runtimeBytes'] != sum(Path(p).stat().st_size for p in files) or cost['sdkBytes'] != sum(Path(p).stat().st_size for p in sdk['files'])):
        raise ValueError('measured native byte count drift')
    if not any('libclang_rt.asan' in p for p in files) or not any('/share/cmake-' in p for p in files):
        raise ValueError('missing actual ASan/CMake runtime')
    if len(value['observations']) != len(TOOLS):
        raise ValueError('missing native version observations')
    for name, observation in zip(TOOLS, value['observations']):
        tool = value['tools'][name]
        if observation['argv'] != [tool['path'], '--version'] or observation['exitCode'] != 0 or observation['signal'] is not None:
            raise ValueError('native version process identity')
        stdout, stderr = bytes(observation['stdoutBytes']), bytes(observation['stderrBytes'])
        if digest(stdout) != observation['stdoutDigest'] or digest(stderr) != observation['stderrDigest']:
            raise ValueError('native version bytes')
        first = (stdout.decode('utf-8') + stderr.decode('utf-8')).strip().splitlines()[0]
        if not tool['version'] or tool['version'] != first or files.get(aliases.get(tool['path'], tool['path'])) != tool['digest']:
            raise ValueError('observed native version/bytes mismatch')
        if live and file_digest(Path(tool['path'])) != tool['digest']:
            raise ValueError('native executable drift')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in TOOLS:
        parser.add_argument('--' + name.replace('++', 'xx'), type=Path, required=True)
    parser.add_argument('--runtime-root', type=Path, action='append', required=True)
    parser.add_argument('--homebrew-prefix', type=Path, required=True)
    parser.add_argument('--sdk-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('CI') != 'true' or platform.system() != 'Darwin':
        raise ValueError('explicit managed macOS CI required')
    roots = list(dict.fromkeys(p.resolve(strict=True) for p in args.runtime_root + [args.sdk_root]))
    config_root = homebrew_clang_config_root(args.clang, args.homebrew_prefix, roots)
    roots = list(dict.fromkeys(roots + [config_root]))
    snapshots = [tree(root, roots) for root in roots]
    files = dict(sorted((p, d) for part in snapshots for p, d in part['files'].items()))
    sdk_snapshot = next(part for part in snapshots if part['root'] == str(args.sdk_root.resolve(strict=True)))
    runtime_bytes = sum(Path(p).stat().st_size for p in files)
    sdk_bytes = sum(Path(p).stat().st_size for p in sdk_snapshot['files'])
    # Conservative fixture bound: both production snapshots & both SDK
    # version/scan admissions rehash runtime inputs. Do not begin native CI
    # controls when current full replay exceeds explicit I/O budget.
    native_requests = CONTROL_COUNT * MAX_NATIVE_REQUESTS_PER_CASE
    projected = native_requests * (6 * runtime_bytes + 2 * sdk_bytes) + 4 * runtime_bytes
    cost = {'schema': 'legion-c-family-hash-cost/1', 'runtimeFiles': len(files),
            'runtimeBytes': runtime_bytes, 'sdkFiles': len(sdk_snapshot['files']), 'sdkBytes': sdk_bytes,
            'controlCount': CONTROL_COUNT, 'maxNativeRequestsPerCase': MAX_NATIVE_REQUESTS_PER_CASE,
            'runtimeReplaysPerRequest': 6, 'sdkReplaysPerRequest': 2,
            'projectedHashBytes': projected, 'maxProjectedHashBytes': MAX_PROJECTED_HASH_BYTES,
            'qualificationEligible': False, 'status': 'admitted' if projected <= MAX_PROJECTED_HASH_BYTES else 'unproven-cost-limit'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_name('hash-cost.json').write_bytes(encoded(cost) + b'\n')
    print('C_FAMILY_HASH_COST ' + json.dumps(cost, sort_keys=True, separators=(',', ':')))
    if projected > MAX_PROJECTED_HASH_BYTES:
        raise ValueError('unproven-cost-limit: native controls not started')
    tools, observations = {}, []
    for name in TOOLS:
        requested = getattr(args, name.replace('++', 'xx').replace('-', '_'))
        # Preserve clang++ argv[0] semantics while removing owner-prefix aliases.
        path = requested.parent.resolve(strict=True) / requested.name
        if not path.is_file() or path.open('rb').read(2) == b'#!':
            raise ValueError('actual native executable required')
        process = subprocess.run([str(path), '--version'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, check=False, timeout=30, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if process.returncode != 0 or len(process.stdout) + len(process.stderr) > 1024 * 1024:
            raise ValueError('native version observation failed')
        first = (process.stdout.decode('utf-8') + process.stderr.decode('utf-8')).strip().splitlines()[0]
        tools[name] = {'path': str(path), 'digest': file_digest(path), 'version': first}
        observations.append({'argv': [str(path), '--version'], 'exitCode': process.returncode, 'signal': None,
                             'stdoutBytes': list(process.stdout), 'stderrBytes': list(process.stderr),
                             'stdoutDigest': digest(process.stdout), 'stderrDigest': digest(process.stderr)})
    sdk = next(part for part in snapshots if part['root'] == str(args.sdk_root.resolve(strict=True)))
    value = {'schema': SCHEMA, 'productionQualification': False, 'qualificationEligible': False,
             'provenance': 'managed-ci-observed-native-bytes', 'officialArchiveAuthentication': False,
             'platform': {'system': platform.system(), 'machine': platform.machine(), 'release': platform.release(), 'macOSVersion': platform.mac_ver()[0], 'ciImageOS': os.environ.get('ImageOS'), 'ciImageVersion': os.environ.get('ImageVersion')},
             'tools': tools, 'runtimeRoots': snapshots, 'runtimeFiles': files, 'sdk': sdk, 'sdkRoot': sdk['root'],
             'observations': observations, 'hashCost': cost}
    verify_enrollment(value, live=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(encoded(value) + b'\n')
    print('C_FAMILY_TOOLCHAIN_ENROLLMENT ' + json.dumps({'path': str(args.out.resolve()), 'digest': digest(args.out.read_bytes()),
                                                      'qualificationEligible': False}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
