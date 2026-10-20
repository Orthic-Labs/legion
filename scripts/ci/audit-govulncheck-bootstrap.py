#!/usr/bin/env python3
"""Managed-CI-only official govulncheck bootstrap; never run inside audited project.

Importable verify_enrollment(repository_root, enrollment, live=False) replays
retained source/data bindings without executing tools or using network.
Provisioning is NOT Audit owner admission or qualification evidence by itself.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import sys
import subprocess
import time
import tarfile
import urllib.request
import urllib.parse
import zipfile

SCHEMA = 'legion-govulncheck-enrollment/1'
MAX_NETWORK_BYTES = 128 * 1024 * 1024
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_TREE_FILES = 40000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def safe_relative(value):
    p = PurePosixPath(value)
    return bool(value) and not p.is_absolute() and str(p) == value and all(c not in ('', '.', '..') for c in p.parts) and not any(c in value for c in '\\\n\r\0')


def snapshot(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('noncanonical runtime root')
    files = {}
    size = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            p = Path(directory) / name
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise ValueError('symlink/special runtime input')
        for name in names:
            p = Path(directory) / name
            size += p.stat().st_size
            if len(files) >= MAX_TREE_FILES or size > MAX_TREE_BYTES:
                raise ValueError('runtime closure limit')
            rel = p.relative_to(root).as_posix()
            if not safe_relative(rel):
                raise ValueError('runtime path')
            files[rel] = digest(p.read_bytes())
    files = dict(sorted(files.items()))
    return {'root': str(root), 'files': files, 'digest': digest(canonical(files))}


def load_inputs(repository_root):
    path = Path(repository_root) / 'scripts/ci/audit-govulncheck-inputs.json'
    data = path.read_bytes()
    lock = json.loads(data)
    if lock['schema'] != 'legion-govulncheck-inputs/1':
        raise ValueError('input schema')
    return lock, digest(data)


def verify_enrollment(repository_root, enrollment, live=False):
    """No execution/network; exact official lock, complete recorded closure replay.

    live=True also rehashes actual runtime bytes. Offline replay proves recorded
    bindings only; actual SDK receipts are separately required by qualification.
    """
    if isinstance(enrollment, (str, Path)):
        enrollment = json.loads(Path(enrollment).read_text())
    lock, inputs_digest = load_inputs(repository_root)
    if enrollment.get('schema') != SCHEMA or enrollment.get('inputsDigest') != inputs_digest:
        raise ValueError('enrollment source binding')
    if enrollment.get('qualificationEligible') is not False:
        raise ValueError('bootstrap is not qualification')
    db = enrollment['database']
    if db['files'] != lock['database']['files'] or db['digest'] != lock['database']['digest']:
        raise ValueError('official database closure')
    if enrollment['databaseArchiveDigest'] != 'sha256:' + lock['database']['sha256']:
        raise ValueError('official database archive')
    if enrollment['moduleProxy'] != lock['moduleProxy']:
        raise ValueError('official source closure')
    if enrollment['go']['archiveDigest'] not in {'sha256:' + d for d in lock['go']['archives'].values()}:
        raise ValueError('Go archive pin')
    if enrollment['go']['version'] != lock['go']['version']:
        raise ValueError('Go version mismatch')
    scanner = enrollment['scanner']
    if scanner['module'] != lock['scanner']['module'] or scanner['version'] != lock['scanner']['version']:
        raise ValueError('scanner module identity')
    for process in enrollment['bootstrapProcesses']:
        if process.get('exitCode') != 0 or digest(process['stdout'].encode()) != process.get('stdoutDigest') or digest(process['stderr'].encode()) != process.get('stderrDigest'):
            raise ValueError('retained bootstrap process binding')
    if scanner['buildInfo'] not in enrollment['bootstrapProcesses'] or enrollment['go']['versionProcess'] not in enrollment['bootstrapProcesses']:
        raise ValueError('missing actual bootstrap identity process')
    go_path = enrollment['go']['path']
    if scanner['buildInfo']['argv'] != [go_path, 'version', '-m', scanner['path']] or enrollment['go']['versionProcess']['argv'] != [go_path, 'version']:
        raise ValueError('bootstrap identity argv')
    if (' ' + lock['go']['version'] + ' ') not in enrollment['go']['versionProcess']['stdout']:
        raise ValueError('actual Go version mismatch')
    if go_path != str(Path(enrollment['go']['runtime']['root']) / 'bin/go'):
        raise ValueError('Go runtime executable binding')
    build_info = scanner['buildInfo']['stdout']
    expected_module = '\tmod\t' + scanner['module'] + '\t' + scanner['version'] + '\t'
    if expected_module not in build_info or scanner['buildInfo']['exitCode'] != 0:
        raise ValueError('actual scanner build info')
    for part in [db, enrollment['moduleCache'], enrollment['go']['runtime']]:
        if part['digest'] != digest(canonical(part['files'])):
            raise ValueError('closure digest')
        if not Path(part['root']).is_absolute() or any(not safe_relative(p) for p in part['files']):
            raise ValueError('closure paths')
        if live and snapshot(Path(part['root'])) != part:
            raise ValueError('runtime input changed')
    prefix = 'golang.org/x/text@v0.3.6/'
    files = {k[len(prefix):]: v for k, v in enrollment['moduleCache']['files'].items() if k.startswith(prefix)}
    if files != lock['positiveControl']['files']:
        raise ValueError('official positive source closure')
    env = enrollment['environment']
    expected_env = {'LEGION_GOVULNCHECK_BIN': scanner['path'], 'LEGION_GOVULNCHECK_DB_ROOT': db['root'],
                    'LEGION_GOVULNCHECK_DB_ARCHIVE': enrollment['databaseArchivePath'],
                    'LEGION_GOVULNCHECK_ENROLLMENT_JSON': enrollment['enrollmentPath'],
                    'GOMODCACHE': enrollment['moduleCache']['root']}
    if env != expected_env or any(not Path(p).is_absolute() for p in env.values()):
        raise ValueError('enrollment environment')
    if live:
        if digest(Path(scanner['path']).read_bytes()) != scanner['digest']:
            raise ValueError('scanner changed')
        if digest(Path(enrollment['databaseArchivePath']).read_bytes()) != enrollment['databaseArchiveDigest']:
            raise ValueError('database archive changed')
    return {'inputsDigest': inputs_digest, 'scannerDigest': scanner['digest'], 'databaseDigest': db['digest'],
            'moduleCacheDigest': enrollment['moduleCache']['digest'], 'goRuntimeDigest': enrollment['go']['runtime']['digest']}


def validate_zip(path, max_files=40000, max_bytes=128 * 1024 * 1024):
    with zipfile.ZipFile(path) as archive:
        names = set()
        expanded = 0
        for info in archive.infolist():
            name = info.filename.rstrip('/')
            if not safe_relative(name) or name in names or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('unsafe official archive member')
            names.add(name)
            expanded += info.file_size
            if len(names) > max_files or expanded > max_bytes:
                raise ValueError('official archive limit')
        return archive.namelist()


def retain_rejected_download(row, data, failure_root):
    """Retain bounded raw response and facts without treating it as an archive."""
    failure_root = Path(failure_root)
    failure_root.mkdir(parents=True, exist_ok=True)
    key = digest(row['url'].encode()).removeprefix('sha256:')
    raw_path = failure_root / (key + '.response.bin')
    metadata_path = failure_root / (key + '.json')
    may_be_truncated = len(data) == row['bytes'] + 1
    raw_path.write_bytes(data)
    metadata = {
        'schema': 'legion-govulncheck-rejected-download/1',
        'url': row['url'],
        'expectedBytes': row['bytes'],
        'expectedDigest': 'sha256:' + row['sha256'],
        'observedBytes': len(data),
        'observedDigest': digest(data),
        'readLimitBytes': row['bytes'] + 1,
        'responseMayBeTruncated': may_be_truncated,
        'rawResponseFile': raw_path.name,
        'rawResponseDigest': digest(data),
    }
    metadata_path.write_bytes(canonical(metadata) + b'\n')
    return metadata


def account_download_response(row, data, downloaded, failure_root):
    """Reject mismatched/budget-exceeding bytes after retaining exact bounded evidence."""
    total = downloaded + len(data)
    reasons = []
    if len(data) != row['bytes']:
        reasons.append('size-mismatch')
    if digest(data) != 'sha256:' + row['sha256']:
        reasons.append('hash-mismatch')
    if total > MAX_NETWORK_BYTES:
        reasons.append('network-budget-exceeded')
    if reasons:
        retain_rejected_download(row, data, failure_root)
        raise ValueError('official source rejected; retained bounded response evidence: ' + ','.join(reasons))
    return total


def complete_module_proxy(proxy, rows):
    """Derive local discovery metadata only from authenticated pinned artifacts."""
    proxy = Path(proxy)
    artifacts = {}
    for row in rows:
        module, version, extension = row['module'], row['version'], row['extension']
        if not safe_relative(module) or not safe_relative(version) or '/' in version or extension not in ('info', 'mod', 'zip'):
            raise ValueError('module proxy identity')
        path = proxy / module / '@v' / (version + '.' + extension)
        data = path.read_bytes()
        if len(data) != row['bytes'] or digest(data) != 'sha256:' + row['sha256']:
            raise ValueError('module proxy source changed')
        artifacts.setdefault((module, version), set()).add(extension)
    pinned_versions = {}
    for (module, version), extensions in sorted(artifacts.items()):
        if 'mod' not in extensions:
            raise ValueError('module proxy version missing authenticated go.mod')
        directory = proxy / module / '@v'
        if 'info' not in extensions:
            # GOPROXY .info requires Version; Time is optional. This is local
            # metadata derived from a locked identity, not an official response
            # or invented commit timestamp. No source ZIP is synthesized.
            with (directory / (version + '.info')).open('xb') as target:
                target.write(canonical({'Version': version}) + b'\n')
        pinned_versions.setdefault(module, set()).add(version)
    for module, versions in sorted(pinned_versions.items()):
        # Deprecation checks consult @v/list even for exact-version installs.
        (proxy / module / '@v' / 'list').write_text(''.join(version + '\n' for version in sorted(versions)))


def prepare_module_cache(go, prepare, control, run):
    """Populate positive source & graph through the caller's pinned file proxy."""
    prepare.mkdir()
    (prepare / 'go.mod').write_text('module legion.invalid/offline-cache-preparation\n\ngo 1.26.0\n\nrequire ' + control['module'] + ' ' + control['version'] + '\n')
    (prepare / 'go.sum').write_text(control['module'] + ' ' + control['version'] + ' ' + control['sum'] + '\n' + control['module'] + ' ' + control['version'] + '/go.mod ' + control['goModSum'] + '\n')
    downloaded_control = run([str(go), 'mod', 'download', '-json', control['module'] + '@' + control['version']], prepare)
    report = json.loads(downloaded_control['stdout'])
    if report.get('Sum') != control['sum'] or report.get('GoModSum') != control['goModSum']:
        raise ValueError('actual module download checksum mismatch')
    # An old dependency's go.mod can require additional graph-only modules.
    # Permit checksum writes only in this isolated preparation module, using
    # authenticated file:// inputs; qualification itself remains offline.
    run([str(go), 'list', '-mod=mod', '-m', 'all'], prepare)
    run([str(go), 'list', '-m', 'all'], prepare)


def provision(args):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or not os.environ.get('RUNNER_TEMP'):
        raise ValueError('bootstrap requires managed GitHub CI')
    repository = Path(args.repository_root).resolve(strict=True)
    runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    output = Path(args.output_root)
    if not output.is_absolute() or output.exists() or not output.parent.resolve(strict=True).is_relative_to(runner) or output.is_relative_to(repository):
        raise ValueError('fresh isolated RUNNER_TEMP output required')
    go_root = Path(args.go_root).resolve(strict=True)
    go_archive = Path(args.go_archive).resolve(strict=True)
    lock, inputs_digest = load_inputs(repository)
    actual_archive = digest(go_archive.read_bytes())
    if actual_archive not in {'sha256:' + v for v in lock['go']['archives'].values()}:
        raise ValueError('Go archive does not match pinned source')
    output.mkdir()
    output = output.resolve(strict=True)
    proxy = output / 'module-proxy'
    downloads = output / 'downloads'
    downloads.mkdir()
    failure_root = runner / 'legion-provider-qualification' / 'downloads' / 'govulncheck-failure-evidence'
    started = time.monotonic()
    downloaded = 0

    def fetch(row, path):
        nonlocal downloaded
        if time.monotonic() - started > 600:
            raise ValueError('bootstrap network budget')
        request = urllib.request.Request(row['url'], headers={'User-Agent': 'legion-audit-govulncheck-bootstrap/1'})
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != 'https' or final.hostname not in ('proxy.golang.org', 'vuln.go.dev', 'storage.googleapis.com'):
                raise ValueError('unexpected official source redirect')
            data = response.read(row['bytes'] + 1)
        downloaded = account_download_response(row, data, downloaded, failure_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    for row in lock['moduleProxy']:
        path = proxy / row['module'] / '@v' / (row['version'] + '.' + row['extension'])
        fetch(row, path)
        if row['extension'] == 'zip':
            validate_zip(path)
    complete_module_proxy(proxy, lock['moduleProxy'])
    db_zip = downloads / 'vulndb.zip'
    fetch(lock['database'], db_zip)
    validate_zip(db_zip, max_files=5000, max_bytes=16 * 1024 * 1024)
    db_root = output / 'database'
    db_root.mkdir()
    with zipfile.ZipFile(db_zip) as archive:
        for info in archive.infolist():
            path = db_root / info.filename
            if info.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as target:
                    target.write(archive.read(info))
    database = snapshot(db_root)
    if database['files'] != lock['database']['files']:
        raise ValueError('database extraction closure mismatch')
    home = output / 'bootstrap-home'
    for path in [home / 'Library/Application Support/go/telemetry', home / '.config/go/telemetry', home / 'AppData/Roaming/go/telemetry']:
        path.mkdir(parents=True)
        (path / 'mode').write_bytes(b'off')
    tools = output / 'tools'
    tools.mkdir()
    go = go_root / 'bin/go'
    env = {'PATH': str(go_root / 'bin') + os.pathsep + '/usr/bin:/bin', 'HOME': str(home),
           'XDG_CONFIG_HOME': str(home / '.config'), 'APPDATA': str(home / 'AppData/Roaming'),
           'GOROOT': str(go_root), 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOSUMDB': 'off',
           'GOPROXY': proxy.as_uri(), 'GOWORK': 'off', 'CGO_ENABLED': '0',
           'GOCACHE': str(output / 'build-cache'), 'GOPATH': str(output / 'tool-gopath'),
           'GOMODCACHE': str(output / 'tool-mod-cache'), 'GOBIN': str(tools), 'TMPDIR': str(output / 'tmp')}
    Path(env['TMPDIR']).mkdir()
    records = []

    def run(argv, cwd, timeout=300):
        begin = time.time()
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
            raise ValueError('bootstrap output limit')
        record = {'argv': [str(x) for x in argv], 'cwd': str(cwd), 'startedUnix': begin,
                  'exitCode': result.returncode, 'stdout': result.stdout.decode('utf-8', 'strict'),
                  'stderr': result.stderr.decode('utf-8', 'strict'), 'stdoutDigest': digest(result.stdout), 'stderrDigest': digest(result.stderr)}
        records.append(record)
        (output / 'bootstrap-processes.json').write_bytes(canonical(records) + b'\n')
        if result.returncode != 0:
            # CI uploads only this QA root; tool output lives outside it.
            failure = runner / 'legion-provider-qualification/provisioning-failures/govulncheck'
            failure.mkdir(parents=True, exist_ok=True)
            evidence = failure / 'bootstrap-processes.json'
            evidence.write_bytes(canonical(records) + b'\n')
            print('GOVULNCHECK_BOOTSTRAP_FAILURE ' + canonical({
                'argv': record['argv'], 'exitCode': result.returncode,
                'stderrPreview': result.stderr[:16384].decode('utf-8', 'replace'),
                'stderrBytes': len(result.stderr), 'stderrDigest': digest(result.stderr),
                'stdoutBytes': len(result.stdout), 'stdoutDigest': digest(result.stdout),
                'retainedProcesses': str(evidence),
            }).decode(), file=sys.stderr)
            raise ValueError('actual bootstrap command failed; retained raw process evidence')
        return record

    go_before = snapshot(go_root)
    archive_files = {}
    expanded = 0
    with tarfile.open(go_archive, 'r:gz') as archive:
        for member in archive:
            if member.isdir() and member.name.rstrip('/') == 'go':
                continue
            if not safe_relative(member.name.rstrip('/')) or not member.name.startswith('go/'):
                raise ValueError('unsafe Go archive path')
            if member.isdir():
                continue
            if not member.isfile() or member.name[3:] in archive_files:
                raise ValueError('unsafe Go archive member')
            expanded += member.size
            if expanded > MAX_TREE_BYTES or len(archive_files) >= MAX_TREE_FILES:
                raise ValueError('Go archive closure limit')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('Go archive member missing')
            archive_files[member.name[3:]] = digest(stream.read())
    if go_before['files'] != archive_files:
        raise ValueError('Go runtime differs from exact official archive')
    version = run([str(go), 'version'], output)
    if (' ' + lock['go']['version'] + ' ') not in version['stdout']:
        raise ValueError('actual Go version mismatch')
    run([str(go), 'install', lock['scanner']['package'] + '@' + lock['scanner']['version']], output)
    scanner = tools / 'govulncheck'
    build_info = run([str(go), 'version', '-m', str(scanner)], output)
    cache = output / 'module-cache'
    prepare = output / 'prepare-module-cache'
    env['GOMODCACHE'] = str(cache)
    prepare_module_cache(go, prepare, lock['positiveControl'], run)
    if snapshot(go_root) != go_before:
        raise ValueError('Go runtime changed during provisioning')
    enrollment_path = output / 'enrollment.json'
    enrollment = {'schema': SCHEMA, 'qualificationEligible': False, 'inputsDigest': inputs_digest,
                  'enrollmentPath': str(enrollment_path), 'moduleProxy': lock['moduleProxy'],
                  'databaseArchivePath': str(db_zip), 'databaseArchiveDigest': digest(db_zip.read_bytes()),
                  'database': database, 'moduleCache': snapshot(cache),
                  'go': {'path': str(go), 'archivePath': str(go_archive), 'archiveDigest': actual_archive,
                         'version': lock['go']['version'], 'versionProcess': version, 'runtime': go_before},
                  'scanner': {'path': str(scanner), 'digest': digest(scanner.read_bytes()),
                              'module': lock['scanner']['module'], 'version': lock['scanner']['version'], 'buildInfo': build_info},
                  'bootstrapProcesses': records}
    enrollment['environment'] = {'LEGION_GOVULNCHECK_BIN': str(scanner), 'LEGION_GOVULNCHECK_DB_ROOT': str(db_root),
                                 'LEGION_GOVULNCHECK_DB_ARCHIVE': str(db_zip),
                                 'LEGION_GOVULNCHECK_ENROLLMENT_JSON': str(enrollment_path), 'GOMODCACHE': str(cache)}
    verify_enrollment(repository, enrollment, live=True)
    enrollment_path.write_bytes(canonical(enrollment) + b'\n')
    print(str(enrollment_path))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository-root', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--go-root', required=True)
    parser.add_argument('--go-archive', required=True)
    provision(parser.parse_args())


if __name__ == '__main__':
    main()
