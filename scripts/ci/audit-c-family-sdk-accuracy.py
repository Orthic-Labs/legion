#!/usr/bin/env python3
"""Strict retained C-family native SDK validator; no execution/network/promotion.

Validates original controls, source/SDK/header denominators, actual SDK receipts &
raw diagnostics. Offline replay cannot authenticate CI or installed native bytes;
registration also requires maintainer-owned authenticated successful CI retrieval.
"""
import argparse
import copy
import hashlib
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import runpy

PROVIDER = 'code.c-family'
HARNESS = 'engine/crates/legion-audit/tests/c_family_sdk_accuracy.rs'
FIXTURES = 'scripts/ci/fixtures/audit-c-family-sdk-accuracy'
BOOTSTRAP = 'scripts/ci/audit-c-family-sdk-bootstrap.py'
VALIDATOR = 'scripts/ci/audit-c-family-sdk-accuracy.py'
CLAIM_SCOPE = 'source-bound CMake/Clang C-family operations/v1 known-answer SDK fixtures'
POLICY = 'legion-c-family-native-fixture-v1'
TOOLS = ('compiler', 'lint', 'analyzer', 'sanitizer', 'test')
CONTROLS = ('nonempty-clean', 'compiler-warning', 'lint-warning', 'analyzer-defect', 'sanitizer-defect',
            'test-failure', 'malformed-cmake', 'unenrolled-sysroot', 'orphan-source', 'orphan-header',
            'source-drift', 'missing-tool', 'rejected-admission', 'absent-sandbox')
CRATES = ('legion-audit', 'legion-effects', 'legion-provider-sdk', 'legion-contracts', 'legion-rules')
SOURCE_ROOTS = ['engine/crates/' + c + '/src' for c in CRATES] + ['src/registry/rules', 'src/registry/controls', FIXTURES]
SOURCE_FILES = ['engine/Cargo.toml', 'engine/Cargo.lock', 'engine/rust-toolchain.toml', HARNESS, BOOTSTRAP, VALIDATOR, 'scripts/ci/audit-c-family-sdk-registration.py', 'scripts/ci/schemas/audit-c-family-sdk-accuracy.schema.json'] + ['engine/crates/' + c + '/Cargo.toml' for c in CRATES]
FILES = ('CMakeLists.txt', 'common.h', 'detail.hpp', 'value.c', 'branch.cc', 'runtime.cxx', 'main.cpp')
TUS = ('value.c', 'branch.cc', 'runtime.cxx', 'main.cpp')


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), 'duplicate JSON key')
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'non-JSON number'))


def source_file(root, relative):
    path = PurePosixPath(relative)
    require(str(path) == relative and not path.is_absolute() and '..' not in path.parts and '\\' not in relative, 'source path')
    actual = Path(root)
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), 'source alias')
    require(actual.is_file(), 'missing source: ' + relative)
    return actual


def source_files(root):
    paths = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        directory = Path(root) / relative
        require(directory.is_dir() and not directory.is_symlink(), 'source root')
        for path in directory.rglob('*'):
            require(not path.is_symlink(), 'source closure alias')
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    return sorted(paths)


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in '\0\r\n\\'), 'absolute path encoding')
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and '..' not in path.parts and not value.startswith('//'), 'absolute canonical path')
    return path


def raw_bytes(value):
    require(isinstance(value, list) and all(type(b) is int and 0 <= b <= 255 for b in value), 'raw byte array')
    return bytes(value)


def fixture(root, control):
    files = {p: source_file(root, FIXTURES + '/' + p).read_text() for p in FILES}
    if control == 'compiler-warning':
        files['value.c'] = '#include "common.h"\nint c_value(void) { int never_used; return 10; }\n'
    elif control == 'lint-warning':
        files['branch.cc'] = '#include "detail.hpp"\nint cc_value() { volatile int input = 1; if (input == 1) { return 11; } else { return 11; } }\n'
    elif control == 'analyzer-defect':
        files['branch.cc'] = '#include "detail.hpp"\nint cc_value() { return 11; }\nint analyzer_only() { int *pointer = 0; return *pointer; }\n'
    elif control == 'sanitizer-defect':
        files['runtime.cxx'] = '#include "detail.hpp"\nint cxx_value() {\n#if __has_feature(address_sanitizer)\n  volatile int zero = 0; return 12 / zero;\n#else\n  return 12;\n#endif\n}\n'
    elif control == 'test-failure':
        files['main.cpp'] = files['main.cpp'].replace('return 0;', 'return 5;')
    elif control == 'malformed-cmake':
        files['CMakeLists.txt'] = 'cmake_minimum_required(VERSION 3.20)\nproject(\n'
    elif control == 'unenrolled-sysroot':
        files['CMakeLists.txt'] += 'set(CMAKE_OSX_SYSROOT /tmp)\n'
    elif control == 'orphan-source':
        files['unbuilt.c'] = 'int unbuilt(void) { return 7; }\n'
    elif control == 'orphan-header':
        files['unread.hpp'] = 'inline int unread() { return 7; }\n'
    return files


def artifact(receipt, value, scratch, live):
    if value is None:
        require(receipt is None, 'missing retained SDK bytes')
        return b''
    require(set(value) == {'path', 'absolutePath', 'digest', 'bytes', 'immutable', 'rawBytes'}, 'artifact fields')
    raw = raw_bytes(value['rawBytes'])
    path = PurePosixPath(value['path'])
    require(not path.is_absolute() and str(path) == value['path'] and all(p not in ('.', '..') for p in path.parts), 'artifact relative path')
    require(value['immutable'] is True and type(value['bytes']) is int and value['bytes'] == len(raw) and value['digest'] == digest(raw), 'raw SDK bytes/digest')
    require(receipt == {k: value[k] for k in ('path', 'digest', 'bytes', 'immutable')}, 'SDK artifact binding')
    require(absolute(value['absolutePath']) == scratch / 'artifacts' / path, 'SDK artifact root')
    if live:
        require(Path(value['absolutePath']).read_bytes() == raw, 'live artifact drift')
    return raw


def profile(root):
    text = str(root).replace('\\', '\\\\').replace('"', '\\"')
    return f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "{text}"))\n(deny file-write* (subpath "{text}"))\n'


def expected_cmake(stage, build, tools, sdk, sanitized):
    flags = '-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all' if sanitized else '-O0 -g'
    return ['--trace-expand', '--trace-format=json-v1', '--trace-redirect=' + str(build / 'configure-trace.jsonl'),
            '-S', str(stage), '-B', str(build), '-G', 'Unix Makefiles', '-DCMAKE_BUILD_TYPE=Debug',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCMAKE_MAKE_PROGRAM=' + tools['make']['path'],
            '-DCMAKE_C_COMPILER=' + tools['clang']['path'], '-DCMAKE_CXX_COMPILER=' + tools['clang++']['path'],
            '-DCMAKE_C_FLAGS=' + flags, '-DCMAKE_CXX_FLAGS=' + flags, '-DBUILD_TESTING=ON',
            '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF', '-DCMAKE_OSX_SYSROOT=' + sdk]


def command(request, case, enrollment):
    root, scratch = absolute(case['fixtureRoot']), absolute(case['scratchRoot'])
    stage = scratch / 'tmp/c-family/source'
    require(request['schemaVersion'] == 1 and request['providerId'] == PROVIDER and request['planId'] == case['planDigest'] and request['policyId'] == 'audit', 'request identity')
    require(request['origin'] == 'TargetProject' and request['shell'] is False and request['skipVersionProbe'] is False and request['versionRequirement'] is None, 'native request execution mode')
    require(request['sensitiveArgumentIndexes'] == request['sensitiveEnvironmentNames'] == [], 'hidden native inputs')
    require(0 < request['timeoutMs'] <= 120000 and request['stdoutLimit'] == request['stderrLimit'] == 33554432, 'native process bounds')
    args = request['args']
    require(len(args) > 4 and args[0] == '-f' and args[2] == '--', 'sandbox argv envelope')
    target = next((name for name, tool in enrollment['tools'].items() if tool['path'] == args[3]), None)
    require(target in ('cmake', 'ctest', 'clang', 'clang++', 'clang-tidy'), 'unenrolled native executable')
    require(request['executable'] == '/usr/bin/sandbox-exec', 'native macOS sandbox wrapper')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', request['expectedDigest']) is not None, 'sandbox identity')
    wanted_profile = digest(profile(root).encode())
    require(args[1] == str(scratch / 'sandbox' / ('audit-' + wanted_profile[7:] + '.sb')), 'sandbox profile path')
    require(request['versionArgs'] == args[:4] + ['--version'], 'actual native version probe argv')
    require(request['requiresNetworkSandbox'] is True, 'native sandbox requirement')
    if case['control'] == 'absent-sandbox':
        require(request['sandbox'] is None, 'absent sandbox control')
    else:
        require(request['sandbox'] == {'id': 'sandbox:macos:' + wanted_profile[7:], 'network': True, 'filesystemScope': str(root)}, 'authenticated native sandbox scope')
    require(request['acceptedExitCodes'] == ([0, 1] if target.startswith('clang') else [0]), 'native accepted exits')
    cwd = absolute(request['cwd'])
    require(cwd in (stage, stage.parent / 'build', stage.parent / 'instrumented'), 'isolated native cwd')
    env = request['environment']
    allowed = {'PATH', 'PATHEXT', 'SystemRoot', 'COMSPEC', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP', 'XDG_CACHE_HOME', 'CARGO_TARGET_DIR', 'npm_config_cache', 'RUFF_CACHE_DIR', 'MYPY_CACHE_DIR', 'PYTHONPYCACHEPREFIX', 'GOCACHE', 'PYTHONNOUSERSITE', 'GIT_CONFIG_NOSYSTEM', 'PYTHONDONTWRITEBYTECODE', 'NO_COLOR', 'CARGO_NET_OFFLINE', 'CARGO_TERM_COLOR', 'CARGO_HOME', 'RUSTUP_HOME', 'GOPATH', 'GOROOT', 'GOMODCACHE', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH', 'XDG_CONFIG_HOME', 'LEGION_C_FAMILY_STAGE', 'LEGION_C_FAMILY_GENERATED', 'LEGION_C_FAMILY_CMAKE_SHARE', 'LEGION_C_FAMILY_SDK_ENROLLMENT', 'LEGION_C_FAMILY_SDK_ENROLLMENT_DIGEST', 'ASAN_OPTIONS', 'UBSAN_OPTIONS'}
    require(set(env) <= allowed and set(env) <= set(request['environmentAllowlist']) <= allowed, 'native environment allowlist')
    search = list(dict.fromkeys(str(PurePosixPath(enrollment['tools'][n]['path']).parent) for n in sorted(enrollment['tools'])))
    require(env['PATH'] == ':'.join(search) and env['LEGION_C_FAMILY_STAGE'] == str(stage), 'pinned native search/stage')
    for name in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH'):
        require(env[name] == '', 'inherited compiler include path')
    require(env['HOME'] == env['USERPROFILE'] == str(stage.parent / 'home') and env['XDG_CONFIG_HOME'] == str(stage.parent / 'home/.config'), 'isolated native config')
    require(env['LEGION_C_FAMILY_SDK_ENROLLMENT_DIGEST'] == case['_enrollmentDigest'], 'request enrolled SDK digest')
    generated = parsed(env['LEGION_C_FAMILY_GENERATED'])
    for path, d in generated.items():
        p = absolute(path)
        require(stage.parent in p.parents or enrollment['runtimeFiles'].get(path) == d, 'external generated native input')
    native_args, task = args[4:], request['taskId']
    if target == 'cmake':
        require(any(native_args == expected_cmake(stage, stage.parent / name, enrollment['tools'], enrollment['sdkRoot'], sanitized) and task == ('sanitizer' if sanitized else 'compiler') for name, sanitized in (('build', False), ('instrumented', True))) or
                any(native_args == ['--build', str(stage.parent / name), '--parallel', '1'] and task == ('sanitizer' if name == 'instrumented' else 'compiler') for name in ('build', 'instrumented')), 'native configure/build argv')
    elif target == 'ctest':
        require(any(task == ('sanitizer' if name == 'instrumented' else 'test') and cwd == stage.parent / name and
                    native_args in (['--show-only=json-v1', '--output-log', str(cwd / 'tests.json.log')], ['--output-on-failure', '--no-tests=error', '--output-junit', str(cwd / 'junit.xml')]) for name in ('build', 'instrumented')), 'native CTest listing/execution argv')
        if task == 'sanitizer' and native_args[0] == '--output-on-failure':
            require(env['ASAN_OPTIONS'] == 'detect_leaks=0:halt_on_error=1:abort_on_error=0:exitcode=86' and env['UBSAN_OPTIONS'] == 'halt_on_error=1:print_stacktrace=1', 'actual sanitizer runtime flags')
    else:
        require(task in ('compiler', 'lint', 'analyzer') and cwd == stage, 'native static task')
        if target == 'clang-tidy':
            require(task == 'lint' and native_args[:3] == ['--config={}', '--checks=-*,bugprone-branch-clone', '--use-color=false'] and native_args[4] == '--' and native_args[3] in [str(stage / p) for p in TUS], 'actual declared clang-tidy checker')
            flags = native_args[5:]
        else:
            require(task != 'lint' and native_args[-1] in [str(stage / p) for p in TUS], 'native source invocation')
            flags = native_args[:-1]
            require(('--analyze' in flags) is (task == 'analyzer') and ('-fsyntax-only' in flags) is (task == 'compiler'), 'compiler/analyzer operation')
        require(all(a in ('-O0', '-g', '-Wall', '-Wextra', '-std=gnu11', '-std=gnu++17', '-fno-color-diagnostics', '-fno-caret-diagnostics', '-fsyntax-only', '--analyze', '-Xanalyzer', '-analyzer-output=text', '-isysroot', enrollment['sdkRoot'], '-I' + str(stage)) for a in flags), 'unbounded compiler flags')
        require(any(flags[i:i + 2] == ['-isysroot', enrollment['sdkRoot']] for i in range(len(flags) - 1)), 'actual enrolled SDK replay absent')
    return target, native_args


def context_record(result):
    evidence = result['details']['nativeAnalysis']['toolEvidence']
    return next(v for v in evidence if v['id'] == 'compiler')['scope']['compileDatabase']


def validate_record(root, record, live=False):
    root = Path(root)
    require(set(record) == {'schema', 'provider', 'productionQualification', 'selfProducerQualification', 'qualificationEligible', 'operationsVersion', 'claimScope', 'sourceBinding', 'toolchainEnrollment', 'toolchainEnrollmentDigest', 'toolchainEnrollmentRawBytes', 'controls', 'cases', 'assertionsPassed', 'modelCalls', 'qualificationDigest'}, 'record fields')
    require(record['schema'] == 'legion-c-family-sdk-qualification/1' and record['provider'] == PROVIDER and record['operationsVersion'] == 'c-family-operations/v1' and record['claimScope'] == CLAIM_SCOPE, 'native qualification identity')
    require(record['productionQualification'] is record['selfProducerQualification'] is False and record['qualificationEligible'] is record['assertionsPassed'] is True and type(record['modelCalls']) is int and record['modelCalls'] == 0, 'expanded/unproven native claim')
    require(record['qualificationDigest'] == digest(encoded({k: v for k, v in record.items() if k != 'qualificationDigest'})), 'qualification content digest')
    bound = record['sourceBinding']
    actual_sources = {p: digest(source_file(root, p).read_bytes()) for p in source_files(root)}
    require(bound['sources'] == actual_sources and bound['sourcesDigest'] == digest(encoded(actual_sources)) and bound['fixture'] == HARNESS, 'native SDK source binding')
    spec = next(v for v in parsed(source_file(root, 'src/registry/providers.json').read_bytes())['providers'] if v['id'] == PROVIDER)
    spec.pop('benchmark', None)
    require(bound['providerSpec'] == spec and bound['providerSpecDigest'] == digest(encoded(spec)), 'original C-family provider contract')
    clean_files = fixture(root, 'nonempty-clean')
    fixture_digests = {p: digest(t.encode()) for p, t in clean_files.items()}
    require(bound['fixtureSources'] == fixture_digests and bound['fixtureSourcesDigest'] == digest(encoded(fixture_digests)), 'full original fixture closure')
    enrollment_bytes = raw_bytes(record['toolchainEnrollmentRawBytes'])
    require(digest(enrollment_bytes) == record['toolchainEnrollmentDigest'] and parsed(enrollment_bytes) == record['toolchainEnrollment'], 'actual original enrollment bytes')
    enrollment = runpy.run_path(str(root / BOOTSTRAP))['verify_enrollment'](record['toolchainEnrollment'], live=live)
    require(record['controls'] == list(CONTROLS) and [v['control'] for v in record['cases']] == list(CONTROLS), 'all five native operation/refusal controls')
    all_ids = set()
    for original_case in record['cases']:
        case = dict(original_case, _enrollmentDigest=record['toolchainEnrollmentDigest'])
        control = case['control']
        require(case['caseId'] == 'code-c-family-' + control and case['provider'] == PROVIDER and case['productionQualification'] is case['qualificationEligible'] is False and case['assertionsPassed'] is True, 'case claim/identity')
        files = fixture(root, control)
        before = {p: digest(t.encode()) for p, t in files.items()}
        require(case['fixtureFiles'] == files and case['fixtureSources'] == before, 'frozen case bytes')
        after = dict(before)
        if control == 'source-drift':
            after['value.c'] = digest(b'/* controlled source drift */\nint c_value(void){return 10;}\n')
        require(case['fixtureAfter'] == after, 'native source writes/drift control')
        entries = case['inventory']['entries']
        require({v['path']: v['digest'] for v in entries} == before and len(entries) == len(before), 'complete inventory denominator')
        result = case['result']
        require(result['provider'] == PROVIDER, 'native result provider')
        selected = {p for p in before if p.endswith(('.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'))}
        denominator = result['details']['nativeAnalysis']['denominator']
        require(denominator == {'kind': 'c-family-files', 'expected': len(selected), 'examined': len(selected) - (1 if control == 'source-drift' else 0),
                'variants': {'c': sum(p.endswith(('.c', '.h')) for p in selected), 'cpp': sum(p.endswith(('.cc', '.cpp', '.cxx', '.hpp')) for p in selected)}}, 'original source/variant denominator')
        producer = result['details']['nativeProducer']
        require(producer['sourceFilesExpected'] == len(selected) and producer['sourceFilesRead'] == len(selected) - (1 if control == 'source-drift' else 0) and producer['contextFilesExpected'] == producer['contextFilesRead'] == 1, 'actual source/context file reads')
        require({v['path']: v['digest'] for v in producer['sourceAccounting'] if v['status'] == 'examined'} == {p: before[p] for p in selected if control != 'source-drift' or p != 'value.c'}, 'exact source accounting bytes')
        require({v['path'] for v in producer['sourceAccounting']} == selected, 'source skip denominator')
        findings = result['details']['findingEvidence']
        for key, finding in findings.items():
            require(key == digest((PROVIDER + '\0' + finding['ruleId'] + '\0' + finding['path'] + '\0' + str(finding['line'])).encode()) and finding['provider'] == PROVIDER and finding['path'] in before and type(finding['line']) is int and finding['line'] > 0, 'exact diagnostic location/identity')
            require(result['details']['findingLocations'][key] == [finding['path'] + ':' + str(finding['line'])], 'finding location linkage')
        require({f['id'] for f in result['findings']} == set(findings), 'native finding projection')
        native = result['details']['nativeProducer']['toolReceipts']
        rows = case['sdkExecutions']
        require(len(native) == len(rows), 'SDK receipt denominator')
        decisions = case['admissionDecisions']
        require(len(decisions) == (0 if control == 'rejected-admission' else len(rows)), 'actual admission decision denominator')
        raw_diagnostics, operations = [], []
        for index, row in enumerate(rows):
            request, receipt = row['request'], row['executionReceipt']
            require(request['requestId'] not in all_ids, 'reused native request ID')
            all_ids.add(request['requestId'])
            require(receipt['requestId'] == request['requestId'] and receipt['providerId'] == PROVIDER and receipt['planId'] == case['planDigest'] and receipt['taskId'] == request['taskId'], 'actual SDK request/receipt identity')
            target, args = command(request, case, enrollment)
            if control != 'rejected-admission':
                require(decisions[index] == {'request': request, 'allowed': True}, 'scoped native admission refusal')
            stdout = artifact(receipt['stdout'], row['stdout'], absolute(case['scratchRoot']), live)
            stderr = artifact(receipt['stderr'], row['stderr'], absolute(case['scratchRoot']), live)
            require(all(native[index]['sdkReceipt'].get(k) == v for k, v in receipt.items()), 'original SDK receipt overwritten/projected')
            require(native[index]['argv'] == [request['args'][3]] + args and native[index]['tool'] == request['taskId'], 'tool operation receipt linkage')
            if receipt['processTree']['started']:
                require(receipt['policy']['allowed'] is True and receipt['policy']['id'] == POLICY and receipt['policy']['version'] == 1 and receipt['sandbox']['required'] is True and receipt['processTree']['reaped'] is True and receipt['signal'] is None, 'actual authorized/reaped/sandboxed native process')
                require(receipt['executable']['digest'] == request['expectedDigest'] and receipt['executable']['version']['args'] == request['versionArgs'] and enrollment['tools'][target]['version'] in receipt['executable']['version']['output'], 'actual native version probe')
                require(native[index]['executableDigest'] == enrollment['tools'][target]['digest'], 'native target bytes')
                snapshots = native[index]['nativeInputSnapshots']
                require(snapshots['before']['files'] == before and snapshots['before']['sdk']['root'] == enrollment['sdkRoot'] and snapshots['before']['sdk']['treeDigest'] == enrollment['sdk']['digest'], 'frozen source & native SDK denominator')
                if control != 'source-drift':
                    require(snapshots['unchanged'] is True and snapshots['before'] == snapshots['after'] and snapshots['afterError'] is None, 'native source/context drift accepted')
                operations.append((request['taskId'], target, args, receipt))
                raw_diagnostics.extend((stdout + b'\n' + stderr).decode('utf-8').splitlines())
        gaps = json.dumps(result['coverage_gaps'])
        def has(rule, path):
            return any(rule in f['ruleId'] and f['path'] == path for f in findings.values())
        if control == 'nonempty-clean':
            require(result['complete'] is True and not findings and result['coverage_gaps'] == [], 'nonempty native clean failed')
            tools = result['details']['nativeAnalysis']['toolEvidence']
            require({v['id'] for v in tools} == set(TOOLS) and all(v['status'] == 'pass' for v in tools), 'all original operation evidence')
            context = context_record(result)
            database_bytes = raw_bytes(context['bytes'])
            require(context['digest'] == digest(database_bytes) and len(parsed(database_bytes)) == len(TUS), 'actual generated compile database bytes')
            require(context['sdk']['root'] == enrollment['sdkRoot'] and context['sdk']['treeDigest'] == enrollment['sdk']['digest'], 'native SDK context identity')
            for prefix in ('', 'sanitizer'):
                deps = context['dependencyCoverage' if not prefix else 'sanitizerDependencyCoverage']
                require(set(deps['covered']) == set(before) - {'CMakeLists.txt'} and len(deps['dependencyArtifacts']) == len(TUS), 'actual full C/C++/header dependency denominator')
                covered, sdk_headers = set(), {}
                stage = absolute(case['scratchRoot']) / 'tmp/c-family/source'
                for dep_path, dep in deps['dependencyArtifacts'].items():
                    require(absolute(dep_path).name.endswith('.o.d'), 'native dependency output path')
                    data = raw_bytes(dep['bytes'])
                    require(dep['digest'] == digest(data), 'actual dependency raw bytes')
                    text = data.decode('utf-8').replace('\\\n', ' ')
                    rhs = text.split(':', 1)[1]
                    require('\\' not in rhs, 'unsupported native Make dependency escape')
                    for name in rhs.split():
                        path = absolute(posixpath.normpath(name))
                        if stage in path.parents:
                            covered.add(str(path.relative_to(stage)))
                        else:
                            # Canonical SDK/resource aliases are recorded, never guessed.
                            aliases = {p: t for part in enrollment['runtimeRoots'] for p, t in part['aliases'].items()}
                            target = str(path)
                            for alias in sorted(aliases, key=len, reverse=True):
                                if target == alias or target.startswith(alias + '/'):
                                    target = aliases[alias] + target[len(alias):]
                                    break
                            require(target in enrollment['runtimeFiles'], 'unenrolled native dependency')
                            sdk_headers[target] = enrollment['runtimeFiles'][target]
                    if live:
                        require(Path(dep_path).read_bytes() == data, 'live dependency artifact drift')
                require(covered == set(deps['covered']) and sdk_headers == deps['sdkHeaders'], 'dependency/header coverage detached from actual .d bytes')
                require(deps['sdkHeaders'] and any('stdint.h' in p and PurePosixPath(enrollment['sdkRoot']) in PurePosixPath(p).parents for p in deps['sdkHeaders']) and all(enrollment['runtimeFiles'].get(p) == d for p, d in deps['sdkHeaders'].items()), 'actual consumed enrolled SDK headers')
                require(len(context['objectProducts' if not prefix else 'sanitizerObjectProducts']) == len(TUS), 'actual object build denominator')
                registered = context['registeredTests' if not prefix else 'sanitizerRegisteredTests']
                listings = [r for r in case['sdkExecutions'] if r['request']['taskId'] == ('sanitizer' if prefix else 'test') and r['request']['args'][3] == enrollment['tools']['ctest']['path'] and r['request']['args'][4] == '--show-only=json-v1']
                require(len(listings) == 1, 'actual registered test listing receipt')
                listing_bytes = raw_bytes(listings[0]['stdout']['rawBytes'])
                require(registered['digest'] == digest(listing_bytes) and registered['tests'] == parsed(listing_bytes)['tests'], 'registered test denominator detached from CTest bytes')
                require(registered['declaredAssertions'] == 4 and [t['name'] for t in registered['tests']] == ['four_assertions'] and registered['executables'], 'actual registered assertion denominator')
                tests = context['testResults' if not prefix else 'sanitizerResults']
                require(tests['testCount'] == 1 and tests['testNames'] == ['four_assertions'] and tests['failures'] == 0 and tests['digest'] == digest(raw_bytes(tests['rawBytes'])), 'actual nonempty CTest per-test results')
            for task in ('compiler', 'lint', 'analyzer'):
                replayed = set()
                for op, target, args, receipt in operations:
                    if op == task and target.startswith('clang'):
                        replayed.update(p for p in TUS if str(absolute(case['scratchRoot']) / 'tmp/c-family/source' / p) in args)
                        require(receipt['exitCode'] == 0, 'native clean static failure')
                require(replayed == set(TUS), 'original source variants not actually replayed')
            for task, build in (('compiler', 'build'), ('sanitizer', 'instrumented')):
                require(any(op == task and target == 'cmake' and args[:1] == ['--build'] and args[1].endswith('/' + build) and receipt['exitCode'] == 0 for op, target, args, receipt in operations), 'real object/link build missing')
            for task in ('test', 'sanitizer'):
                require(any(op == task and target == 'ctest' and args[0] == '--output-on-failure' and receipt['exitCode'] == 0 for op, target, args, receipt in operations), 'real assertion execution missing')
        elif control in ('compiler-warning', 'lint-warning', 'analyzer-defect', 'sanitizer-defect'):
            rule, path = {'compiler-warning': ('unused-variable', 'value.c'), 'lint-warning': ('bugprone-branch-clone', 'branch.cc'), 'analyzer-defect': ('core.NullDereference', 'branch.cc'), 'sanitizer-defect': ('ubsan:runtime-error', 'runtime.cxx')}[control]
            require(has(rule, path), 'genuine planted native diagnostic absent')
            require(any(path in line and (('runtime error:' in line) if control == 'sanitizer-defect' else rule in line) for line in raw_diagnostics), 'native diagnostic detached from original SDK bytes')
            if control == 'sanitizer-defect':
                require(result['complete'] is False and any(op == 'sanitizer' and target == 'ctest' and args[0] == '--output-on-failure' and receipt['exitCode'] == 8 for op, target, args, receipt in operations), 'instrumented defect was not actually executed')
        elif control == 'test-failure':
            require(result['complete'] is False and any(op == 'test' and target == 'ctest' and args[0] == '--output-on-failure' and receipt['exitCode'] == 8 for op, target, args, receipt in operations), 'failed assertions did not actually execute')
        elif control == 'malformed-cmake':
            require(result['complete'] is False and any(target == 'cmake' and receipt['exitCode'] == 1 for _, target, _, receipt in operations), 'actual native malformed CMake refusal missing')
        elif control in ('unenrolled-sysroot', 'orphan-source', 'orphan-header', 'source-drift', 'missing-tool'):
            expected = {'unenrolled-sysroot': 'unsupported-project-cmake-syntax', 'orphan-source': 'orphan-source-not-built', 'orphan-header': 'orphan-source-or-header', 'source-drift': 'source-closure-changed', 'missing-tool': 'clang-missing'}[control]
            require(result['complete'] is False and expected in gaps, 'required native context/refusal gap absent')
            if control in ('unenrolled-sysroot', 'missing-tool'):
                require(not rows, 'refused native context launched')
            if control == 'source-drift':
                require(rows and before != after, 'source drift not actually induced')
        else:
            wanted = 'unauthorized_effect' if control == 'rejected-admission' else 'sandbox_missing'
            require(result['complete'] is False and rows and all(r['executionReceipt']['state'] == wanted and r['executionReceipt']['processTree']['started'] is False for r in rows), 'SDK refusal started project code')
    return {'provider': PROVIDER, 'stage': 'finding', 'scope': CLAIM_SCOPE, 'productionQualification': False,
            'selfProducerQualification': False, 'qualificationDigest': record['qualificationDigest'], 'cases': len(CONTROLS),
            'matched': len(CONTROLS), 'mismatched': 0, 'validatorRejectionControls': 12}


def rejection_controls(root, record):
    mutations = [lambda r: r.update(productionQualification=True), lambda r: r.update(selfProducerQualification=True),
                 lambda r: r['controls'].pop(), lambda r: r['cases'].pop(), lambda r: r['sourceBinding']['sources'].pop(HARNESS),
                 lambda r: r['toolchainEnrollment'].update(sdkRoot='/tmp'),
                 lambda r: r['cases'][0]['sdkExecutions'].pop(), lambda r: r['cases'][0]['result'].update(complete=False),
                 lambda r: r['cases'][0]['sdkExecutions'][0]['request'].update(shell=True),
                 lambda r: r['cases'][0]['sdkExecutions'][0]['executionReceipt']['processTree'].update(started=False),
                 lambda r: r['cases'][0]['fixtureSources'].pop('common.h'),
                 lambda r: r['cases'][4]['result']['details']['findingEvidence'].clear()]
    for mutate in mutations:
        changed = copy.deepcopy(record)
        mutate(changed)
        changed['qualificationDigest'] = digest(encoded({k: v for k, v in changed.items() if k != 'qualificationDigest'}))
        try:
            validate_record(root, changed, live=False)
        except (AssertionError, KeyError, ValueError, TypeError, StopIteration):
            continue
        raise AssertionError('forged native SDK evidence accepted')
    return len(mutations)


def artifact_locator(record, original_bytes, path):
    require(parsed(original_bytes) == record, 'original retained record bytes')
    return {'provider': PROVIDER, 'path': str(path), 'sha256': digest(original_bytes), 'qualificationDigest': record['qualificationDigest']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    args = parser.parse_args()
    records = list(args.receipts.glob('c-family-sdk-*/evidence/code-c-family-native-sdk.json'))
    require(len(records) == 1, 'exactly one retained native harness run required')
    record = parsed(records[0].read_bytes())
    result = validate_record(args.root, record, live=True)
    require(rejection_controls(args.root, record) == result['validatorRejectionControls'], 'validator tamper controls')
    print('C_FAMILY_SDK_ACCURACY_SUMMARY ' + json.dumps({'records': [result], 'modelCalls': 0}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
