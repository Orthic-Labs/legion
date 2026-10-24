#!/usr/bin/env python3
"""Strict, source-bound replay of native Audit report protocol known answers."""
import argparse
import copy
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = 'compatibility.core'
SCOPE = 'native Audit report v1/v2 v1-core preservation; excludes v2-only fields/extensions'
SCHEMA = 'legion-compatibility-report-accuracy/1'
README = b'# Usage\n\nSee `src/existing.rs` & `src/missing.rs`.\n'
SOURCE = b'pub const VALUE: u32 = 3;\n'
CRATES = ('legion-audit', 'legion-contracts', 'legion-provider-sdk', 'legion-effects', 'legion-rules', 'legion-report')
FILES = ['engine/Cargo.toml', 'engine/Cargo.lock', 'engine/rust-toolchain.toml', 'src/registry/providers.json',
         'engine/crates/legion-audit/tests/compatibility_report_accuracy.rs',
         'scripts/ci/audit-compatibility-report-accuracy.py', 'scripts/ci/validate-compatibility-report-accuracy.py',
         'scripts/ci/tests/test_audit_compatibility_report_accuracy.py',
         'scripts/ci/audit-qualification-records.py', 'scripts/ci/tests/test_audit_qualification_records.py',
         'qualification/provider-accuracy/schema.json', 'scripts/ci/right-git-ci.sh', '.github/workflows/ci.yml']


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def encoded(row):
    return json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def objective_graph_bound(plan):
    """Independently recompute the schema-2 plan objective-graph binding (legion-audit dag.rs)."""
    providers = plan["providers"]
    ids = {provider["id"] for provider in providers}
    require(len(ids) == len(providers), "duplicate provider id")
    artifacts = lambda provider, key: provider["configuration"][key] if isinstance(provider["configuration"].get(key), list) else []
    producers = {}
    for provider in providers:
        for kind in artifacts(provider, "produces"):
            producers.setdefault(kind, set()).add(provider["id"])
    edges = {}
    for provider in providers:
        deps = {}
        for dependency in provider["dependencies"]:
            require(dependency in ids, "objective dependency missing")
            deps[dependency] = "declared"
        for kind in artifacts(provider, "consumes"):
            for source in sorted(producers.get(kind, set()) - {provider["id"]}):
                deps.setdefault(source, {"artifact": kind})
        edges[provider["id"]] = deps
    order, done = [], set()
    while len(order) < len(edges):
        ready = [key for key in sorted(edges) if key not in done and set(edges[key]) <= done]
        require(ready, "objective dependency cycle")
        order.append(ready[0]); done.add(ready[0])
    by_id = {provider["id"]: provider for provider in providers}
    proof = lambda p: {"providerVersion": p["version"], "denominatorDigest": p["configuration"].get("denominatorDigest"),
                       "denominatorCount": p["configuration"].get("denominatorCount"), "cleanClaim": p["cleanClaim"], "required": p["required"]}
    objective = {}
    for key in order:
        seed = {"repositoryId": plan["repositoryId"], "inventoryDigest": plan["inventoryDigest"], "providerId": key,
                "stage": by_id[key]["phase"], "dependencies": sorted(edges[key]), "proofObligations": proof(by_id[key])}
        objective[key] = "obj_" + digest(encoded(seed)).removeprefix("sha256:")[:16]
    objectives = [{"format": "audit-objective/v1", "objectiveId": objective[key], "providerId": key, "stage": by_id[key]["phase"],
                   "dependencies": sorted(objective[dep] for dep in edges[key]), "consumes": artifacts(by_id[key], "consumes"),
                   "produces": artifacts(by_id[key], "produces"), "proofObligations": proof(by_id[key])} for key in order]
    edge_list = sorted(({"fromObjective": objective[dep], "toObjective": objective[key], "kind": kind}
                        for key in order for dep, kind in sorted(edges[key].items())),
                       key=lambda edge: (edge["fromObjective"], edge["toObjective"]))
    graph = {"objectives": objectives, "edges": edge_list}
    return {"schemaVersion": 1, "digest": digest(encoded(graph)), "objectiveCount": len(objectives)}


def same(a, b, message):
    require(encoded(a) == encoded(b), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), 'duplicate JSON field')
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'non-JSON number'))


def source(root, name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name, 'unsafe source path')
    path = PurePosixPath(name)
    require(str(path) == name and not path.is_absolute() and all(x not in ('.', '..') for x in path.parts), 'unsafe source path')
    result = root
    for part in path.parts:
        result /= part
        require(not result.is_symlink(), 'source symlink')
    require(result.is_file() and result.stat().st_size <= 64 * 1024 * 1024, 'source missing/oversized')
    return result


def source_digest(root, name):
    raw = source(root, name).read_bytes()
    if name == 'src/registry/providers.json':
        value = parsed(raw)
        for provider in value['providers']:
            provider.pop('benchmark', None)
        raw = encoded(value)
    return digest(raw)


def source_manifest(root):
    names = set(FILES)
    for crate in CRATES:
        names.add(f'engine/crates/{crate}/Cargo.toml')
        directory = root / f'engine/crates/{crate}/src'
        require(directory.is_dir() and not directory.is_symlink(), 'source root missing')
        for path in directory.rglob('*'):
            require(not path.is_symlink(), 'source symlink')
            relative = path.relative_to(root).as_posix()
            if path.is_file() and not re.fullmatch(r'engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json', relative):
                names.add(relative)
    return {name: source_digest(root, name) for name in sorted(names)}


def fixed_inventory(extra=False):
    entries = [{'path': name, 'symbols': [], 'dependencies': [], 'packageScripts': [],
                'sourceFile': name.endswith('.rs'), 'digest': digest(data)}
               for name, data in [('README.md', README), ('src/existing.rs', SOURCE)] +
               ([('src/additional.rs', b'pub const EXTRA: u32 = 4;\n')] if extra else [])]
    entries.sort(key=lambda item: item['path'])
    generation = 'filesystem:' + digest(encoded(entries))
    identity = 'compatibility-report-three-files' if extra else 'compatibility-report-controls'
    return {'schemaVersion': 1, 'repositoryId': identity, 'generation': generation,
            'entries': entries, 'digest': digest(encoded([1, identity, generation, entries]))}


def core(report):
    findings = []
    for f in report['findings']:
        item = {key: f[key] for key in ('id', 'severity', 'title', 'message', 'provider', 'locations', 'evidence')}
        item = copy.deepcopy(item)
        item['evidence'].pop('legionV2', None)
        findings.append(item)
    return {'reportId': report['report_id'], 'status': report['status'],
            'findings': sorted(findings, key=lambda f: f['id']), 'gaps': report['gaps'],
            'claims': report['claims'], 'targets': report['targets']}


def expected_finding():
    evidence = {'claim': 'README.md cites src/missing.rs', 'authority': 'README.md', 'status': 'contradicted',
                'evidence': [], 'implementationInferred': False, 'id': 'docs.contract:e73da6403495', 'severity': 'warning',
                'kind': 'missing-cited-path', 'path': 'README.md', 'line': 3, 'cited': 'src/missing.rs'}
    return {'id': 'docs.contract:e73da6403495', 'severity': 'warning', 'title': 'Audit finding',
            'message': 'Provider reported a finding', 'provider': 'docs.contract', 'locations': ['README.md'], 'evidence': evidence}


def observation(row, inv, plan, root):
    require(set(row) == {'schema', 'contract', 'claimScope', 'protocolComplete', 'certificationClaim', 'implementation',
                         'planDigest', 'inventoryDigest', 'denominatorDigest', 'denominatorCount', 'files',
                         'execution', 'reportV1', 'reportV2', 'cases', 'controls', 'protocolDenominator', 'preservationScope'}, 'observation fields differ')
    require(row['schema'] == 'legion-native-report-compatibility-observation/1' and row['contract'] == 'legion-audit-report-v1-v2/1'
            and row['claimScope'] == 'native-report-v1-v2-v1-core-preservation' and row['protocolComplete'] is True
            and row['certificationClaim'] is False, 'observation scope changed')
    require(row['planDigest'] == digest(encoded(plan)) and row['inventoryDigest'] == inv['digest']
            and row['denominatorDigest'] == inv['digest'] and row['denominatorCount'] == len(inv['entries']), 'observation detached')
    same(row['protocolDenominator'], {'kind': 'report-schema-contracts', 'expected': 2, 'examined': 2}, 'schema denominator differs')
    require(row['preservationScope'] == 'v1-core-only; excludes v2-only fields & extensions', 'preservation scope expanded')
    same(row['files'], {entry['path']: entry['digest'] for entry in inv['entries']}, 'source denominator changed')
    implementation = row['implementation']
    require(set(implementation) == {'contract', 'producer', 'consumer', 'platform', 'sources'}, 'implementation identity fields differ')
    paths = ['engine/crates/legion-audit/src/report.rs', 'engine/crates/legion-contracts/src/report.rs',
             'engine/crates/legion-report/src/lib.rs', 'engine/crates/legion-report/src/json.rs']
    same(implementation['sources'], {path: digest(source(root, path).read_bytes()) for path in paths}, 'compiled producer/consumer source drift')
    version = re.search(r'^version\s*=\s*"([^"]+)"', source(root, 'engine/Cargo.toml').read_text(), re.MULTILINE).group(1)
    same(implementation['producer'], {'crate': 'legion-audit', 'version': version, 'schemas': [1, 2]}, 'producer version drift')
    same(implementation['consumer'], {'crate': 'legion-contracts+legion-report', 'version': version, 'schemas': [1, 2]}, 'consumer version drift')
    require(implementation['contract'] == row['contract'] and set(implementation['platform']) == {'os', 'arch'}
            and implementation['platform']['os'] in ('macos', 'windows', 'linux')
            and implementation['platform']['arch'] in ('aarch64', 'x86_64'), 'native platform/contract absent')
    execution = row['execution']
    require(execution['planDigest'] == row['planDigest'] and execution['inventoryDigest'] == inv['digest']
            and execution['generation'] == inv['generation'] and execution['plannedProviders'] == [p['id'] for p in plan['providers']]
            and len(execution['results']) == 2 and execution['pendingHost'] == [], 'real execution detached')
    results = {r['provider']: r for r in execution['results']}
    require(set(results) == {ID, 'docs.contract'} and not any(r['skipped'] for r in results.values()), 'execution scope changed')
    docs = results['docs.contract']['result']
    require(len(docs['findings']) == 1 and docs['findings'][0]['id'] == 'docs.contract:e73da6403495', 'fixed planted source finding missing')
    report1, report2 = row['reportV1'], row['reportV2']
    require(report1['schema_version'] == 1 and report2['schema_version'] == 2 and report1['status'] == report2['status'] == 'incomplete'
            and report1['gaps'] and len(report1['findings']) == len(report2['findings']) == 1, 'fixed report known answer changed')
    require(report1['findings'][0]['id'] == 'docs.contract:e73da6403495'
            and report1['findings'][0]['locations'] == ['README.md'], 'report finding/location lost')
    same(core(report1)['findings'], [expected_finding()], 'fixed finding/evidence known answer changed')
    same(core(report1), core(report2), 'lift lost report semantics')
    require(set(row['cases']) == {'schema-1', 'schema-2'}, 'supported matrix incomplete')
    for schema in [1, 2]:
        case = row['cases'][f'schema-{schema}']
        require(set(case) == {'schema', 'producedBytes', 'producedDigest', 'renderedBytes', 'renderedDigest', 'expected', 'observed', 'status'}, 'case fields differ')
        require(type(case['schema']) is int and case['schema'] == schema and case['status'] == 'compatible', 'case schema changed')
        produced, rendered = parsed(case['producedBytes']), parsed(case['renderedBytes'])
        require(case['producedDigest'] == digest(case['producedBytes'].encode())
                and case['renderedDigest'] == digest(case['renderedBytes'].encode()), 'output bytes tampered')
        same(produced, report1 if schema == 1 else report2, 'actual producer output differs')
        require(rendered['schema_version'] == schema, 'consumer rendered unsupported schema')
        same(core(rendered), core(produced), 'consumer output semantics drift')
        same(case['expected'], core(produced), 'producer expectation drift')
        same(case['observed'], core(rendered), 'consumer observation drift')
    require(set(row['controls']) == {'unsupported-schema', 'missing-schema', 'malformed-findings'}, 'negative matrix incomplete')
    for name in row['controls']:
        control = row['controls'][name]
        require(set(control) == {'input', 'status', 'error'} and control['status'] == 'incompatible'
                and isinstance(control['error'], str) and control['error'], 'consumer rejection missing')
        expected = copy.deepcopy(report1)
        if name == 'unsupported-schema':
            expected['schema_version'] = 3
        elif name == 'missing-schema':
            del expected['schema_version']
        else:
            expected['findings'] = 'malformed'
        same(control['input'], expected, 'rejected input was not derived from actual producer')


def validate(root, row):
    require(set(row) == {'schema', 'provider', 'stage', 'scope', 'productionQualification', 'wholeProviderQualified', 'auditCleanClaim',
                         'qualificationEligible', 'modelCalls', 'sourceManifest', 'inventory', 'plan', 'planDigest', 'planSignature',
                         'fallback', 'result', 'observation', 'controls', 'nonTwoFiles', 'qualificationDigest'}, 'record fields differ')
    require(row['schema'] == SCHEMA and row['provider'] == ID and row['stage'] == 'fact-output' and row['scope'] == SCOPE
            and row['qualificationEligible'] is True and type(row['modelCalls']) is int and row['modelCalls'] == 0, 'record scope differs')
    for field in ('productionQualification', 'wholeProviderQualified', 'auditCleanClaim'):
        require(row[field] is False, 'runtime qualification claim prohibited')
    require(row['qualificationDigest'] == digest(encoded({k: v for k, v in row.items() if k != 'qualificationDigest'})), 'record digest detached')
    same(row['sourceManifest'], source_manifest(root), 'current source drift')
    inv, plan = row['inventory'], row['plan']
    same(inv, fixed_inventory(), 'original selected inventory changed')
    require(row['planDigest'] == digest(encoded(plan)) and row['planSignature'] == 'hmac-sha256:' + hmac.new(b'native-report-compatibility-controls', encoded(plan), hashlib.sha256).hexdigest(), 'constructed plan binding differs')
    require(plan['inventoryDigest'] == inv['digest'] and plan['inventoryGeneration'] == inv['generation']
            and plan['repositoryId'] == inv['repositoryId'] and len(plan['providers']) == 2, 'plan scope changed')
    registry = parsed(source(root, 'src/registry/providers.json').read_bytes())['providers']
    require({p['id'] for p in plan['providers']} == {ID, 'docs.contract'}, 'frozen provider inventory changed')
    for provider in plan['providers']:
        spec = next(p for p in registry if p['id'] == provider['id'])
        require(provider['version'] == spec['providerVersion'] and provider['kind'] == 'rust-algorithm'
                and provider['cleanClaim'] == spec['cleanClaim'] and 'input' not in provider['configuration'], 'provider truth changed')
        config = provider['configuration']
        require(config['denominatorDigest'] == inv['digest'] and config['denominatorCount'] == 2, 'provider denominator changed')
        for key in ('selector', 'runner', 'execution', 'reasoning', 'consumes', 'produces', 'controlIds', 'scopes'):
            same(config[key], spec[key], 'provider configuration drift')
    observation(row['observation'], inv, plan, root)
    fallback = row['fallback']
    require(fallback['complete'] is False and fallback['details']['availability']['state'] == 'unavailable', 'source fallback promoted')
    result = row['result']
    require(result['provider'] == ID and result['complete'] is False and result['status'] == 'partial'
            and result['coverage_gaps'] == ['runtime-evidence-trust-unavailable'], 'runtime trust boundary lost')
    same(result['coverage'], {'denominator_digest': inv['digest'], 'expected': 2, 'examined': 2,
                              'gaps': ['runtime-evidence-trust-unavailable']}, 'result denominator narrowed')
    same(result['details']['nativeAnalysis']['nativeReportCompatibility'], row['observation'], 'native registry did not consume observation')
    same(result['details']['nativeAnalysis']['denominator'], {'kind': 'source-files', 'expected': 2, 'examined': 2}, 'source denominator changed')
    same(result['details']['nativeAnalysis']['protocolDenominator'], {'kind': 'report-schema-contracts', 'expected': 2, 'examined': 2}, 'protocol denominator changed')
    extra = row['nonTwoFiles']
    require(set(extra) == {'inventory', 'plan', 'observation', 'result'}, 'non-two-file control fields differ')
    same(extra['inventory'], fixed_inventory(extra=True), 'non-two-file inventory changed')
    inv3, plan3, result3 = extra['inventory'], extra['plan'], extra['result']
    require(plan3['inventoryDigest'] == inv3['digest'] and plan3['inventoryGeneration'] == inv3['generation']
            and plan3['repositoryId'] == inv3['repositoryId'], 'non-two-file plan detached')
    expected3 = copy.deepcopy(plan)
    expected3.update(inventoryDigest=inv3['digest'], inventoryGeneration=inv3['generation'], repositoryId=inv3['repositoryId'])
    for provider3 in expected3['providers']:
        provider3['configuration'].update(denominatorDigest=inv3['digest'], denominatorCount=3)
    if expected3['schemaVersion'] == 2:
        same(plan['bounds'].get('objectiveGraph'), objective_graph_bound(plan), 'frozen objective graph changed')
        expected3['bounds']['objectiveGraph'] = objective_graph_bound(expected3)
    same(plan3, expected3, 'non-two-file provider contract changed')
    observation(extra['observation'], inv3, plan3, root)
    same(result3['coverage'], {'denominator_digest': inv3['digest'], 'expected': 3, 'examined': 3,
                              'gaps': ['runtime-evidence-trust-unavailable']}, 'three-file coverage lost')
    require(result3['complete'] is False and result3['coverage_gaps'] == ['runtime-evidence-trust-unavailable'], 'three-file result promoted')
    same(result3['details']['nativeAnalysis']['nativeReportCompatibility'], extra['observation'], 'three-file native observation detached')
    same(result3['details']['nativeAnalysis']['denominator'], {'kind': 'source-files', 'expected': 3, 'examined': 3}, 'three-file source denominator changed')
    same(result3['details']['nativeAnalysis']['protocolDenominator'], {'kind': 'report-schema-contracts', 'expected': 2, 'examined': 2}, 'three-file protocol denominator conflated')
    controls = row['controls']
    require(set(controls) == {'copiedJson', 'sourceDrift', 'providerBinding', 'tamperedObservation'}, 'boundary matrix incomplete')
    require(controls['copiedJson']['complete'] is False
            and 'nativeReportCompatibility' not in controls['copiedJson']['details']['nativeAnalysis'], 'JSON minted native capability')
    for name in ('sourceDrift', 'providerBinding'):
        require(controls[name]['complete'] is False and 'report-protocol-observation-binding-invalid' in controls[name]['coverage_gaps']
                and 'nativeReportCompatibility' not in controls[name]['details']['nativeAnalysis'], 'bound observation followed drift')
    try:
        observation(controls['tamperedObservation'], inv, plan, root)
    except (AssertionError, KeyError, TypeError, ValueError):
        pass
    else:
        raise AssertionError('tampered output accepted')
    return {'provider': ID, 'stage': 'fact-output', 'scope': SCOPE, 'productionQualification': False,
            'wholeProviderQualified': False, 'qualificationEligible': True, 'supportedCases': 2, 'negativeCases': 3,
            'boundaryControls': 4, 'nonTwoFileControls': 1, 'qualificationDigest': row['qualificationDigest']}


def rejection_controls(root, row):
    changes = [('schema-count', lambda r: r['nonTwoFiles']['observation']['protocolDenominator'].update(expected=3, examined=3)),
               ('promotion', lambda r: r.update(productionQualification=True)),
               ('source', lambda r: r['sourceManifest'].update({'engine/Cargo.toml': 'sha256:' + '0' * 64})),
               ('missing-case', lambda r: r['observation']['cases'].pop('schema-2')),
               ('finding-severity', lambda r: r['observation']['reportV1']['findings'][0].update(severity='info')),
               ('tamper', lambda r: r['observation']['cases']['schema-1'].update(renderedBytes='{}')),
               ('denominator', lambda r: r['inventory'].update(entries=[])),
               ('copied-json', lambda r: r['controls']['copiedJson']['details']['nativeAnalysis'].update(nativeReportCompatibility=r['observation']))]
    for name, change in changes:
        changed = copy.deepcopy(row)
        change(changed)
        changed['qualificationDigest'] = digest(encoded({k: v for k, v in changed.items() if k != 'qualificationDigest'}))
        try:
            validate(root, changed)
        except (AssertionError, KeyError, TypeError, ValueError, StopIteration):
            continue
        raise AssertionError(f'replay accepted {name}')
    return len(changes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--record', required=True, type=Path)
    args = parser.parse_args()
    row = parsed(args.record.read_bytes())
    summary = validate(args.root.resolve(), row)
    summary['rejectionControls'] = rejection_controls(args.root.resolve(), row)
    print('COMPATIBILITY_REPORT_PROVIDER_ACCURACY_SUMMARY ' + encoded({'records': [summary], 'modelCalls': 0}).decode())


if __name__ == '__main__':
    main()
