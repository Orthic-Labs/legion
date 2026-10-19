#!/usr/bin/env python3
"""Strict native ownership known-answer validation; authentic CI retrieval stays root-owned."""
import argparse
import copy
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = 'governance.capability-ownership'
POLICY = 'audit-native-owner-admission-v1'
FILE = 'src/duplicate.swift'
POSITIVE = b'let first = AXUIElementCreateSystemWide()\nlet second = AXUIElementCreateSystemWide()\n'
CLEAN = b'let first = 42\nlet second = 43\n'
SCOPE = 'constructed committed native Scanner known-answer controls; protected trust required'
MUTATIONS = ('malformed', 'outside-denominator', 'catalog-drift', 'verdict-drift', 'input-denominator-drift', 'source-identity-drift')
SOURCES = ['engine/Cargo.toml', 'engine/Cargo.lock', 'engine/rust-toolchain.toml',
           'engine/crates/legion-audit/tests/ownership_native_accuracy.rs',
           'engine/crates/legion-audit/examples/ownership_qualification_owner.rs',
           'scripts/ci/audit-ownership-native-accuracy.py', 'scripts/ci/validate-ownership-native-accuracy.py',
           'scripts/ci/provision-ownership-native-fixtures.py', 'src/registry/providers.json']
SOURCE_ROOTS = ['engine/crates/' + c + '/src' for c in ('legion-audit', 'legion-effects', 'legion-provider-sdk', 'legion-contracts')]


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def same(a, b, message):
    require(encoded(a) == encoded(b), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), 'duplicate JSON field')
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'non-JSON number'))


def source(root, name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and name and str(path) == name and not path.is_absolute()
            and '..' not in path.parts and '\\' not in name and ':' not in name, 'unsafe retained path')
    result = root
    for part in path.parts:
        result /= part
        require(not result.is_symlink(), 'retained symlink')
    require(result.is_file() and result.stat().st_size <= 64 * 1024 * 1024, 'missing/oversized retained file')
    return result


def source_files(root):
    result = set(SOURCES)
    result.update('engine/crates/' + c + '/Cargo.toml' for c in ('legion-audit', 'legion-effects', 'legion-provider-sdk', 'legion-contracts'))
    for name in SOURCE_ROOTS:
        require((root / name).is_dir() and not (root / name).is_symlink(), 'source root missing')
        for path in (root / name).rglob('*'):
            require(not path.is_symlink(), 'source symlink')
            relative = path.relative_to(root).as_posix()
            if path.is_file() and not re.fullmatch(r'engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json', relative):
                result.add(relative)
    return sorted(result)


def owner_document(document, identity, source_id, files, scan):
    same(document['identity'], identity, 'owner identity drift')
    require(document['protocol'] == 'legion-rightkit-ownership-native/1' and document['root'] == source_id['root'], 'owner protocol/root differs')
    inventory = document['inputInventory']
    require(inventory['complete'] is True, 'incomplete owner denominator')
    same(inventory['sourceIdentity'], source_id, 'owner source identity differs')
    same(inventory['files'], [{'path': k, 'digest': v} for k, v in sorted(files.items())], 'owner denominator differs')
    owner = document['owner']
    require('code' not in owner, 'owner refused inputs')
    inputs, trust = owner['inputs'], owner['trust']
    for field in ('contentDigest', 'catalogDigest', 'trustDigest', 'approvalsDigest', 'scannerPolicyDigest'):
        require(re.fullmatch('[0-9a-f]{64}', inputs[field] or '') is not None, 'invalid owner input digest')
    same(inputs['catalogDigest'], identity['catalogDigest'], 'embedded catalog differs')
    same(inputs['scannerPolicyDigest'], identity['scannerPolicyDigest'], 'scanner policy differs')
    same(inputs['contentDigest'], inventory['ownerContentDigest'], 'owner content binding differs')
    require(set(inputs['protectedFloors']) == {'minimumScannerVersion', 'minimumCatalogVersion', 'minimumCatalogDigest'}, 'protected floor fields differ')
    # Authenticated native execution is essential: these observations are never enrollment receipts.
    require(trust.get('enrollmentComplete') is not False, 'owner trust enrollment pending')
    same(inputs['protectedFloors'], {k: trust.get(k) or None for k in ('minimumScannerVersion', 'minimumCatalogVersion', 'minimumCatalogDigest')}, 'protected floors detached')
    registration = [r for r in trust['repositories'] if r['repositoryIdentity'] == source_id['repositoryIdentity']]
    require(len(registration) == 1 and registration[0]['roots'] == ['.'], 'fixture root not registered by protected owner')
    if not scan:
        require(owner['complete'] is True and owner['enrollmentPending'] is False, 'native probe incomplete/pending')
        return
    report, evidence, verdict = owner['report'], owner['evidence'], owner['verdict']
    require(evidence['schema'] == 1 and evidence['source'] == 'committed-git-tree'
            and evidence['trustEnrolled'] is True and evidence['floorOk'] is True
            and report['enrollmentPending'] is False, 'protected committed owner evidence absent')
    metadata = report['metadata']
    for field in ('repositoryIdentity', 'commit', 'tree'):
        same(evidence[field], source_id[field], 'committed identity differs')
        same(metadata[field], source_id[field], 'report source identity differs')
    for field in ('catalogDigest', 'catalogVersion', 'scannerVersion'):
        same(metadata[field], evidence[field], 'report/evidence version differs')
    same(evidence['catalogDigest'], identity['catalogDigest'], 'catalog evidence differs')
    same(evidence['scannerVersion'], identity['scannerVersion'], 'scanner version differs')
    require(metadata['pathBase'] == 'repository' and metadata['pathPrefix'] == '', 'owner paths not repository-relative')
    require(all(r['status'] == 'complete' for r in report['coverage'] + metadata['coverage']) and not report['problems'], 'owner coverage/problems present')
    same(evidence['registeredRoots'], ['.'], 'protected roots differ')
    same(evidence['registrationDigest'], hashlib.sha256(encoded(registration[0])).hexdigest(), 'protected registry binding differs')
    require(evidence['contentDigest'] == hashlib.sha256(encoded(metadata['contentDigests'])).hexdigest(), 'owner report content digest differs')
    content = metadata['contentDigests']
    require(len(content) == len(files) and len({r['path'] for r in content}) == len(content), 'owner content denominator incomplete')
    for row in content:
        require(row['path'] in files and row['digest'] == files[row['path']].removeprefix('sha256:'), 'owner committed file digest differs')
    expected_code = 'RK_OWNERSHIP_ADVISORY' if report['violations'] else 'RK_OWNERSHIP_CLEAN'
    problems = [f"desktop-automation (automation.api.ax-element in {FILE}) is owned by rightkit-automation [advise]" for _ in report['violations']]
    require(all(v['tier'] == 'advise' and v.get('policy') != 'banned' for v in report['violations'])
            and verdict['code'] == expected_code and verdict['admit'] is True
            and verdict['problems'] == problems, 'known-answer owner verdict differs')


def validate_case(root, row, name, identity, source_id, live, retained):
    data = CLEAN if name == 'clean' else POSITIVE
    files = {FILE: digest(data)}
    require(row['control'] == name and row['root'] == source_id['root'], 'case identity differs')
    inv, plan, result = row['inventory'], row['plan'], row['result']
    entries = [{'path': FILE, 'symbols': [], 'dependencies': [], 'packageScripts': [], 'sourceFile': True, 'digest': digest(data)}]
    same(inv['entries'], entries, 'full fixture inventory differs')
    require(inv['schemaVersion'] == 1 and inv['repositoryId'] == ID and inv['generation'] == 'filesystem:' + digest(encoded(entries)), 'inventory generation differs')
    same(inv['digest'], digest(encoded([1, ID, inv['generation'], entries])), 'inventory digest differs')
    require(plan['repositoryId'] == ID and plan['inventoryDigest'] == inv['digest'] and plan['inventoryGeneration'] == inv['generation'], 'plan inventory detached')
    require(row['planDigest'] == digest(encoded(plan)), 'plan digest differs')
    signature = 'hmac-sha256:' + hmac.new(b'constructed-ownership-sdk-fixture-key', encoded(plan), hashlib.sha256).hexdigest()
    same(row['planSignature'], signature, 'constructed frozen plan signature differs')
    require(len(plan['providers']) == 1, 'provider plan widened')
    provider = plan['providers'][0]
    registry = parsed(source(root, 'src/registry/providers.json').read_bytes())['providers']
    spec = next(p for p in registry if p['id'] == ID)
    require(provider['id'] == ID and provider['required'] is True and provider['version'] == spec['providerVersion'], 'original provider contract differs')
    configuration = provider['configuration']
    same(configuration['selector'], spec['selector'], 'provider selector differs')
    require(configuration['denominatorDigest'] == inv['digest'] and configuration['denominatorCount'] == 1, 'provider denominator narrowed')
    same(configuration['ownershipNativeOwner'], identity, 'frozen owner identity differs')
    same(configuration['ownershipSourceIdentity'], source_id, 'frozen source differs')
    require(configuration['hostDeclaration']['declared'] is True and configuration['hostDeclaration']['env'] == 'AUDIT_OWNERSHIP_SCAN_CMD'
            and configuration['hostDeclaration']['commandDigest'] == digest(encoded([identity['executable'], source_id['root']])), 'host declaration absent/detached')
    for field, key in [('family', 'family'), ('consumes', 'consumes'), ('produces', 'produces'), ('denominatorKind', 'denominatorKind'), ('runner', 'runner'), ('hostCapabilities', 'hostCapabilities'), ('execution', 'execution'), ('reasoning', 'reasoning'), ('benchmark', 'benchmark'), ('controlIds', 'controlIds'), ('scopes', 'scopes'), ('selectable', 'selectable')]:
        same(configuration[field], spec[key], 'original provider configuration differs: ' + field)
    require(provider['cleanClaim'] == spec['cleanClaim'] and provider['role'] == spec['role'] and provider['phase'] == spec['phase'], 'original provider behavior narrowed')
    require(result['provider'] == ID and result['applicable'] is True and result['required'] is True, 'result contract differs')
    coverage, details = result['coverage'], result['details']
    require(coverage['expected'] == 1 and coverage['denominator_digest'] == inv['digest'], 'result denominator differs')
    same(details['frozenInputFiles'], files, 'snapshot bytes differ')
    same(details['nativeOwnerIdentity'], identity, 'result owner identity differs')
    require(details['hostDeclared'] is True, 'result host declaration absent')
    receipts, documents = details['executionReceipts'], details['ownerDocuments']
    success = name in ('positive', 'clean')
    require(result['complete'] is success and result['status'] == ('complete' if success else 'partial')
            and coverage['examined'] == (1 if success else 0), 'coverage completion differs')
    if success:
        same(coverage['gaps'], [], 'success coverage gaps')
        same(result['coverage_gaps'], [], 'success coverage gaps')
        same(result['degradation'], [], 'success degradation')
        require(len(receipts) == len(documents) == 3, 'three genuine owner calls required')
    elif name == 'denial':
        require(len(receipts) == 1 and not documents and not result['findings'], 'default denial advanced owner execution')
        r = receipts[0]
        require(r['state'] == 'unauthorized_effect' and r['complete'] is False and r['policy']['allowed'] is False
                and r['processTree']['started'] is False and r['executable'] is None and r['stdout'] is None
                and r['parser']['attempted'] is False, 'default denial resolved/spawned/parsed owner')
        same(coverage['gaps'], ['ownership-sdk-incomplete:unauthorized_effect'], 'denial reason differs')
    else:
        require(not result['findings'] and any(g.startswith('ownership-denominator-drift:') for g in coverage['gaps']), 'source drift not fail-closed')
    for index, receipt in enumerate(receipts):
        mode = ('inputs-before', 'scan', 'inputs-after')[index]
        request_id = 'legion-audit/' + hashlib.sha256(f"{row['planDigest']}:{inv['digest']}:{mode}".encode()).hexdigest()
        require(receipt['requestId'] == request_id and receipt['providerId'] == ID and receipt['planId'] == row['planDigest']
                and receipt['policyId'] == POLICY and receipt['taskId'] == 'ownership-' + mode and receipt['cwd'] == source_id['root'], 'native request identity differs')
        if name == 'denial':
            continue
        require(receipt['state'] == 'completed' and receipt['complete'] is True and receipt['exitCode'] == 0
                and receipt['signal'] is None and receipt['processTree']['started'] is True
                and receipt['processTree']['reaped'] is True and receipt['policy']['allowed'] is True, 'native owner execution incomplete')
        require(receipt['policy']['id'] == POLICY and receipt['policy']['version'] == 1
                and receipt['policy']['digest'] == digest(encoded({'scope': 'constructed ownership SDK fixture', 'root': source_id['root'], 'owner': identity, 'plan': row['planDigest']})), 'constructed admission policy differs')
        require(receipt['executable']['canonicalPath'] == identity['executable']
                and receipt['executable']['digest'] == identity['executableDigest'], 'native executable not pinned')
        args = [source_id['root']] + ([] if mode == 'scan' else ['--inputs'])
        same(receipt['command']['args'], args, 'owner command args differ')
        require(receipt['command']['executable'] == identity['executable'] and receipt['command']['environmentNames'] == []
                and receipt['environmentNames'] == [], 'owner command/environment differs')
        if live:
            for stream in ('stdout', 'stderr'):
                item = receipt[stream]
                raw = source(retained / 'controls' / name / 'artifacts', item['path']).read_bytes()
                require(item['immutable'] is True and item['bytes'] == len(raw) and item['digest'] == digest(raw), 'native output artifact drift')
                if stream == 'stdout' and index < len(documents):
                    same(parsed(raw), documents[index], 'native stdout detached from owner document')
    if not success:
        same(details['findingEvidence'], {}, 'partial result invented findings')
        same(details['findingLocations'], {}, 'partial result invented locations')
        same(details['findingMessages'], {}, 'partial result invented messages')
        same(result['coverage_gaps'], coverage['gaps'], 'partial gaps detached')
        same(result['degradation'], coverage['gaps'], 'partial degradation detached')
        return
    for i, doc in enumerate(documents):
        owner_document(doc, identity, source_id, files, i == 1)
    for doc in documents[1:]:
        for field in ('inputs', 'trust'):
            same(doc['owner'][field], documents[0]['owner'][field], 'before/scan/after protected input drift')
        same(doc['inputInventory'], documents[0]['inputInventory'], 'before/after denominator drift')
    violations = documents[1]['owner']['report']['violations']
    expected_lines = [1, 2] if name == 'positive' else []
    require([v['line'] for v in violations] == expected_lines, 'known-answer lines/count differ')
    expected_findings, evidence, locations, messages = [], {}, {}, {}
    for v in violations:
        require(v['file'] == FILE and v['fingerprint'] == 'automation.api.ax-element'
                and v['capability'] == 'desktop-automation' and v['package'] == 'rightkit-automation', 'known-answer ownership differs')
        line = v['line']
        fid = digest(f'{ID}:automation.api.ax-element\0{FILE}\0{line}'.encode())
        message = 'desktop-automation duplicates RightKit owner rightkit-automation'
        expected_findings.append({'id': fid, 'severity': 'warning'})
        evidence[fid] = {'path': FILE, 'line': line, 'lineKnown': True, 'rule': v['fingerprint'], 'message': message,
                         'capability': v['capability'], 'owner': v['package'], 'ownerFinding': v,
                         'ownerEvidence': documents[1]['owner']['evidence'], 'ownerIdentity': identity}
        locations[fid], messages[fid] = [f'{FILE}:{line}'], message
    same(result['findings'], expected_findings, 'native known-answer findings differ')
    same(details['findingEvidence'], evidence, 'finding evidence detached')
    same(details['findingLocations'], locations, 'finding locations detached')
    same(details['findingMessages'], messages, 'finding messages detached')


def validate_record(root, record, live=False, retained=None):
    require(set(record) == {'schema', 'provider', 'stage', 'modelCalls', 'productionQualification', 'qualificationEligible',
                            'wholeProviderQualified', 'auditCleanClaim', 'scope', 'fixtureIdentityManifest', 'nativeOwner', 'cases', 'controls', 'qualificationDigest'}, 'record fields differ')
    require(record['schema'] == 'legion-ownership-native-sdk-controls/2' and record['provider'] == ID
            and record['qualificationEligible'] is True and record['productionQualification'] is False
            and record['wholeProviderQualified'] is False and record['auditCleanClaim'] is False
            and record['scope'] == SCOPE and record['stage'] == 'finding'
            and type(record['modelCalls']) is int and record['modelCalls'] == 0, 'qualification scope differs')
    same(record['qualificationDigest'], digest(encoded({k: v for k, v in record.items() if k != 'qualificationDigest'})), 'record digest differs')
    require(set(record['fixtureIdentityManifest']) == {'path', 'digest', 'document'}
            and re.fullmatch(r'sha256:[0-9a-f]{64}', record['fixtureIdentityManifest']['digest']), 'manifest binding differs')
    require(set(record['cases']) == {'positive', 'clean'} and set(record['controls']) == set(MUTATIONS) | {'drift', 'denial'}, 'known-answer controls missing/extra')
    identity = record['nativeOwner']
    require(identity['protocol'] == 'legion-rightkit-ownership-native/1' and identity['ownerCrate'] == 'rightkit-ownership'
            and identity['ownerVersion'] == '0.3.1' and re.fullmatch(r'sha256:[0-9a-f]{64}', identity['executableDigest'])
            and Path(identity['executable']).is_absolute(), 'native published owner identity differs')
    manifest = record['fixtureIdentityManifest']
    require(set(manifest['document']) == {'positive', 'clean'}, 'fixture manifest fields differ')
    if live:
        same(digest(Path(manifest['path']).read_bytes()), manifest['digest'], 'original fixture identity bytes drift')
        same(parsed(Path(manifest['path']).read_bytes()), manifest['document'], 'fixture manifest drift')
        same(digest(Path(identity['executable']).read_bytes()), identity['executableDigest'], 'owner binary drift')
    roots = []
    for name in ('positive', 'clean'):
        sid = manifest['document'][name]
        require(set(sid) == {'root', 'repositoryIdentity', 'commit', 'tree'} and Path(sid['root']).is_absolute()
                and sid['repositoryIdentity'] == 'https://github.com/orthic-labs/legion'
                and all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', sid[k]) for k in ('commit', 'tree')), 'constructed committed source identity differs')
        roots.append(sid['root'])
        validate_case(root, record['cases'][name], name, identity, sid, live, retained)
    require(roots[0] != roots[1], 'positive/clean source roots aliased')
    for name in ('drift', 'denial'):
        validate_case(root, record['controls'][name], name, identity, manifest['document']['positive'], live, retained)
    genuine = record['cases']['positive']['result']['details']['ownerDocuments'][1]
    for name in MUTATIONS:
        control = record['controls'][name]
        expected = copy.deepcopy(genuine)
        if name == 'malformed': expected['owner']['report']['violations'] = 'malformed'
        elif name == 'outside-denominator': expected['owner']['report']['violations'][0]['file'] = 'outside.swift'
        elif name == 'catalog-drift': expected['owner']['inputs']['catalogDigest'] = '0' * 64
        elif name == 'verdict-drift': expected['owner']['verdict']['admit'] = not expected['owner']['verdict']['admit']
        elif name == 'input-denominator-drift': expected['inputInventory']['files'].pop()
        elif name == 'source-identity-drift': expected['inputInventory']['sourceIdentity']['commit'] = '0' * 40
        same(control['mutatedDocument'], expected, 'consumer control not exact mutation of genuine owner output')
        require(control['observed'] == 'rejected' and control['scope'] == 'consumer-boundary mutation of genuine owner envelope'
                and control['error'] == {'malformed': 'ownership-verdict-mismatch', 'outside-denominator': 'ownership-verdict-mismatch',
                'catalog-drift': 'ownership-owner-policy-mismatch', 'verdict-drift': 'ownership-verdict-mismatch',
                'input-denominator-drift': 'ownership-input-denominator-mismatch',
                'source-identity-drift': 'ownership-evidence-source-identity:commit'}[name], 'consumer rejection absent/different')
    return {'provider': ID, 'stage': 'finding', 'qualificationDigest': record['qualificationDigest'], 'scope': SCOPE,
            'productionQualification': False, 'wholeProviderQualified': False, 'cases': 10, 'matched': 10, 'mismatched': 0}


def rejection_controls(root, record):
    edits = [lambda r: r.update(productionQualification=True), lambda r: r.update(auditCleanClaim=True),
             lambda r: r['controls'].pop('denial'), lambda r: r['cases']['positive']['result']['findings'].pop(),
             lambda r: r['cases']['clean']['result'].update(complete=False),
             lambda r: r['cases']['positive']['result']['details']['ownerDocuments'][1]['owner']['evidence'].update(trustEnrolled=False),
             lambda r: r['cases']['positive']['inventory']['entries'].clear(),
             lambda r: r['cases']['positive']['result']['details']['findingLocations'].clear(),
             lambda r: r['controls']['outside-denominator'].update(mutatedDocument={}),
             lambda r: r['cases']['positive'].update(planSignature='hmac-sha256:' + '0' * 64)]
    for edit in edits:
        altered = copy.deepcopy(record)
        edit(altered)
        altered['qualificationDigest'] = digest(encoded({k: v for k, v in altered.items() if k != 'qualificationDigest'}))
        try:
            validate_record(root, altered)
        except (AssertionError, KeyError, ValueError, TypeError, IndexError):
            continue
        raise AssertionError('ownership validator accepted altered qualification')
    return len(edits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    args = parser.parse_args()
    record = parsed(source(args.receipts / 'controls', ID + '.json').read_bytes())
    result = validate_record(args.root, record, live=True, retained=args.receipts)
    require(rejection_controls(args.root, record) == 10, 'validator controls incomplete')
    print('OWNERSHIP_NATIVE_PROVIDER_ACCURACY_SUMMARY ' + json.dumps({'records': [result], 'modelCalls': 0}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
