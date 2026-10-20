#!/usr/bin/env python3
"""Strict replay of original Rust SDK observations; CI authentication stays separate."""
import argparse
import copy
import io
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import runpy
import tarfile

COMMON = 'scripts/ci/audit-code-sdk-accuracy.py'
REPLAY = 'scripts/ci/audit-pip-audit-provider-accuracy.py'
HARNESS = 'engine/crates/legion-audit/tests/real_rust_code_accuracy.rs'
FIXTURES = 'scripts/ci/fixtures/audit-rust-code-sdk'
BOOTSTRAP = 'scripts/ci/provision-rust-code-fixtures.py'
PROVIDER = 'code.rust'
POLICY = 'legion-real-rust-code-fixture-v1'
CONTROLS = ('positive','nonempty-clean','dependency-positive','dependency-nonempty-clean','unsafe-assessment','features','targets','compiler-failure','test-failure','malformed-lock','missing-database','tampered-database','missing-tool','tampered-tool','changed-source','audit-config','rejected-admission','absent-sandbox','budget-exhausted')
TASKS = ('metadata','check','lint','test','dependency')
LIMITATIONS = ['dependency subset cannot establish full/current RustSec security clean','unsafe source soundness unassessed','feature/target variants unexercised','multiple manifests & project audit configuration remain explicit gaps']
_shared = runpy.run_path(str(Path(__file__).resolve().parents[2] / COMMON))
for _name in ('require','keys','encoded','digest','is_digest','same','parsed','source_file','absolute','artifact','required_contract'):
    globals()[_name] = _shared[_name]
RECEIPT_FIELDS = _shared['RECEIPT_FIELDS']
SOURCE_ROOTS = ['engine/crates/'+c+'/src' for c in ('legion-audit','legion-effects','legion-provider-sdk','legion-contracts','legion-rules')] + ['src/registry/rules','src/registry/controls',FIXTURES,'engine/crates/legion-audit/tests/fixtures/cargo-audit']
SOURCE_FILES = ['engine/Cargo.toml','engine/Cargo.lock','engine/rust-toolchain.toml',HARNESS,BOOTSTRAP,'scripts/ci/provision-python-qualification-tools.py',REPLAY] + ['engine/crates/'+c+'/Cargo.toml' for c in ('legion-audit','legion-effects','legion-provider-sdk','legion-contracts','legion-rules')]

def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    paths = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        p = Path(root)/relative
        require(p.is_dir() and not p.is_symlink(), 'missing source root')
        for item in p.rglob('*'):
            require(not item.is_symlink(), 'source symlink')
            if item.is_file():
                if generated_session_provenance(item.relative_to(root).as_posix()):
                    continue
                paths.add(item.relative_to(root).as_posix())
    return sorted(paths)

def safe_relative(value):
    require(isinstance(value,str) and value and not PurePosixPath(value).is_absolute() and str(PurePosixPath(value)) == value and all(p not in ('.','..') for p in PurePosixPath(value).parts), 'unsafe retained relative path')
    return value

def retained_bytes(retained, relative, reference=None):
    safe_relative(relative)
    root = Path(retained)
    p = root
    for part in PurePosixPath(relative).parts:
        p = p/part
        require(not p.is_symlink(), 'retained alias refused')
    require(p.is_file(), 'original retained artifact missing: '+relative)
    raw = p.read_bytes()
    if reference is not None: same(reference, {'file':relative,'digest':digest(raw),'bytes':len(raw)}, 'original retained bytes differ')
    return raw

def raw_bytes(value):
    require(isinstance(value,list) and all(type(x) is int and 0 <= x < 256 for x in value), 'raw bytes malformed')
    return bytes(value)

def resolve_observed(path, links):
    absolute(path)
    pending, current, hops = path.split('/'), [], 0
    while pending:
        part = pending.pop(0)
        if part in ('','.'): continue
        if part == '..':
            require(current, 'alias escapes root'); current.pop(); continue
        current.append(part)
        key = '/'.join(current)
        if key in links:
            hops += 1; require(hops <= 40, 'alias cycle')
            target = links[key]; current.pop()
            if target.startswith('/'): current = []
            pending = target.split('/') + pending
    return '/'+ '/'.join(current)

def native_linker(root, native, live):
    keys(native, ('schema','target','bin','sdkRoot','resourceRoot','tools','discoveryTool','searchInputs','probes','runtime','nativeDiscovery','scope'))
    require(native['schema'] == 'legion-rust-native-linker-enrollment/1' and native['target'] == 'aarch64-apple-darwin' and native['scope'] == 'Rust-only fixed fixture linker/SDK libraries; OS /usr/lib & /System/Library runtime exemptions; no C builds', 'native platform/scope differs')
    runtime = native['runtime']
    runpy.run_path(str(source_file(root,REPLAY)))['runtime_closure'](runtime, live)
    require(runtime['exclusions'] == [] and len(runtime['files']) <= 300000 and all(p not in ('/','/usr','/opt','/opt/homebrew','/Applications','/System') for p in runtime['roots']), 'native closure exclusions/broad roots/bounds introduced')
    files, links = runtime['files'],runtime['links']
    def bound(path, sha=None):
        absolute(path)
        require(files.get(path[1:]) is not None and (sha is None or files[path[1:]] == sha), 'native identity outside closure')
    graph = native['nativeDiscovery']
    keys(graph, ('inspector','systemExemptions','images','digest'))
    require(graph['inspector']['path'] == '/usr/bin/otool' and is_digest(graph['inspector']['digest']) and graph['systemExemptions'] == ['/usr/lib','/System/Library'], 'native inspector/exemptions differ')
    require(graph['digest'] == digest(encoded({k:v for k,v in graph.items() if k != 'digest'})), 'native graph digest differs')
    require(graph['images'] and len(graph['images']) <= 15000, 'native images absent/unbounded')
    contexts = set()
    for image in graph['images']:
        keys(image,('path','executable','rpathStack','dependencies'))
        bound(image['path']); bound(image['executable'])
        key = (image['path'],image['executable'],tuple(image['rpathStack']))
        require(key not in contexts, 'duplicate native context'); contexts.add(key)
        for item in image['dependencies']:
            keys(item,('command','requested','resolved','systemExempt'))
            absolute(item['resolved'])
            system = any(item['resolved'] == x or item['resolved'].startswith(x+'/') for x in graph['systemExemptions'])
            require(type(item['systemExempt']) is bool and item['systemExempt'] is system, 'native system exemption expanded')
            if not system: bound(item['resolved'])
    keys(native['tools'],('clang','ld','ar','ranlib','dsymutil'))
    for name,item in native['tools'].items():
        keys(item,('selectedPath','path','digest'))
        bound(item['path'],item['digest'])
        require(resolve_observed(item['selectedPath'],links) == item['path'], 'selected tool aliases differ')
    same(native['discoveryTool'], {'path':'/usr/bin/xcrun','digest':files.get('usr/bin/xcrun')}, 'fixed discovery tool differs')
    bound('/usr/bin/xcrun')
    bin_path = str(absolute(native['bin']))
    expected_links = {bin_path[1:]+'/'+name: '/usr/bin/xcrun' if name == 'xcrun' else native['tools']['clang' if name == 'cc' else name]['path'] for name in ('clang','cc','ld','ar','ranlib','dsymutil','xcrun')}
    same({k:v for k,v in links.items() if k.startswith(bin_path[1:]+'/')},expected_links,'isolated native PATH membership differs')
    sdk,res = str(absolute(native['sdkRoot'])),str(absolute(native['resourceRoot']))
    search = [sdk+'/usr/lib',sdk+'/System/Library/Frameworks',res+'/lib/darwin']
    keys(native['searchInputs'],search)
    for search_root,items in native['searchInputs'].items():
        require(isinstance(items,dict) and items and len(items) <= 200000, 'native search membership absent/unbounded')
        for rel,sha in items.items():
            safe_relative(rel)
            require(rel.endswith(('.tbd','.a','.dylib','.o')) and not any(x in ('Headers','PrivateHeaders','Modules') or x.endswith('.swiftmodule') for x in PurePosixPath(rel).parts), 'unapproved native search input')
            target = resolve_observed(search_root+'/'+rel,links)
            require(target.startswith(sdk+'/') or target.startswith(res+'/'), 'native search input escaped SDK/resource')
            bound(target,sha)
        # Every retained regular selectable input directly under each search root must occur.
        for key,sha in files.items():
            path = '/'+key
            if path.startswith(search_root+'/') and path.endswith(('.tbd','.a','.dylib','.o')):
                relative = path[len(search_root)+1:]
                if not any(x in ('Headers','PrivateHeaders','Modules') or x.endswith('.swiftmodule') for x in PurePosixPath(relative).parts): require(items.get(relative) == sha, 'retained native search membership omitted')
    clang,ld = native['tools']['clang']['path'],native['tools']['ld']['path']
    argv = [['/usr/bin/xcrun','--find',x] for x in ('clang','ld','ar','ranlib','dsymutil')] + [['/usr/bin/xcrun','--show-sdk-path'],[clang,'-print-resource-dir'],[clang,'--version'],[clang,'-print-search-dirs'],[clang,'-###','-isysroot',sdk,'-fuse-ld='+ld,'-Wl,-Z','-L'+sdk+'/usr/lib','-F'+sdk+'/System/Library/Frameworks','-L'+res+'/lib/darwin','-x','c','/dev/null','-o',str(PurePosixPath(bin_path).parent/'never-created-link-probe')]]
    require(len(native['probes']) == 10, 'native fixed probes incomplete')
    outputs=[]
    for probe,args in zip(native['probes'],argv):
        keys(probe,('args','cwd','environment','exitCode','stdout','stderr'))
        same(probe['args'],args,'native probe argv differs')
        require(probe['cwd'] == str(PurePosixPath(bin_path).parent) and probe['exitCode'] == 0,'native probe failed/wrong cwd')
        same(probe['environment'],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'},'discovery environment differs')
        streams=[]
        for name in ('stdout','stderr'):
            keys(probe[name],('rawBytes','digest')); raw=raw_bytes(probe[name]['rawBytes'])
            require(probe[name]['digest'] == digest(raw),'native raw probe changed');streams.append(raw)
        require(sum(map(len,streams)) <= 1024*1024,'native probe bound exceeded'); outputs.append(streams)
    for index,name in enumerate(('clang','ld','ar','ranlib','dsymutil')): require(outputs[index][0].decode().strip() == native['tools'][name]['selectedPath'],'native tool discovery mismatch')
    require(resolve_observed(outputs[5][0].decode().strip(),links) == sdk and resolve_observed(outputs[6][0].decode().strip(),links) == res,'SDK/resource discovery mismatch')
    require(ld.encode() in outputs[9][1] and sdk.encode() in outputs[9][1], 'driver trace misses linker/SDK')
    if live: require(digest(Path('/usr/bin/otool').read_bytes()) == graph['inspector']['digest'],'live inspector drift')
    return {k:native[k] for k in ('runtime','searchInputs','tools','bin','sdkRoot','resourceRoot','nativeDiscovery','discoveryTool','probes')}

def config_bytes(enrollment):
    native=enrollment['nativeLinker'];sdk=native['sdkRoot'];resource=native['resourceRoot'];ld=native['tools']['ld']['path']
    flags=['-C','link-arg=-fuse-ld='+ld,'-C','link-arg=-isysroot','-C','link-arg='+sdk,'-C','link-arg=-Wl,-Z','-C','link-arg=-L'+sdk+'/usr/lib','-C','link-arg=-F'+sdk+'/System/Library/Frameworks','-C','link-arg=-L'+resource+'/lib/darwin']
    return ('[source.crates-io]\nreplace-with="legion-fixed-vendor"\n[source.legion-fixed-vendor]\ndirectory='+json.dumps(enrollment['vendor']['root'])+'\n[target.aarch64-apple-darwin]\nlinker='+json.dumps(native['tools']['clang']['path'])+'\nrustflags='+json.dumps(flags,separators=(',',':'))+'\n').encode()

def enrollment_snapshot(root,enrollment,retained,live):
    keys(enrollment,('schema','scope','productionQualification','inputsDigest','archives','nativeLinker','vendor','cargoHome','database'))
    pins_raw=source_file(root,FIXTURES+'/inputs.json').read_bytes();pins=parsed(pins_raw)
    require(enrollment['schema'] == 'legion-rust-code-fixture-enrollment/1' and enrollment['scope'] == pins['scope'] == 'constructed offline SDK fixture inputs; no production, freshness or full RustSec claim' and enrollment['productionQualification'] is False and enrollment['inputsDigest'] == digest(pins_raw),'input enrollment scope/pins differ')
    native=native_linker(root,enrollment['nativeLinker'],live)
    private=str(PurePosixPath(enrollment['nativeLinker']['bin']).parent)
    require(PurePosixPath(private).name=='legion-rust-code-sdk-tools' and not str(absolute(private)).startswith(str(root)+'/'), 'isolated managed CI tool root differs')
    require(enrollment['vendor']['root']==private+'/vendor' and enrollment['cargoHome']['root']==private+'/cargo-home' and enrollment['database']['root']==private+'/database','private provisioned roots escaped closure')
    expected_vendor={}; archives={}
    require([(p['name'],p['version']) for p in pins['packages']] == [('smallvec','0.6.9'),('smallvec','0.6.10')], 'fixed package closure differs')
    keys(enrollment['archives'],('smallvec-0.6.9','smallvec-0.6.10'))
    for package in pins['packages']:
        name='smallvec-'+package['version'];original=enrollment['archives'][name]
        keys(original,('path','digest','bytes','url'));require(original['path']==private+'/archives/'+name+'.crate','archive path escaped private closure')
        data=retained_bytes(retained,'input-archives/'+name+'.crate')
        require(digest(data) == 'sha256:'+package['sha256'] == original['digest'] and len(data) == original['bytes'] and original['url'] == package['url'] == 'https://static.crates.io/crates/smallvec/'+name+'.crate','original official crate differs')
        archives[name]=original
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            observed={};members=archive.getmembers();require(len(members)<=1000,'crate member bound')
            for member in members:
                path=PurePosixPath(member.name)
                require(path.parts and path.parts[0] == name and not path.is_absolute() and '..' not in path.parts,'crate escapes prefix')
                if member.isdir():continue
                require(member.isfile() and len(path.parts)>1 and member.size<=1024*1024,'crate special/large member')
                rel=path.relative_to(name).as_posix();require(rel not in observed,'duplicate crate member')
                payload=archive.extractfile(member).read(1024*1024+1);require(len(payload)==member.size,'crate size differs');observed[rel]=digest(payload)[7:]
        same(observed,package['files'],'crate exact member closure differs')
        expected_vendor.update({name+'/'+p:'sha256:'+sha for p,sha in observed.items()})
        expected_vendor[name+'/.cargo-checksum.json']=digest(encoded({'files':observed,'package':package['sha256']})+b'\n')
    same(enrollment['vendor']['files'],expected_vendor,'vendor membership differs')
    home=enrollment['cargoHome']; require(home['configPath'] == home['root']+'/config.toml' and home['configDigest'] == digest(config_bytes(enrollment)),'exact Cargo config differs')
    advisory=pins['advisory'];raw=source_file(root,advisory['path']).read_bytes()
    require(digest(raw) == 'sha256:'+advisory['sha256'],'official advisory source drift')
    same(enrollment['database']['files'],{advisory['databasePath']:digest(raw)},'database subset identity differs')
    same(enrollment['database']['advisory'],advisory,'advisory descriptor differs')
    if live:
        for path,files in ((enrollment['vendor']['root'],expected_vendor),(enrollment['database']['root'],enrollment['database']['files'])): same(tree(path),files,'live provisioned tree drift')
        require(Path(home['configPath']).read_bytes() == config_bytes(enrollment),'live Cargo config drift')
        for name in ('config','credentials','credentials.toml'):require(not (Path(home['root'])/name).exists() and not (Path(home['root'])/name).is_symlink(),'unenrolled Cargo configuration')
        for archive in archives.values():require(digest(Path(archive['path']).read_bytes()) == archive['digest'],'live archive drift')
    return {'schema':'legion-rust-code-actual-input-snapshot/1','inputsDigest':digest(pins_raw),'vendor':enrollment['vendor'],'cargoHome':dict(home,absent=['config','credentials','credentials.toml']),'database':{'root':enrollment['database']['root'],'files':enrollment['database']['files']},'archives':archives,'nativeLinker':native}

def verify_enrollment(repository_root, enrollment, retained, live=False):
    """Pure replay by default; no process, network or installed-host reads."""
    return enrollment_snapshot(Path(repository_root).resolve(), enrollment, retained, live)

def tree(root):
    root=Path(root);require(root.is_dir() and not root.is_symlink(),'tree missing/aliased');out={}
    for p in root.rglob('*'):
        require(not p.is_symlink(),'tree alias refused')
        if p.is_file():out[p.relative_to(root).as_posix()]=digest(p.read_bytes())
        else:require(p.is_dir(),'special tree member')
    return out

def fixture(root,control):
    name='nonempty-clean' if control in ('missing-database','tampered-database','missing-tool','tampered-tool','changed-source','rejected-admission','absent-sandbox','budget-exhausted') else control
    manifest='Cargo.toml.txt' if name=='malformed-lock' else 'Cargo.toml'
    p=source_file(root,FIXTURES+'/'+name+'/'+manifest).parent
    files={x.relative_to(p).as_posix():x.read_text() for x in sorted(p.rglob('*')) if x.is_file()}
    if name=='malformed-lock':
        # Replay the exact names materialized only in the owned native case scratch.
        for target in ('Cargo.toml','Cargo.lock'):
            template=target+'.txt'
            require(template in files and target not in files,'missing/duplicate malformed-lock template')
            files[target]=files.pop(template)
    return files

def commands(policy,enrollment,tools):
    cwd=policy['cwd'];scratch=str(PurePosixPath(policy['profile']['path']).parent.parent)
    suffixes=[['metadata','--locked','--offline','--format-version','1'],['check','--locked','--offline','--workspace','--all-targets','--message-format=json'],['clippy','--locked','--offline','--workspace','--all-targets','--message-format=json'],['test','--locked','--offline','--workspace','--all-targets'],['audit','--json','--file',cwd+'/Cargo.lock','--db',policy['database'],'--no-fetch','--no-yanked']]
    env={'PATH':str(PurePosixPath(tools['cargo'][0]).parent)+':'+str(PurePosixPath(tools['cargo-audit'][0]).parent)+':'+enrollment['nativeLinker']['bin'],'HOME':str(PurePosixPath(cwd).parent/'home'),'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','GIT_CONFIG_NOSYSTEM':'1','NO_COLOR':'1','CARGO_NET_OFFLINE':'true','CARGO_TERM_COLOR':'never','CARGO_HOME':enrollment['cargoHome']['root'],'SDKROOT':enrollment['nativeLinker']['sdkRoot']}
    for name,relative in (('TMPDIR','tmp'),('TEMP','tmp'),('TMP','tmp'),('XDG_CACHE_HOME','cache/xdg'),('CARGO_TARGET_DIR','cache/cargo-target'),('npm_config_cache','cache/npm'),('RUFF_CACHE_DIR','cache/ruff'),('MYPY_CACHE_DIR','cache/mypy'),('PYTHONPYCACHEPREFIX','cache/pycache'),('GOCACHE','cache/go-build')): env[name]=scratch+'/'+relative
    allowed={'PATH','PATHEXT','SystemRoot','COMSPEC','HOME','USERPROFILE'} | set(env)
    result=[]
    for task,args in zip(TASKS,suffixes):
        values=dict(env)
        if task=='dependency':values['CARGO_HOME']=scratch+'/cache/rust-dependency-cargo-home'
        tool='cargo-audit' if task=='dependency' else 'cargo'
        result.append({'task':task,'args':args,'versionArgs':['-f',policy['profile']['path'],'--',tools[tool][0],'--version'],'environment':values,'environmentAllowlist':sorted(allowed),'acceptedExitCodes':[0,101] if task in ('check','lint') else [0,1] if task=='dependency' else [0]})
    same(policy['commands'],result,'source-owned argv/env/probes/exits changed')
    return result,Path(scratch)

def execution(item,policy,command,control,plan,scratch,live):
    keys(item,('request','executionReceipt','stdout','stderr'));req,r=item['request'],item['executionReceipt']; keys(r,RECEIPT_FIELDS)
    task=req['taskId'];tool='cargo-audit' if task=='dependency' else 'cargo'
    require(re.fullmatch(r'legion-audit/[0-9a-f]{64}',req['requestId'] or ''),'SDK request identity malformed')
    prefix=['-f',policy['profile']['path'],'--',policy['toolIdentities'][tool][0]]
    expected={'schemaVersion':1,'requestId':req['requestId'],'providerId':PROVIDER,'planId':plan,'policyId':'audit','taskId':task,'executable':policy['wrapper']['path'],'args':prefix+command['args'],'cwd':policy['cwd'],'origin':'TargetProject','shell':False,'expectedDigest':policy['wrapper']['digest'],'acceptedExitCodes':command['acceptedExitCodes'],'versionArgs':command['versionArgs'],'skipVersionProbe':False,'versionRequirement':None,'environment':command['environment'],'environmentAllowlist':command['environmentAllowlist'],'sensitiveArgumentIndexes':[],'sensitiveEnvironmentNames':[],'requiresNetworkSandbox':True,'sandbox':None if control=='absent-sandbox' else {'id':policy['profile']['receiptId'],'network':True,'filesystemScope':policy['cwd']},'timeoutMs':120000,'stdoutLimit':33554432,'stderrLimit':33554432}
    same(req,expected,'SDK exact request differs')
    require(r['schemaVersion']==1 and r['receiptId']=='receipt:'+req['requestId'] and all(r[k]==req[k] for k in ('requestId','providerId','planId','taskId','cwd')),'receipt/request binding differs')
    same(r['command'],{'executable':req['executable'],'args':req['args'],'environmentNames':sorted(req['environment']),'redactedArgumentIndexes':[],'redactedEnvironmentNames':[]},'launched command differs')
    same(r['environmentNames'],sorted(req['environment']),'launched environment differs')
    same(r['parser'],{'attempted':False,'succeeded':False,'error':None},'raw SDK receipt reinterpreted')
    denied=control in ('changed-source','rejected-admission');absent=control=='absent-sandbox'
    p=r['policy'];require(r['policyId']==p['id'],'policy identity differs')
    if control=='rejected-admission':same(p,{'id':'audit-native-owner-admission-v1','version':1,'allowed':False,'reason':'native-owner-admission-unavailable','digest':digest(encoded({'externalProcesses':'owner-admission-required','admissionStatus':'unavailable','effectiveMode':'deny-external'}))},'genuine owner denial differs')
    else:same(p,{'id':POLICY,'version':1,'digest':digest(encoded(policy)),'allowed':not denied,'reason':'outside exact constructed Rust SDK fixture contract' if denied else 'exact constructed Rust SDK fixture request'},'fixture policy differs')
    same(r['sandbox'],{'required':True,'receiptId':None if absent else policy['profile']['receiptId'],'networkEnabled':not absent},'sandbox binding differs')
    if denied or absent:
        require(r['state']==('sandbox_missing' if absent else 'unauthorized_effect') and r['complete'] is False and r['exitCode'] is r['signal'] is r['executable'] is None and r['gaps'],'refusal became executed/clean')
        same(r['processTree'],{'started':False,'terminated':False,'hardKilled':False,'reaped':False,'detail':None},'refusal launched process')
        same(r['timing'],{'startedAtMs':0,'completedAtMs':0,'durationMs':0},'refusal timed process')
        require(r['stdout'] is r['stderr'] is item['stdout'] is item['stderr'] is None,'refusal invented output')
        return b'',b''
    identity=r['executable'];require(identity['requestedPath']==identity['canonicalPath']==policy['wrapper']['path'] and identity['digest']==policy['wrapper']['digest'] and identity['digestState']=='sealed','executed wrapper differs')
    version=identity['version'];require(version['args']==command['versionArgs'] and version['qualified'] is True and version['skippedByPolicy'] is False and version['exitCode']==0 and version['output'].startswith('cargo-audit 0.22.2' if task=='dependency' else 'cargo 1.98.0 '),'actual tool probe differs')
    good=r['exitCode'] in command['acceptedExitCodes'];require(type(r['exitCode']) is int and r['signal'] is None and r['state']==('completed' if good else 'failed') and r['complete'] is good,'SDK exit/outcome differs')
    lifecycle=r['processTree'];require(all(lifecycle[k] is True for k in ('started','terminated','reaped')) and lifecycle['hardKilled'] is False,'native tree lifecycle incomplete')
    timing=r['timing'];keys(timing,('startedAtMs','completedAtMs','durationMs'));require(all(type(x) is int for x in timing.values()) and timing['startedAtMs']>0 and timing['completedAtMs']>=timing['startedAtMs'] and timing['durationMs']==timing['completedAtMs']-timing['startedAtMs'],'SDK timing inconsistent')
    streams=tuple(artifact(r[name],item[name],scratch,live) for name in ('stdout','stderr'))
    require(all(len(raw)<=33554432 for raw in streams),'SDK output bound exceeded')
    return streams

def validate_case(root,case,enrollment,input_snapshot,toolchain,retained,live):
    keys(case,('control','provider','fixtureFiles','fixtureSources','sourceAfter','inventory','planDigest','frozenProvider','nativeResult','sdkExecutions','policyDefinition','policyDecisions','databaseRoot','databaseFiles','scope','matched'))
    control=case['control'];require(control in CONTROLS and case['provider']==PROVIDER and case['matched'] is True and case['scope']==('sdk-boundary-control' if control=='absent-sandbox' else 'native-provider-known-answer-fixture'),'case identity differs')
    source=fixture(root,control);hashes={p:digest(t.encode()) for p,t in source.items()}
    same(case['fixtureFiles'],source,'original fixture bytes differ');same(case['fixtureSources'],hashes,'fixture source hashes differ')
    after=dict(hashes)
    if control=='changed-source':after['src/lib.rs']=digest(b'pub fn answer()->u8{0}\n')
    same(case['sourceAfter'],after,'source unchanged/drift control differs')
    inv=case['inventory'];entries=[{'path':p,'symbols':[],'dependencies':[],'packageScripts':[],'sourceFile':p.endswith('.rs'),'digest':hashes[p]} for p in sorted(source)]
    same(inv['entries'],entries,'original denominator/source-context siblings differ')
    require(inv['schemaVersion']==1 and inv['repositoryId']==control and inv['generation']=='filesystem:'+digest(encoded(entries)) and inv['digest']==digest(encoded([1,control,inv['generation'],entries])),'inventory identity differs')
    spec=next(s for s in parsed(source_file(root,'src/registry/providers.json').read_bytes())['providers'] if s['id']==PROVIDER)
    frozen=case['frozenProvider'];require(is_digest(case['planDigest']) and frozen['id']==PROVIDER and frozen['version']==spec['providerVersion'] and frozen['configuration']['denominatorCount']==len(entries) and frozen['configuration']['denominatorDigest']==digest(encoded([inv['digest'],spec['selector'],entries])),'frozen provider denominator differs')
    policy=case['policyDefinition'];keys(policy,('id','version','scope','provider','planDigest','cwd','toolIdentities','sourceFiles','nativeLinker','database','wrapper','profile','commands','timeoutMs','stdoutLimit','stderrLimit','maxRequestsPerTask','absentSandboxControl'))
    require(policy['id']==POLICY and policy['version']==1 and policy['scope']=='exact constructed Rust SDK fixtures; no production owner admission' and policy['provider']==PROVIDER and policy['planDigest']==case['planDigest'] and policy['timeoutMs']==120000 and policy['stdoutLimit']==policy['stderrLimit']==33554432 and policy['maxRequestsPerTask']==1 and policy['absentSandboxControl'] is (control=='absent-sandbox'),'policy scope/bounds differ')
    cwd=str(absolute(policy['cwd']));require(PurePosixPath(cwd).name=='source' and PurePosixPath(cwd).parent.name==control and PurePosixPath(cwd).parent.parent.name=='fixture-roots','private fixture layout differs')
    same(policy['sourceFiles'],hashes,'policy source closure differs');same(policy['nativeLinker'],input_snapshot['nativeLinker'],'policy native closure differs')
    require(policy['wrapper']['path']=='/usr/bin/sandbox-exec' and is_digest(policy['wrapper']['digest']),'fixed sandbox identity absent')
    if live:require(digest(Path('/usr/bin/sandbox-exec').read_bytes())==policy['wrapper']['digest'],'live sandbox drift')
    escaped=cwd.replace('\\','\\\\').replace('"','\\"');text='(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "'+escaped+'"))\n';sha=digest(text.encode())[7:]
    profile=policy['profile'];require(profile['text']==text and profile['receiptId']=='sandbox:macos:'+sha and profile['path'].endswith('/sandbox/audit-'+sha+'.sb'),'sandbox text/id/path differs')
    tools=policy['toolIdentities'];keys(tools,('cargo','rustc','cargo-clippy','clippy-driver','cargo-audit'))
    for name,(path,sha) in tools.items():
        absolute(path);require(is_digest(sha),'tool digest malformed')
        if name!='cargo-audit':require(path==toolchain['root']+'/bin/'+name and toolchain['files'].get('bin/'+name)==sha,'tool outside original sysroot closure')
        else:
            expected='sha256:33fbe81adca1b794f4ffe98574d59b0ebe6fcfdb310976fafed98a094c795111'
            if control!='tampered-tool':require(sha==expected,'official cargo-audit binary pin differs')
            else:require(sha!=expected and PurePosixPath(path).parent.name=='tampered-tool','actual scanner drift control missing')
        if live:require(digest(Path(path).read_bytes())==sha and not Path(path).read_bytes().startswith(b'#!'),'live native tool differs')
    specs,scratch=commands(policy,enrollment,tools)
    require(scratch==Path(cwd).parents[2]/'cases'/control/'run' and case['databaseRoot']==policy['database']==str(PurePosixPath(cwd).parent/'database'),'private scratch/database layout differs')
    original=source_file(root,'engine/crates/legion-audit/tests/fixtures/cargo-audit/RUSTSEC-2019-0009.md').read_bytes()
    if control=='tampered-database':original+=b'\ncontrolled byte drift\n'
    same(case['databaseFiles'],{} if control=='missing-database' else {'crates/smallvec/RUSTSEC-2019-0009.md':digest(original)},'case database drift/missing control differs')
    rows=case['sdkExecutions'];require(len({r['request']['requestId'] for r in rows})==len(rows),'duplicate SDK request')
    unavailable=control in ('missing-database','tampered-database','tampered-tool','audit-config')
    tasks=[r['request']['taskId'] for r in rows]
    if control in ('missing-tool','budget-exhausted'):same(tasks,[],'unstarted control executed')
    elif control=='absent-sandbox':same(tasks,['metadata'],'absent sandbox control differs')
    elif control in ('changed-source','rejected-admission'):require(tasks and len(tasks)==len(set(tasks)) and set(tasks)<=set(TASKS),'denial tasks differ')
    else:same(tasks,[t for t in TASKS if not unavailable or t!='dependency'],'five-operation execution matrix differs')
    streams={}
    for n,item in enumerate(rows):
        command=next(s for s in specs if s['task']==item['request']['taskId'])
        streams[command['task']]=execution(item,policy,command,control,case['planDigest'],scratch,live)
        same(parsed(retained_bytes(retained,'cases/'+control+'/run/sdk-execution-'+str(n)+'.json')),item,'original SDK receipt artifact differs')
    decisions=[] if control=='rejected-admission' else [{'requestId':x['request']['requestId'],'taskId':x['request']['taskId'],'allowed':control!='changed-source','request':x['request']} for x in rows]
    same(case['policyDecisions'],decisions,'actual authorizer decisions differ')
    native=case['nativeResult']
    if control=='absent-sandbox':require(native is None,'sandbox refusal invented provider result')
    else:
        require(native['provider']==PROVIDER and native['applicable'] is True and native['complete'] is False and native['coverage']['expected']==len(entries) and native['coverage_gaps'],'native subset/unsafe scope falsely clean')
        gaps=' '.join(native['coverage_gaps'])
        gap={'missing-tool':'tool-missing','budget-exhausted':'tool-budget-exhausted','changed-source':'changed-since-inventory','rejected-admission':'native-owner-admission-unavailable','compiler-failure':'cargo-build-incomplete','test-failure':'tool-failed:test','unsafe-assessment':'unsafe-assessment-unavailable','features':'unproven-build-variant','targets':'unproven-build-variant','malformed-lock':'tool-failed:dependency'}.get(control)
        if gap:require(gap in gaps,'required control gap missing')
        if unavailable:require('rust-dependency-input-unavailable' in gaps,'unavailable dependency promoted to clean')
        if control not in ('missing-tool','budget-exhausted','changed-source','rejected-admission'):
            require(native['coverage']['examined']==len(entries)-(control=='audit-config'),'native examined denominator differs')
            producer=native['details']['nativeProducer'];require(producer['sourceFilesRead']==1 and producer['contextFilesRead']==3,'source/context accounting differs')
            projected=producer['toolReceipts']
            for item in rows:
                task=item['request']['taskId'];matches=[p for p in projected if p['tool']==task];require(len(matches)==1,'native tool receipt absent/duplicate');same(matches[0]['sdkReceipt'],item['executionReceipt'],'parser used different SDK receipt')
                if task=='dependency':
                    snaps=matches[0]['nativeInputSnapshots'];require(snaps['unchanged'] is True,'dependency input drift hidden');same(snaps['before'],snaps['after'],'dependency input snapshots differ')
            evidence=native['details']['nativeAnalysis']['toolEvidence'];require(len(evidence)==5 and {e['id'] for e in evidence}==set(TASKS),'parser evidence operations incomplete/duplicate')
            for e in evidence:
                task=e['id'];failed=control=='malformed-lock' or (control=='compiler-failure' and task in ('check','lint','test')) or (control=='test-failure' and task=='test')
                status='unavailable' if unavailable and task=='dependency' else 'fail' if failed else 'pass'
                require(e['status']==status,'actual parser outcome differs')
                if status=='pass':
                    require(e['artifactDigest']==digest(digest(streams[task][0]).encode()) and len(e['scope']['runs'])==1,'parser pass missing original output digest/scope')
                    same(e['scope']['runs'][0],next(p for p in projected if p['tool']==task),'analysis scope differs from actual native tool receipt')
            by_task={x['request']['taskId']:x['executionReceipt'] for x in rows}
            findings=list(native['details']['findingEvidence'].values())
            def finding(rule,path):return any(f['ruleId']==rule and f['path']==path and type(f['line']) is int and f['line']>0 for f in findings)
            if control=='positive':require(finding('clippy:needless_return','src/lib.rs') and by_task['lint']['exitCode']==0 and b'needless_return' in streams['lint'][0],'genuine Clippy diagnostic missing')
            if control in ('nonempty-clean','dependency-nonempty-clean'):require(native['findings']==[] and all(r['exitCode']==0 for r in by_task.values()),'nonempty clean control failed')
            if control=='dependency-positive':
                data=parsed(streams['dependency'][0]);require(finding('cargo-audit:RUSTSEC-2019-0009','Cargo.lock') and by_task['dependency']['exitCode']==1 and data['vulnerabilities']['found'] is True and data['vulnerabilities']['count']==1 and data['vulnerabilities']['list'][0]['advisory']['id']=='RUSTSEC-2019-0009','genuine advisory diagnostic missing')
            if control=='compiler-failure':require(finding('rustc:E0425','src/lib.rs') and by_task['check']['exitCode']==101 and b'E0425' in streams['check'][0],'genuine compiler diagnostic missing')
            if 'test' in streams and control not in ('compiler-failure','malformed-lock'):
                out=streams['test'][0];require(re.search(rb'\b[1-9][0-9]* passed;',out) if control!='test-failure' else b'FAILED' in out and b'1 failed;' in out,'actual nonempty test assertions missing')
            if control=='test-failure':require(by_task['test']['exitCode']==101,'test assertion failure promoted')
            if control=='unsafe-assessment':require(native['findings']==[],'unsafe semantic assessment fabricated')
            if control=='malformed-lock':require(by_task['dependency']['exitCode']==2,'malformed lock became clean')
    same(parsed(retained_bytes(retained,'cases/'+control+'/case-observation.json')),case,'original case observation differs')
    return {control+'/'+p:sha for p,sha in hashes.items()}

def artifact_locator(row,raw):
    return {'schema':'legion-rust-code-sdk-artifact/1','provider':PROVIDER,'file':'code_rust.json','digest':digest(raw),'bytes':len(raw),'qualificationDigest':row['qualificationDigest'],'qualificationEligible':row['qualificationEligible'],'productionQualification':False}

def retained_files(row):
    names={'code_rust.json','input-enrollment.json','environment.json','toolchain-runtime.json','toolchain-runtime-after.json'}
    names.update(ref['file'] for ref in row['inputArchives'].values())
    for case in row['cases']:
        prefix='cases/'+case['control']+'/'
        names.update(prefix+n for n in ('child-execution.json','child.stdout.log','child.stderr.log','input-snapshots.json','case-observation.json'))
        names.update(prefix+'run/sdk-execution-'+str(n)+'.json' for n in range(len(case['sdkExecutions'])))
    return sorted(names)

def validate_record(repository_root,row,live=False,retained=None):
    root=Path(repository_root).resolve();require(retained is not None,'original retained evidence required');retained=Path(retained)
    keys(row,('schema','kind','provider','providerVersion','platform','retainedRoot','productionQualification','selfProducerQualification','publicHelperQualification','qualificationEligible','claimScope','modelCalls','executionPath','admissionScope','requiredContract','binding','controls','children','cases','inputSnapshots','inputArchives','inputEnrollment','environment','toolchain','metrics','runtimeLimitations','qualificationDigest'))
    require(row['schema']=='legion-rust-code-sdk-accuracy/1' and row['kind']=='code-rust-sdk-constructed' and row['provider']==PROVIDER and row['platform']=={'os':'macos','arch':'aarch64'} and all(row[x] is False for x in ('productionQualification','selfProducerQualification','publicHelperQualification')) and row['qualificationEligible'] is True and row['claimScope']=='known-answer-fixture-cases' and type(row['modelCalls']) is int and row['modelCalls']==0 and row['executionPath']=='native-sdk-frozen-plan-self-sourced-code' and row['admissionScope']=='exact constructed authorizer & genuine default denial; no production owner admission','Rust SDK identity/claim differs')
    require(row['qualificationDigest']==digest(encoded({k:v for k,v in row.items() if k!='qualificationDigest'})),'original qualification digest differs')
    same(row['controls'],list(CONTROLS),'19 control denominator changed');same([c['control'] for c in row['cases']],list(CONTROLS),'original controls incomplete/reordered');same(row['runtimeLimitations'],LIMITATIONS,'runtime limitation scope erased')
    original_retained=str(absolute(row['retainedRoot']));require(original_retained.endswith('/legion-provider-qualification/code-rust-sdk'),'original retained layout differs')
    spec=next(s for s in parsed(source_file(root,'src/registry/providers.json').read_bytes())['providers'] if s['id']==PROVIDER);spec={k:v for k,v in spec.items() if k!='benchmark'}
    require(row['providerVersion']==spec['providerVersion'],'provider version stale')
    bound=row['binding'];keys(bound,('providerSpec','providerSpecDigest','sources','sourcesDigest','fixtureSources','fixtureSourcesDigest','fixture','repositoryRoot'))
    sources={p:digest(source_file(root,p).read_bytes()) for p in source_files(root)}
    same(bound['providerSpec'],spec,'semantic provider spec changed');same(bound['sources'],sources,'original source closure drift')
    require(bound['providerSpecDigest']==digest(encoded(spec)) and bound['sourcesDigest']==digest(encoded(sources)) and bound['fixture']==HARNESS,'source bindings differ');absolute(bound['repositoryRoot'])
    contract=required_contract(root,PROVIDER);require(contract['tools']==list(TASKS) and contract['requiredContext']==['features','targets'] and contract['extensions']==['rs'],'full original provider contract narrowed')
    same(row['requiredContract'],{'tools':list(TASKS),'contexts':['features','targets'],'unsafe':'keyword inventory & explicit soundness gap; no semantic assessment','dependency':'dependency/v1 official unchanged RUSTSEC-2019-0009 subset only'},'required operation/unsafe contract differs')
    enrollment_raw=retained_bytes(retained,'input-enrollment.json',row['inputEnrollment']);enrollment=parsed(enrollment_raw)
    snapshot=enrollment_snapshot(root,enrollment,retained,live)
    same(row['inputSnapshots'],{'before':snapshot,'after':snapshot,'unchanged':True},'global before/after enrollment drift hidden')
    environment_raw=retained_bytes(retained,'environment.json',row['environment'])
    expected_env={'CARGO_HOME':enrollment['cargoHome']['root'],'LEGION_RUST_CODE_ENROLLMENT_JSON':str(PurePosixPath(enrollment['cargoHome']['root']).parent/'enrollment.json'),'SDKROOT':enrollment['nativeLinker']['sdkRoot']}
    same(parsed(environment_raw),expected_env,'original environment export lost SDKROOT/config/enrollment')
    runtime_raw=retained_bytes(retained,'toolchain-runtime.json',{k:v for k,v in row['toolchain'].items() if k in ('file','digest','bytes')});toolchain=parsed(runtime_raw)
    keys(toolchain,('root','files','scope'));absolute(toolchain['root']);require(toolchain['files'] and toolchain['scope']=='actual pinned Rust compiler/Cargo/Clippy/sysroot file closure; OS system libraries excluded' and row['toolchain']['version']=='1.98.0' and row['toolchain']['unchanged'] is True,'Rust sysroot observation missing')
    for p,sha in toolchain['files'].items():safe_relative(p);require(is_digest(sha),'sysroot digest malformed')
    after=parsed(retained_bytes(retained,'toolchain-runtime-after.json',row['toolchain']['after']));same(after,{'root':toolchain['root'],'files':toolchain['files']},'original sysroot before/after drift')
    if live:same(tree(toolchain['root']),toolchain['files'],'live toolchain drift')
    keys(row['inputArchives'],enrollment['archives'])
    for name,ref in row['inputArchives'].items():
        raw=retained_bytes(retained,'input-archives/'+name+'.crate');same(ref,{'file':'input-archives/'+name+'.crate','digest':digest(raw),'bytes':len(raw),'url':enrollment['archives'][name]['url']},'retained crate locator differs')
    same(row['metrics'],{'cases':19,'matched':19,'wholeProviderQualified':False,'boundedSdkAccuracyQualified':True},'matrix metrics/claim differs')
    require(len(row['children'])==19,'owned child denominator differs');fixtures={}
    for case,child in zip(row['cases'],row['children']):
        control=case['control'];keys(child,('schema','control','started','success','inputSnapshots','exitCode','signal','error','stdout','stderr'))
        require(child['schema']=='legion-rust-code-owned-child/1' and child['control']==control and child['started'] is child['success'] is True and child['exitCode']==0 and child['signal'] is child['error'] is None,'native child failed/unstarted')
        same(child['inputSnapshots'],{'before':snapshot,'after':snapshot,'unchanged':True},'child native/input before-after drift')
        same(parsed(retained_bytes(retained,'cases/'+control+'/input-snapshots.json')),child['inputSnapshots'],'original child snapshots differ')
        same(parsed(retained_bytes(retained,'cases/'+control+'/child-execution.json')),child,'original child receipt differs')
        for stream in ('stdout','stderr'):
            raw=retained_bytes(retained,'cases/'+control+'/child.'+stream+'.log')
            same(child[stream],{'file':'child.'+stream+'.log','bytes':len(raw),'digest':digest(raw)},'original child raw stream differs')
            if stream=='stdout':require(re.findall(rb'test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;',raw)==[(b'1',b'0',b'0')] and len(re.findall(rb'\btest real_rust_code_accuracy \.\.\.',raw))==1,'actual named native child selector did not pass once')
        # Keep original host locations in policy/receipts; offline artifact paths are separate.
        fixtures.update(validate_case(root,case,enrollment,snapshot,toolchain,retained,live))
    same(bound['fixtureSources'],fixtures,'full fixture denominator differs');require(bound['fixtureSourcesDigest']==digest(encoded(fixtures)),'fixture digest differs')
    return {'provider':PROVIDER,'cases':19,'qualificationEligible':True,'productionQualification':False,'claimScope':'known-answer-fixture-cases','modelCalls':0}

def rejection_controls(root,row,retained):
    """Disconfirm eligibility from actual retained input; never mint a positive fixture."""
    mutations = {
        'missing-control': lambda v: v['cases'].pop(),
        'duplicate-control': lambda v: v['cases'].append(copy.deepcopy(v['cases'][0])),
        'narrow-tools': lambda v: v['requiredContract']['tools'].pop(),
        'narrow-features-targets': lambda v: v['requiredContract']['contexts'].pop(),
        'unsafe-gap-erased': lambda v: v['runtimeLimitations'].pop(1),
        'benchmark-provider-spec-rebound': lambda v: v['binding']['providerSpec'].update(benchmark={'status':'qualified'}),
        'source-digest': lambda v: v['binding']['sources'].update({next(iter(v['binding']['sources'])):'sha256:'+'0'*64}),
        'native-snapshot-drift': lambda v: v['inputSnapshots']['after']['nativeLinker']['runtime'].update(digest='sha256:'+'0'*64),
        'missing-admission': lambda v: v['cases'][0]['sdkExecutions'][0]['executionReceipt']['policy'].update(allowed=False),
        'missing-sandbox': lambda v: v['cases'][0]['sdkExecutions'][0]['request'].update(sandbox=None),
        'raw-output-drift': lambda v: v['cases'][0]['sdkExecutions'][0]['stdout']['rawBytes'].append(0),
        'unreaped-descendant': lambda v: v['cases'][0]['sdkExecutions'][0]['executionReceipt']['processTree'].update(reaped=False),
        'failed-native-child': lambda v: v['children'][0].update(success=False),
        'lost-SDKROOT-export': lambda v: v['environment'].update(digest='sha256:'+'0'*64),
        'whole-provider-claim': lambda v: v['metrics'].update(wholeProviderQualified=True),
    }
    rejected=[]
    for name,mutate in mutations.items():
        value=copy.deepcopy(row);mutate(value)
        value['qualificationDigest']=digest(encoded({k:v for k,v in value.items() if k!='qualificationDigest'}))
        try: validate_record(root,value,live=False,retained=retained)
        except (AssertionError,KeyError,TypeError,ValueError):rejected.append(name)
        else:require(False,'retained evidence tamper accepted: '+name)
    return rejected

def validate_retained(root,row,retained):
    raw=retained_bytes(retained,'code_rust.json');same(parsed(raw),row,'indexed record is not original bytes')
    result=validate_record(root,row,live=False,retained=retained)
    result['validatorRejectionControls']=rejection_controls(root,row,retained)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--receipts',type=Path,required=True);args=parser.parse_args()
    raw=retained_bytes(args.receipts,'code_rust.json');row=parsed(raw)
    summary=validate_record(args.root,row,live=True,retained=args.receipts)
    summary['validatorRejectionControls']=rejection_controls(args.root,row,args.receipts)
    print('RUST_CODE_SDK_ACCURACY_SUMMARY '+json.dumps({'records':[summary],'modelCalls':0},sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
