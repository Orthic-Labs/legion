#!/usr/bin/env python3
"""Replay original PHP/Ruby SDK known-answer artifacts; never grant production admission."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import runpy

COMMON = "scripts/ci/audit-code-sdk-accuracy.py"
BOOTSTRAP = "scripts/ci/audit-php-ruby-sdk-bootstrap.py"
HARNESS = "engine/crates/legion-audit/tests/real_php_ruby_code_command_accuracy.rs"
FIXTURES = "scripts/ci/fixtures/audit-code-php-ruby-sdk-accuracy"
POLICY = "legion-real-php-ruby-code-command-fixture-v1"
PROVIDER = "code.php-ruby"
CONTROLS = ("nonempty-clean","php-lint-positive","ruby-lint-positive","type-positive","security-positive","php-test-failure","ruby-test-failure","malformed-manifest","malformed-lock","source-drift","missing-tool","rejected-admission","absent-sandbox","disabled-sandbox","timeout","cancel")
TASKS = ("ruby-lint","ruby-lint","package","type","test","test","test","security","lint","ruby-syntax","lint","ruby-syntax")
# Reuse reviewed canonical JSON, safe-path, raw-artifact & original CONFIG readers.
_shared = runpy.run_path(str(Path(__file__).resolve().parents[2] / COMMON))
for _name in ("require", "keys", "encoded", "digest", "is_digest", "same", "parsed", "source_file", "absolute", "artifact", "required_contract"):
    globals()[_name] = _shared[_name]
RECEIPT_FIELDS = _shared["RECEIPT_FIELDS"]
SOURCE_ROOTS = ["engine/crates/" + c + "/src" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls", FIXTURES, "scripts/ci/php-ruby-sdk-assets"]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, BOOTSTRAP, "scripts/ci/provision-python-qualification-tools.py", "scripts/ci/audit-pip-audit-provider-accuracy.py", "scripts/ci/php-ruby-sdk-inputs.json", "scripts/ci/audit-php-ruby-code-sdk-accuracy.py"] + ["engine/crates/" + c + "/Cargo.toml" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]

def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    paths = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        p = Path(root) / relative
        require(p.is_dir() and not p.is_symlink(), "source closure root missing")
        for item in p.rglob("*"):
            require(not item.is_symlink(), "source closure symlink")
            if item.is_file():
                if generated_session_provenance(item.relative_to(root).as_posix()):
                    continue
                paths.add(item.relative_to(root).as_posix())
    return sorted(paths)

def fixture(root, control):
    name = "nonempty-clean" if control in ("missing-tool", "rejected-admission", "absent-sandbox", "disabled-sandbox", "source-drift") else control
    p = Path(root) / FIXTURES / name
    require(p.is_dir() and not p.is_symlink(), "fixture source missing")
    result = {}
    for item in sorted(p.rglob("*")):
        require(not item.is_symlink(), "fixture symlink")
        if item.is_file(): result[item.relative_to(p).as_posix()] = item.read_text()
    require(result, "empty known-answer fixture")
    return result

def literal(root, relative, name):
    text = source_file(root, relative).read_text()
    prefix = 'const ' + name + ': &str = r#"'
    require(text.count(prefix) == 1, "owned command literal changed")
    return text.split(prefix, 1)[1].split('"#;', 1)[0]


def expected_environment(scratch, original, enrollment):
    base = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
    expected = {"PATH": ":".join([enrollment["environment"]["LEGION_PHP_RUBY_SDK_BIN_DIR"],str(absolute(enrollment["tools"]["php"]["path"]).parent),str(absolute(enrollment["tools"]["ruby"]["path"]).parent),"/usr/bin","/bin"]), "HOME": str(original.parent.parent / "home")}
    for name,rel in (("TMPDIR","tmp"),("TEMP","tmp"),("TMP","tmp"),("XDG_CACHE_HOME","cache/xdg"),("CARGO_TARGET_DIR","cache/cargo-target"),("npm_config_cache","cache/npm"),("RUFF_CACHE_DIR","cache/ruff"),("MYPY_CACHE_DIR","cache/mypy"),("PYTHONPYCACHEPREFIX","cache/pycache"),("GOCACHE","cache/go-build")):
        expected[name]=str(scratch/rel)
    expected.update(PYTHONNOUSERSITE="1",GIT_CONFIG_NOSYSTEM="1",PYTHONDONTWRITEBYTECODE="1",NO_COLOR="1",CARGO_NET_OFFLINE="true",CARGO_TERM_COLOR="never")
    return expected, sorted(base|set(expected))

def compact(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()

def frozen_inputs(policy,files,scratch,enrollment):
    base=scratch/"tmp/php-ruby-sdk"; stage=base/"source";home=base/"home";output=base/"output";repo=base/"repository"
    feed=enrollment["advisory"]["path"]
    metadata={"packages":{},"metadata-url":"p2/%package%.json","available-packages":enrollment["advisory"]["packages"],"security-advisories":{"metadata":False,"api-url":"file://"+feed}}
    config={"repositories":{"packagist.org":{"type":"composer","url":"file://"+str(repo)}}}
    owned={str(repo/"packages.json"):digest(compact(metadata)),str(home/"config.json"):digest(compact(config)),feed:enrollment["advisory"]["digest"]}
    return {"typeSuppressionUnsupported":False,"schema":"legion-php-ruby-inputs/1","root":policy["originalRoot"],"stage":str(stage),"sources":{p:digest(files[p].encode()) for p in sorted(files)},"selectedPhp":sorted(p for p in files if p.endswith(".php")),"ownedFiles":dict(sorted(owned.items())),"enrollment":{"path":enrollment["environment"]["LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON"],"digest":policy["enrollmentDigest"]},"advisoryCovered":True,"lockedPackages":["symfony/process"],"output":str(output)}

def command_definitions(root,policy,files,scratch,enrollment):
    original=absolute(policy["originalRoot"]);base_env,base_allow=expected_environment(scratch,original,enrollment)
    prefix=["-f",policy["profile"]["path"],"--"];commands=[];timeout=5000 if original.parent.name.endswith("-timeout") else 120000
    def add(task,tool,cwd,args,probe,accepted,env,allow,kind=None):
        commands.append({"task":task,"tool":tool,"cwd":str(cwd),"args":prefix+[enrollment["tools"][tool]["path"]]+args,"versionArgs":prefix+[enrollment["tools"][tool]["path"]]+probe,"acceptedExitCodes":accepted,"environment":env,"environmentAllowlist":allow,"timeoutMs":timeout,"kind":kind})
    ruby_cwd=scratch/"tmp/ruby-lint"
    for n,_ in enumerate(sorted(p for p in files if p.endswith(".rb"))):
        env=dict(base_env,HOME=str(ruby_cwd),USERPROFILE=str(ruby_cwd),XDG_CONFIG_HOME=str(ruby_cwd),RUBOCOP_OPTS="",RUBYOPT="",RUBYLIB="",GEM_HOME=enrollment["gemRoot"],GEM_PATH=enrollment["gemRoot"])
        add("ruby-lint","rubocop",ruby_cwd,["--config",str(ruby_cwd/"audit.yml"),"--format","json","--lint","--no-server","--no-parallel","--no-color","--ignore-parent-exclusion","--ignore-disable-comments","--raise-cop-error","--fail-level","info","--",str(ruby_cwd/("source-"+str(n)+".rb"))],["--no-server","--version"],[0,1],env,sorted(set(base_allow)|set(env)))
    inputs=frozen_inputs(policy,files,scratch,enrollment);base=scratch/"tmp/php-ruby-sdk";stage=base/"source";home=base/"home";output=base/"output"
    env=dict(base_env,LEGION_PHP_RUBY_FROZEN_INPUTS=str(base/"inputs.json"),LEGION_PHP_RUBY_FROZEN_DIGEST=digest(compact(inputs)),HOME=str(home),COMPOSER_HOME=str(home),COMPOSER_CACHE_DIR=str(output/"composer-cache"),COMPOSER_DISABLE_NETWORK="1",COMPOSER_NO_INTERACTION="1",GEM_HOME=enrollment["gemRoot"],GEM_PATH=enrollment["gemRoot"],BUNDLE_GEMFILE=str(stage/"Gemfile"),BUNDLE_FROZEN="true",BUNDLE_DISABLE_VERSION_CHECK="true",BUNDLE_USER_HOME=str(output/"bundle"),RUBYOPT="",RUBYLIB="")
    phar=lambda n:["-n",enrollment["assets"][n]["path"]]
    report=str(output/"phpunit.xml")
    specs=[("package","php","composer-validate",phar("composer")+["--no-plugins","--no-scripts","validate","--strict","--no-check-publish"],phar("composer")+["--version"],[0]),
        ("type","php","phpstan",phar("phpstan")+["analyse","--error-format=json","--no-progress","--no-interaction","--debug","--level=max","--memory-limit=1G","--autoload-file",enrollment["assets"]["phpunit"]["path"],"--"]+[str(stage/p) for p in sorted(files) if p.endswith(".php")],phar("phpstan")+["--version"],[0,1]),
        ("test","php","phpunit",phar("phpunit")+["--colors=never","--no-output","--do-not-record-test-run-history","--do-not-cache-test-index","--fail-on-empty-test-suite","--fail-on-risky","--fail-on-warning","--fail-on-notice","--fail-on-deprecation","--log-junit",report],phar("phpunit")+["--version"],[0]),
        ("test","php","phpunit-report",["-n","-r",literal(root,"engine/crates/legion-audit/src/native_providers/code/php_ruby_commands.rs","JUNIT_CHECK"),report],["--version"],[0]),
        ("test","ruby","rake",[enrollment["tools"]["bundle"]["path"],"exec","rake","test"],["--version"],[0]),
        ("security","php","composer-audit",phar("composer")+["--no-plugins","--no-scripts","audit","--locked","--format=json","--no-interaction"],phar("composer")+["--version"],[0,1])]
    for task,tool,kind,args,probe,accepted in specs:
        merged=dict(env,LEGION_PHP_RUBY_COMMAND=kind);add(task,tool,stage,args,probe,accepted,merged,sorted(set(base_allow)|set(merged)),kind)
    for n,path in enumerate(sorted(p for p in files if p.endswith((".php",".rb")) and not(original.parent.name.endswith("-source-drift") and p=="app.php"))):
        php=path.endswith(".php");tool="php" if php else "ruby";staged=str(scratch/("tmp/native-syntax-"+str(n)+(".php" if php else ".rb")))
        args=["-n","-l",staged] if php else ["--disable-gems","-rripper","-e","unless Ripper.sexp(File.read(ARGV.fetch(0))); STDERR.puts 'Ruby syntax error'; exit 1; end; puts 'Syntax OK'",staged]
        add("lint" if php else "ruby-syntax",tool,original,args,["--version"],[0,1,2,255],base_env,base_allow)
    same(policy["commands"],commands,"source-owned complete PHP/Ruby argv/env/probe contract differs")
    return commands,inputs

def sdk(item, policy, control, plan, scratch, enrollment, commands, live):
    keys(item, ("request", "executionReceipt", "stdout", "stderr"))
    req, r = item["request"], item["executionReceipt"]
    keys(r, RECEIPT_FIELDS)
    keys(req, ("schemaVersion", "requestId", "providerId", "planId", "policyId", "taskId", "executable", "args", "cwd", "origin", "shell", "expectedDigest", "acceptedExitCodes", "versionArgs", "skipVersionProbe", "versionRequirement", "environment", "environmentAllowlist", "sensitiveArgumentIndexes", "sensitiveEnvironmentNames", "requiresNetworkSandbox", "sandbox", "timeoutMs", "stdoutLimit", "stderrLimit"))
    task = req["taskId"]
    require(task in TASKS and re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"] or ""), "actual SDK identity differs")
    matching=[c for c in commands if c["task"]==task and c["args"]==req["args"]]
    require(len(matching)==1,"SDK command outside exact source-owned contract")
    command=matching[0];tool=command["tool"]
    expected=dict(req,schemaVersion=1,providerId=PROVIDER,planId=plan,policyId="audit",executable=policy["wrapper"]["path"],args=command["args"],cwd=command["cwd"],origin="TargetProject",shell=False,expectedDigest=policy["wrapper"]["digest"],acceptedExitCodes=command["acceptedExitCodes"],versionArgs=command["versionArgs"],skipVersionProbe=False,versionRequirement=None,environment=command["environment"],environmentAllowlist=command["environmentAllowlist"],sensitiveArgumentIndexes=[],sensitiveEnvironmentNames=[],requiresNetworkSandbox=True,sandbox=None if control=="absent-sandbox" else {"id":policy["profile"]["receiptId"],"network":True,"filesystemScope":policy["originalRoot"]},timeoutMs=command["timeoutMs"],stdoutLimit=33554432,stderrLimit=33554432)
    same(req, expected, "actual SDK argv/cwd/env/digest/sandbox/bounds changed")
    require(r["schemaVersion"] == 1 and r["requestId"] == req["requestId"] and r["receiptId"] == "receipt:" + req["requestId"] and r["providerId"] == PROVIDER and r["planId"] == plan and r["taskId"] == task and r["cwd"] == req["cwd"], "SDK receipt request binding differs")
    same(r["command"], {"executable": req["executable"], "args": req["args"], "environmentNames": sorted(req["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "SDK launched command differs")
    same(r["environmentNames"], sorted(req["environment"]), "SDK launched environment differs")
    p = r["policy"]
    keys(p, ("id", "version", "digest", "allowed", "reason"))
    require(r["policyId"] == p["id"] and p["version"] == 1, "SDK actual policy identity differs")
    rejected, absent = control == "rejected-admission", control == "absent-sandbox"
    if rejected:
        same(p, {"id": "audit-native-owner-admission-v1", "version": 1, "allowed": False, "reason": "native-owner-admission-unavailable", "digest": digest(encoded({"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}))}, "actual production owner admission denial missing")
    else:
        same(p, {"id": POLICY, "version": 1, "allowed": True, "reason": "exact constructed PHP/Ruby SDK fixture request", "digest": digest(encoded(policy))}, "constructed exact SDK admission binding differs")
    same(r["parser"], {"attempted": False, "succeeded": False, "error": None}, "raw SDK receipt reinterpreted")
    same(r["sandbox"], {"required": True, "receiptId": None if absent else policy["profile"]["receiptId"], "networkEnabled": not absent}, "SDK sandbox receipt differs")
    keys(r["timing"], ("startedAtMs", "completedAtMs", "durationMs"))
    require(all(type(v) is int and v >= 0 for v in r["timing"].values()), "SDK timing malformed")
    if rejected or absent:
        require(r["state"] == ("unauthorized_effect" if rejected else "sandbox_missing") and r["complete"] is False and r["exitCode"] is r["signal"] is None and r["gaps"], "actual SDK refusal became execution/clean")
        if rejected:require(r["executable"] is None,"owner-admission refusal resolved an executable")
        else:
            # The executor seals the wrapper identity before it reports the missing sandbox, but never probes or runs it.
            e=r["executable"];require(isinstance(e,dict) and e["canonicalPath"] == e["requestedPath"] == policy["wrapper"]["path"] and e["digest"] == policy["wrapper"]["digest"] and e["digestState"] == "sealed" and e["version"]["exitCode"] is None and e["version"]["output"] is None,"missing-sandbox refusal executable identity differs")
        same(r["processTree"], {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "SDK refusal launched process")
        same(r["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "SDK refusal launched timed process")
    else:
        e = r["executable"]
        require(e["canonicalPath"] == e["requestedPath"] == policy["wrapper"]["path"] and e["digest"] == policy["wrapper"]["digest"] and e["digestState"] == "sealed", "SDK wrapper identity differs")
        version = e["version"]
        require(version["args"] == command["versionArgs"] and version["skippedByPolicy"] is False, "actual tool probe bypassed")
        wanted=enrollment["assets"]["composer" if command["kind"] in ("composer-audit","composer-validate") else "phpstan" if command["kind"]=="phpstan" else "phpunit"]["version"] if command["kind"] in ("composer-audit","composer-validate","phpstan","phpunit") else enrollment["tools"][tool]["version"]
        require(version["qualified"] is True and version["exitCode"]==0 and re.search(r"(?<![0-9.])"+re.escape(wanted)+r"(?![0-9.])",version["output"] or ""),"actual pinned tool probe unproven")
        special=command["kind"]=="rake" and control in ("timeout","cancel")
        good=r["exitCode"] in req["acceptedExitCodes"] and not special
        require(r["state"]==("timeout" if control=="timeout" else "cancelled") if special else r["state"]==("completed" if good else "failed"),"actual process failure/lifecycle state changed")
        require(r["complete"] is good,"failure became complete")
        tree=r["processTree"]
        require(tree["started"] is tree["terminated"] is tree["reaped"] is True,"native lifecycle incomplete")
        if not special:require(tree["hardKilled"] is False and r["signal"] is None,"unexpected process termination")
        require(r["timing"]["startedAtMs"]>0 and r["timing"]["completedAtMs"]>=r["timing"]["startedAtMs"] and r["timing"]["durationMs"]==r["timing"]["completedAtMs"]-r["timing"]["startedAtMs"],"native timing inconsistent")
    out = artifact(r["stdout"], item["stdout"], scratch, live)
    err = artifact(r["stderr"], item["stderr"], scratch, live)
    return out, err

def mutations(case, scratch, live):
    controls = case.get("requestMutationControls")
    require(isinstance(controls, list) and [c["mutatedField"] for c in controls] == ["args", "cwd", "executable", "planId"], "four same-policy request mutation controls required")
    source = next(r["request"] for r in case["sdkExecutions"] if r["request"]["taskId"] == "package")
    policy = case["policyDefinition"]
    for c in controls:
        field = c["mutatedField"]
        keys(c, ("control", "scope", "qualificationEligible", "sourceRequest", "baselineRequest", "mutatedField", "policyDefinition", "policyDecisions", "sdkExecutions", "matched"))
        require(c["control"] == "request-mutation-" + field and c["scope"] == "sdk-exact-policy-boundary" and c["qualificationEligible"] is False and c["matched"] is True, "mutation identity/status differs")
        same(c["sourceRequest"], source, "mutation source is not original successful request")
        same(c["policyDefinition"], policy, "mutation changed authorizer definition")
        baseline = dict(source, requestId="legion-audit/" + digest((source["requestId"] + ":mutation:" + field).encode())[7:])
        same(c["baselineRequest"], baseline, "mutation changed admitted baseline")
        wanted = dict(baseline)
        wanted[field] = baseline["args"] + ["--outside-fixture-command"] if field == "args" else str(absolute(policy["originalRoot"]).parent) if field == "cwd" else policy["toolIdentities"]["php"][0] if field == "executable" else "different-frozen-plan"
        require(len(c["sdkExecutions"]) == 1, "mutation must retain one actual refusal")
        row = c["sdkExecutions"][0]
        same(row["request"], wanted, "mutation did not change exactly one bound field")
        same(c["policyDecisions"], [{"requestId": wanted["requestId"], "taskId": wanted["taskId"], "allowed": False, "request": wanted}], "same scoped policy did not refuse mutation")
        r = row["executionReceipt"]
        keys(r, RECEIPT_FIELDS)
        require(r["schemaVersion"] == 1 and r["receiptId"] == "receipt:" + wanted["requestId"] and r["requestId"] == wanted["requestId"] and r["providerId"] == PROVIDER and r["planId"] == wanted["planId"] and r["taskId"] == "package" and r["cwd"] == wanted["cwd"] and r["policyId"] == POLICY and r["state"] == "unauthorized_effect" and r["complete"] is False and r["executable"] is r["exitCode"] is r["signal"] is r["stdout"] is r["stderr"] is row["stdout"] is row["stderr"] is None and r["gaps"], "mutation refusal launched process or invented receipt")
        same(r["policy"], {"id": POLICY, "version": 1, "digest": digest(encoded(policy)), "allowed": False, "reason": "outside exact constructed PHP/Ruby SDK fixture contract"}, "mutation used different policy authority")
        same(r["processTree"], {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "mutation launched process")
        same(r["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "mutation launched timed process")
        same(r["parser"], {"attempted": False, "succeeded": False, "error": None}, "mutation invoked parser")
        same(r["command"], {"executable": wanted["executable"], "args": wanted["args"], "environmentNames": sorted(wanted["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "mutation original command lost")
        same(r["environmentNames"], sorted(wanted["environment"]), "mutation environment changed")
        same(r["sandbox"], {"required": True, "receiptId": wanted["sandbox"]["id"], "networkEnabled": True}, "mutation sandbox changed")
        if live: same(parsed(Path(scratch, "mutations", field, "sdk-execution-0.json").read_bytes()), row, "actual mutation evidence changed")


def observation(enrollment):
    return {name:{"schema":"legion-php-ruby-sdk-runtime-observation/1","runtimeDigest":enrollment["runtime"][name]["digest"],"fileCount":len(enrollment["runtime"][name]["files"]),"linkCount":len(enrollment["runtime"][name]["links"]),"absentCount":len(enrollment["runtime"][name]["absent"])} for name in ("php","ruby")}

def validate_case(root,case,enrollment,live):
    control=case["control"];fields={"caseId","control","provider","scope","fixtureFiles","fixtureSources","inventory","planDigest","frozenProvider","nativeResult","policyDefinition","policyDecisions","sdkExecutions","runtimeBefore","runtimeAfter","junitReport","matched"}
    if control=="nonempty-clean":fields.add("requestMutationControls")
    keys(case,fields)
    require(control in CONTROLS and case["caseId"]=="code-php-ruby-"+control and case["provider"]==PROVIDER and case["matched"] is True and case["scope"]==("sdk-boundary-control" if control=="absent-sandbox" else "native-provider-known-answer-fixture"),"case identity/status differs")
    files=fixture(root,control);hashes={p:digest(t.encode()) for p,t in files.items()};same(case["fixtureFiles"],files,"original source fixture changed");same(case["fixtureSources"],hashes,"fixture frozen hashes changed")
    inv=case["inventory"];entries=[{"path":p,"symbols":[],"dependencies":["minitest","rake"] if p=="Gemfile" else [],"packageScripts":[],"sourceFile":p.endswith((".php",".rb")),"digest":hashes[p]} for p in sorted(files)]
    # Replay exact source-owned inventory; preserve every frozen source/config/lock.
    require([e["path"] for e in inv["entries"]]==[e["path"] for e in entries],"frozen inventory dropped source/config/lock siblings")
    for observed,expected in zip(inv["entries"],entries):
        require(observed["digest"]==expected["digest"] and observed["sourceFile"]==expected["sourceFile"] and observed["symbols"]==[] and observed["packageScripts"]==[],"inventory file identity differs")
        require(observed["dependencies"]==expected["dependencies"],"source-owned Gemfile dependency context differs")
    same(inv["entries"],entries,"source-owned frozen inventory differs")
    require(inv["schemaVersion"]==1 and inv["repositoryId"]==case["caseId"] and inv["generation"]=="filesystem:"+digest(encoded(entries)) and inv["digest"]==digest(encoded([1,case["caseId"],inv["generation"],entries])),"inventory identity differs")
    spec=next(s for s in parsed(source_file(root,"src/registry/providers.json").read_bytes())["providers"] if s["id"]==PROVIDER);frozen=case["frozenProvider"]
    require(is_digest(case["planDigest"]) and frozen["id"]==PROVIDER and frozen["version"]==spec["providerVersion"] and frozen["configuration"]["denominatorCount"]==len(entries) and (frozen["configuration"]["denominatorDigest"]==inv["digest"] if spec["selector"]=={"op":"always"} else frozen["configuration"]["denominatorDigest"]==digest(encoded([inv["digest"],spec["selector"],entries]))),"original selected-scope denominator changed")
    policy=case["policyDefinition"];keys(policy,("id","version","scope","provider","planDigest","originalRoot","frozenInputs","toolIdentities","runtimeDigests","enrollmentDigest","wrapper","profile","commands","absentSandboxControl","stdoutLimit","stderrLimit"))
    original=absolute(policy["originalRoot"]);scratch=absolute(policy["profile"]["path"]).parent.parent
    require(original.name=="source" and original.parent.name==case["caseId"] and scratch.name==case["caseId"] and scratch.parent.name=="cases" and not(original==scratch or original in scratch.parents or scratch in original.parents),"original/private scratch boundary changed")
    require(policy["id"]==POLICY and policy["version"]==1 and policy["provider"]==PROVIDER and policy["planDigest"]==case["planDigest"] and policy["scope"]=="exact constructed PHP/Ruby SDK fixtures; no production owner admission" and policy["absentSandboxControl"] is (control=="absent-sandbox") and policy["stdoutLimit"]==policy["stderrLimit"]==33554432,"constructed scope/bounds differ")
    same(policy["frozenInputs"],hashes,"policy bound different source")
    identities={name:[enrollment[section][name]["path"],enrollment[section][name]["digest"]] for section,names in (("tools",("php","ruby","bundle","rubocop")),("assets",("composer","phpstan","phpunit"))) for name in names};same(policy["toolIdentities"],identities,"tool/asset closure differs")
    same(policy["runtimeDigests"],{n:enrollment["runtime"][n]["digest"] for n in ("php","ruby")},"closed runtime identity differs")
    require(is_digest(policy["enrollmentDigest"]),"enrollment identity malformed")
    require(policy["wrapper"]["path"]=="/usr/bin/sandbox-exec" and is_digest(policy["wrapper"]["digest"]),"sandbox wrapper identity missing")
    if live:require(digest(Path(policy["wrapper"]["path"]).read_bytes())==policy["wrapper"]["digest"],"live sandbox wrapper drift")
    escaped=str(original).replace('\\','\\\\').replace('"','\\"');text='(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "'+escaped+'"))\n(deny file-write* (subpath "'+escaped+'"))\n';sha=digest(text.encode())[7:]
    same(policy["profile"],{"path":str(scratch/"sandbox"/("audit-"+sha+".sb")),"text":text,"receiptId":"sandbox:macos:"+sha},"network/project-write sandbox boundary changed")
    commands,inputs=command_definitions(root,policy,files,scratch,enrollment)
    same(case["runtimeBefore"],observation(enrollment),"runtime before missing");same(case["runtimeAfter"],observation(enrollment),"runtime drift hidden")
    chosen=[] if control in ("missing-tool","disabled-sandbox") else [commands[0]] if control=="absent-sandbox" else commands[:2]+commands[8:] if control in ("malformed-manifest","malformed-lock") else commands[:2]+commands[8:] if control=="source-drift" else commands
    rows=case["sdkExecutions"];same([r["request"]["args"] for r in rows],[c["args"] for c in chosen],"required actual requests omitted/reordered")
    require(len({r["request"]["requestId"] for r in rows})==len(rows),"duplicate actual SDK identity")
    streams=[sdk(row,policy,control,case["planDigest"],scratch,enrollment,commands,live) for row in rows]
    if live:
        for n,row in enumerate(rows):same(parsed((Path(scratch)/("sdk-execution-"+str(n)+".json")).read_bytes()),row,"original SDK bytes changed")
    decisions=[] if control=="rejected-admission" else [{"requestId":r["request"]["requestId"],"taskId":r["request"]["taskId"],"allowed":True,"request":r["request"]} for r in rows]
    same(case["policyDecisions"],decisions,"actual authorizer decision differs")
    native=case["nativeResult"]
    if control=="absent-sandbox":require(native is None,"SDK refusal invented provider report")
    else:
        full=control in ("nonempty-clean","ruby-lint-positive","type-positive","security-positive")
        require(native["provider"]==PROVIDER and native["applicable"] is True and native["complete"] is False and native["coverage"]["expected"]==len(entries) and native["coverage_gaps"],"runtime gaps or denominator narrowed")
        if full:
            require(native["coverage"]["examined"]==4 and native["coverage_gaps"]==["code.php-ruby:selection-narrower-than-denominator:4of10"],"honest source selection gap changed")
        producer=native["details"]["nativeProducer"];same(producer["deferredCommands"],[],"required commands deferred")
        receipts=producer["toolReceipts"];bound=[r for r in receipts if "sdkReceipt" in r]
        def without_policy_annotation(receipt):
            # The engine annotates owner-admission refusals with the execution policy it denied under;
            # the annotation must be internally bound to the receipt's policy before it is set aside.
            if receipt.get("state")!="unauthorized_effect":return receipt
            pol=receipt["policy"]
            require(digest(encoded(receipt["executionPolicy"]))==pol["digest"]
                    and receipt["executionPolicyIdentity"]=={k:pol[k] for k in ("id","version","digest")},"refusal execution policy annotation differs")
            return {k:v for k,v in receipt.items() if k not in ("executionPolicy","executionPolicyIdentity")}
        same([without_policy_annotation(r["sdkReceipt"]) for r in bound],[r["executionReceipt"] for r in rows],"original SDK receipts omitted/reissued/reinterpreted")
        boundary=[r for r in receipts if r.get("kind")=="php-ruby-native-enrollment-boundary"];require(len(boundary)==1 and boundary[0]["before"]==boundary[0]["after"] and boundary[0]["beforeError"] is boundary[0]["afterError"] is None,"full native runtime boundary missing/changed")
        for receipt in bound:
            if "nativeInputSnapshots" in receipt:
                same(receipt["nativeInputSnapshots"],{"before":{"bindingDigest":digest(compact(inputs)),"inputs":inputs},"after":{"bindingDigest":digest(compact(inputs)),"inputs":inputs},"afterError":None,"unchanged":True},"original/staged/config/feed source drift hidden")
        find=native["details"]["findingEvidence"]
        bykind={c["kind"]:(row,stream) for c,row,stream in zip(chosen,rows,streams) if c["kind"]}
        if full:
            require(all(r["executionReceipt"]["state"]=="completed" and r["executionReceipt"]["complete"] is True for r in rows),"positive/clean control contains process failure")
            phpstan=bykind["phpstan"][1][0].decode();offset=phpstan.index('{');same(sorted(x for x in phpstan[:offset].splitlines() if x.strip()),[str(scratch/"tmp/php-ruby-sdk/source"/p) for p in sorted(files) if p.endswith('.php')],"actual PHPStan source denominator missing")
            typed=parsed(phpstan[offset:].encode());require(typed["totals"]["errors"]==0 and typed["errors"]==[],"actual PHPStan operation failed")
            if control=="type-positive":require(any(m.get("identifier")=="return.type" for f in typed["files"].values() for m in f["messages"]),"actual planted type detection missing")
            else:require(typed["totals"]["file_errors"]==0 and typed["files"] in ({},[]),"unexpected type findings")
            junit=parsed(bykind["phpunit-report"][1][0]);require(junit["schema"]=="legion-phpunit-assertions/1" and type(junit["tests"]) is int and junit["tests"]>0 and type(junit["assertions"]) is int and junit["assertions"]>0,"actual nonzero PHP assertions absent")
            require(re.search(rb'(?m)^1 runs, 1 assertions, 0 failures, 0 errors, 0 skips\r?$',bykind["rake"][1][0]),"actual Ruby assertions absent")
            security=parsed(bykind["composer-audit"][1][0]);advisories=security["advisories"]
            if control=="security-positive":require({r["advisoryId"] for r in advisories["symfony/process"]}=={"PKSA-rkkf-636k-qjb3","PKSA-wws7-mr54-jsny"},"genuine affected lock advisory output missing")
            else:require(advisories in ({},[]),"unaffected genuine version emitted findings")
            if control=="nonempty-clean":require(find=={} and all(r["executionReceipt"]["exitCode"]==0 for r in rows),"nonempty clean contains finding/failure")
            elif control=="ruby-lint-positive":require(any(f["ruleId"]=="rubocop:Lint/UselessAssignment" and f["path"]=="lib/answer.rb" for f in find.values()),"planted Ruby identity lost")
            elif control=="type-positive":require(any(f["ruleId"]=="phpstan:return.type" and f["path"]=="app.php" for f in find.values()),"planted type identity lost")
            else:require(all(any(f["ruleId"]=="composer-audit:"+id and f["path"]=="composer.lock" for f in find.values()) for id in ("PKSA-rkkf-636k-qjb3","PKSA-wws7-mr54-jsny")),"lock-context advisory finding lost")
        if control=="php-lint-positive":require(any(c["task"]=="lint" and r["executionReceipt"]["exitCode"]!=0 for c,r in zip(chosen,rows)) and any(f["path"]=="app.php" for f in find.values()),"actual syntax detection absent")
        if control in ("php-test-failure","ruby-test-failure"):
            row,streams_failed=bykind["phpunit" if control=="php-test-failure" else "rake"];require(row["executionReceipt"]["state"]=="failed" and row["executionReceipt"]["exitCode"]!=0,"actual failed assertion not retained")
            if control=="ruby-test-failure":require(re.search(rb"(?m)^1 runs, 1 assertions, 1 failures, 0 errors, 0 skips\r?$",streams_failed[0]),"actual Ruby failed assertion summary missing")
        if control in ("timeout","cancel"):
            row,lifecycle_streams=bykind["rake"];require(b"LEGION_PHP_RUBY_LIFECYCLE_TEST_STARTED" in lifecycle_streams[1],"lifecycle fixture body never started");require(row["executionReceipt"]["state"]==("timeout" if control=="timeout" else "cancelled") and row["executionReceipt"]["processTree"]["reaped"] is True,"actual bounded lifecycle control absent")
        gaps=json.dumps(native["coverage_gaps"])
        if control.startswith("malformed-"):require(("php-ruby-composer-manifest-json" if control=="malformed-manifest" else "php-ruby-composer-lock-json") in gaps,"malformed config/lock gap hidden")
        if control=="disabled-sandbox":require("php-ruby-project-code-requires-authenticated-sandbox" in gaps and not rows,"disabled sandbox submitted an SDK request")
        if control=="missing-tool":require("tool-missing" in gaps,"missing tools became clean")
        if control=="source-drift":require("php-ruby-source-changed" in gaps,"frozen source drift gap hidden")
    full=control in ("nonempty-clean","ruby-lint-positive","type-positive","security-positive")
    report=case["junitReport"]
    if report is not None:
        keys(report,("path","digest","bytes","rawBytes"));raw=bytes(report["rawBytes"]);require(report["digest"]==digest(raw) and report["bytes"]==len(raw) and report["path"]==str(scratch/"tmp/php-ruby-sdk/output/phpunit.xml"),"original JUnit raw bytes changed")
        require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,"unsafe JUnit source")
        import xml.etree.ElementTree as ET
        xml=ET.fromstring(raw);tests=xml.findall('.//testcase');require(control=="php-lint-positive" or (len(tests)>0 and sum(int(t.get('assertions','0')) for t in xml.findall('./testsuite'))>0),"real nonempty assertion report missing")
        if control=="php-test-failure":require(any(t.find('failure') is not None for t in tests),"actual failed PHP assertion absent")
        if full:require(junit["reportDigest"]==digest(raw),"actual assertion checker didn't bind original report")
        if live:same(Path(report["path"]).read_bytes(),raw,"live JUnit raw bytes differ")
    elif control in ("nonempty-clean","ruby-lint-positive","type-positive","security-positive","php-test-failure","ruby-test-failure","timeout","cancel"):require(False,"mandatory actual JUnit report absent")
    if control=="nonempty-clean":mutations(case,scratch,live)
    return {case["caseId"]+"/"+p:d for p,d in hashes.items()}

def retained_enrollment(root, record, path, live):
    raw = Path(path).read_bytes()
    same(record["enrollment"], {"file": "php-ruby-sdk-enrollment.json", "digest": digest(raw), "bytes": len(raw)}, "original enrollment bytes differ")
    value = parsed(raw)
    bootstrap_path = source_file(root, BOOTSTRAP)
    bootstrap = runpy.run_path(str(bootstrap_path))
    bootstrap["verify_enrollment"](root, value, live=live)
    return value

def validate_record(repository_root, row, live=False, enrollment=None):
    root = Path(repository_root).resolve()
    keys(row, ("schema", "kind", "provider", "providerVersion", "productionQualification", "qualificationEligible", "claimScope", "executionPath", "modelCalls", "admissionScope", "advisoryScope", "binding", "requiredContract", "executedScope", "enrollment", "runtimeBefore", "runtimeAfter", "cases", "missingControls", "metrics", "status", "qualificationDigest"))
    require(row["schema"] == "legion-php-ruby-code-command-sdk-accuracy/1" and row["kind"] == "php-ruby-code-command-sdk-constructed" and row["provider"] == PROVIDER and row["productionQualification"] is False and row["qualificationEligible"] is True and row["claimScope"] == "known-answer-fixture-cases" and row["executionPath"] == "native-sdk-frozen-plan-self-sourced-code" and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and row["admissionScope"] == "explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial; no production owner-admission claim", "PHP/Ruby bounded SDK identity/scope differs")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "original qualification digest differs")
    require(row["advisoryScope"] == "untouched official captured symfony/process query; affected and unaffected genuine locked versions; no full/current database claim", "captured advisory query scope changed")
    contract = required_contract(root, PROVIDER)
    contract.pop("coverageRequirement")
    same(contract, {"tools":["package","lint","ruby-lint","type","test","security"],"extensions":["php","rb"],"variants":[["php",["php"]],["ruby",["rb"]]],"requiredContext":[]}, "source PHP/Ruby contract changed; do not narrow")
    same(row["requiredContract"], contract, "original tool/context contract narrowed")
    same(row["executedScope"], contract["tools"], "required tool execution scope missing")
    spec = next(s for s in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if s["id"] == PROVIDER)
    spec = {k: v for k, v in spec.items() if k != "benchmark"}
    require(row["providerVersion"] == spec["providerVersion"], "provider version stale")
    binding = row["binding"]
    keys(binding, ("providerSpec", "providerSpecDigest", "sources", "sourcesDigest", "fixtureSources", "fixtureSourcesDigest", "fixture"))
    sources = {p: digest(source_file(root, p).read_bytes()) for p in source_files(root)}
    same(binding["providerSpec"], spec, "source provider registration differs")
    same(binding["sources"], sources, "production/SDK/fixture/bootstrap source closure differs")
    require(binding["providerSpecDigest"] == digest(encoded(spec)) and binding["sourcesDigest"] == digest(encoded(sources)) and binding["fixture"] == HARNESS, "source closure digest differs")
    require(enrollment is not None, "actual retained managed PHP/Ruby/tool enrollment required")
    require([c["control"] for c in row["cases"]] == list(CONTROLS), "required control corpus missing/reordered")
    fixtures = {}
    for c in row["cases"]:
        require(c["policyDefinition"]["enrollmentDigest"]==row["enrollment"]["digest"],"policy original enrollment bytes mismatch")
        fixtures.update(validate_case(root,c,enrollment,live))
    same(binding["fixtureSources"], fixtures, "full fixture denominator differs")
    require(binding["fixtureSourcesDigest"] == digest(encoded(fixtures)), "fixture corpus digest differs")
    same(row["runtimeBefore"], observation(enrollment), "runtime before evidence differs")
    same(row["runtimeAfter"], observation(enrollment), "runtime after evidence differs")
    same(row["missingControls"], [], "mandatory qualification dependency missing")
    same(row["metrics"], {"cases": len(CONTROLS), "matched": len(CONTROLS), "mismatched": 0, "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}, "bounded accuracy promoted to arbitrary-input whole-provider proof")
    require(row["status"] == "observed-known-answer-controls", "actual observation status differs")
    return {"provider": PROVIDER, "cases": len(CONTROLS), "qualificationEligible": True, "productionQualification": False, "claimScope": row["claimScope"], "modelCalls": 0}

def artifact_locator(row, raw):
    return {"schema": "legion-php-ruby-code-command-sdk-artifact/1", "provider": PROVIDER, "file": "code_php-ruby.json", "digest": digest(raw), "bytes": len(raw), "qualificationDigest": row["qualificationDigest"], "qualificationEligible": row["qualificationEligible"], "productionQualification": False}

def child_record(execution_path, stdout_path, stderr_path, record_path):
    execution = parsed(Path(execution_path).read_bytes())
    keys(execution, ("schema", "productionQualification", "status", "stdout", "stderr"))
    require(execution["schema"] == "legion-php-ruby-code-command-child-execution/1" and execution["productionQualification"] is False, "child execution identity differs")
    same(execution["status"], {"success": True, "exitCode": 0, "signal": None}, "actual child control harness failed")
    streams = []
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), "original child stream unsafe/missing")
        raw = path.read_bytes()
        same(execution[name], {"file": "child." + name + ".log", "bytes": len(raw), "sha256": digest(raw)}, "child original raw stream differs")
        streams.append(raw)
    marker = b"PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_ARTIFACT "
    locators = [parsed(line.split(marker, 1)[1]) for line in streams[0].splitlines() if marker in line]
    require(len(locators) == 1, "one exact PHP/Ruby child artifact emission required")
    path = Path(record_path)
    require(path.is_file() and not path.is_symlink(), "original PHP/Ruby record missing/unsafe")
    raw = path.read_bytes()
    row = parsed(raw)
    same(locators[0], artifact_locator(row, raw), "authenticated child locator differs from original record bytes")
    text = streams[0].decode()
    require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", text) == [("1", "0", "0")] and len(re.findall(r"\btest real_php_ruby_code_command_accuracy \.\.\.", text)) == 1, "named actual child control did not execute exactly once")
    return row

def validate_retained(root, row, paths):
    """Offline replay consumes original authenticated bytes, preserving original paths."""
    keys(paths, ("childExecution", "childStdout", "childStderr", "phpRubyEnrollment", "providerRecord"))
    observed = child_record(paths["childExecution"], paths["childStdout"], paths["childStderr"], paths["providerRecord"])
    same(observed, row, "indexed row differs from original child artifact")
    enrollment = retained_enrollment(root, row, paths["phpRubyEnrollment"], False)
    return validate_record(root, row, live=False, enrollment=enrollment)

def validate_records(root, receipts, live=True):
    root, receipts = Path(root).resolve(), Path(receipts)
    require(receipts.is_dir() and not receipts.is_symlink(), "original retained output missing/unsafe")
    require({p.name for p in receipts.glob("code_*.json")} == {"code_php-ruby.json"}, "PHP/Ruby record inventory differs")
    row = child_record(receipts / "child-execution.json", receipts / "child.stdout.log", receipts / "child.stderr.log", receipts / "code_php-ruby.json")
    enrollment = retained_enrollment(root, row, receipts / "php-ruby-sdk-enrollment.json", live)
    return {"records": [validate_record(root, row, live=live, enrollment=enrollment)], "modelCalls": 0}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--receipts", type=Path, required=True)
    args = p.parse_args()
    result = validate_records(args.root, args.receipts)
    print("PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__": main()
