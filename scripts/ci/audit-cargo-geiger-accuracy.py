#!/usr/bin/env python3
"""Validate constructed cargo-geiger SDK controls; never production admission or full RustSec coverage."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.security.rust-unsafe"
HARNESS = "engine/crates/legion-audit/tests/cargo_geiger_accuracy.rs"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/cargo-geiger"
FAMILY_SCOPE = "constructed native SDK; full SafetyReport unsafe positive/absence + compiler failure + missing-tool controls in disposable scratch; no production owner-admission claim"
POLICY = "legion-cargo-geiger-full-scan-fixture-v1"
ARGV = ["--output-format", "Json", "--quiet"]
COMMIT = "08543ac0b48ff6eec12c0a1f2478ef9c3259cd4d"
ARCHIVE = "sha256:4fbe170b23e5130aadb2ede5b169d027596dada6ad2aadf6422f50a858ce3e3b"
LOCK = "sha256:3f11d51a112555ed76faec9ab9d10cf9ae0f852582e6a3b12773aabf41f583c4"
SOURCE_ROOTS = [f"engine/crates/{crate}/src" for crate in ["legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules"]] + ["src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS] + [f"engine/crates/{crate}/Cargo.toml" for crate in ["legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules"]]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source_file(root, relative):
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and ".." not in parts.parts and "\\" not in relative, "unsafe source path")
    path = root
    for part in parts.parts:
        path /= part
        require(not path.is_symlink(), "source symlink refused")
    require(path.is_file(), f"source missing: {relative}")
    return path


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def sources(root):
    files = {}
    for relative in SOURCE_ROOTS:
        path = root / relative
        require(path.is_dir() and not path.is_symlink(), "source closure root missing")
        for item in path.rglob("*"):
            require(not item.is_symlink(), "source closure symlink")
            if item.is_file() and not generated_session_provenance(item.relative_to(root).as_posix()):
                files[item.relative_to(root).as_posix()] = digest(item.read_bytes())
    for relative in SOURCE_FILES:
        files[relative] = digest(source_file(root, relative).read_bytes())
    return files


def absolute(value):
    require(isinstance(value, str), "absolute path missing")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "noncanonical retained path")
    return path



def safety_report(row):
    require(isinstance(row,dict) and set(row) == {"packages","packages_without_metrics","used_but_not_scanned_files"}, "not full SafetyReport")
    require(isinstance(row["packages"],list) and row["packages"] and row["packages_without_metrics"] == [] and row["used_but_not_scanned_files"] == [], "unmeasured packages/files")
    ids=set()
    def package(value):
        require(isinstance(value,dict) and set(value)=={"name","version","source"} and all(isinstance(value[k],str) and value[k] for k in ["name","version"]),"malformed package identity")
        source=value["source"]
        require(isinstance(source,dict) and len(source)==1,"malformed package source")
        kind,fields=next(iter(source.items()))
        if kind=="Path": require(isinstance(fields,str) and fields.startswith("file:"),"invalid path source")
        else:
            required={"url","rev"} if kind=="Git" else {"name","url"} if kind=="Registry" else None
            require(required is not None and isinstance(fields,dict) and set(fields)==required and all(isinstance(x,str) and x for x in fields.values()),"invalid source")
    totals={"used":{"safe":0,"unsafe_":0},"unused":{"safe":0,"unsafe_":0}}
    for entry in row["packages"]:
        require(isinstance(entry,dict) and set(entry)=={"package","unsafety"},"quick/incomplete report entry")
        info=entry["package"]; require(set(info)=={"id","dependencies","dev_dependencies","build_dependencies"},"package graph incomplete")
        package(info["id"]); identity=encoded(info["id"]);require(identity not in ids,"duplicate package");ids.add(identity)
        for kind in ["dependencies","dev_dependencies","build_dependencies"]:
            require(isinstance(info[kind],list),"malformed package graph")
            for item in info[kind]: package(item)
        unsafe=entry["unsafety"];require(set(unsafe)=={"used","unused","forbids_unsafe"} and type(unsafe["forbids_unsafe"]) is bool,"incomplete UnsafeInfo")
        for block in totals:
            require(set(unsafe[block])=={"functions","exprs","item_impls","item_traits","methods"},"incomplete CounterBlock")
            for count in unsafe[block].values():
                require(isinstance(count,dict) and set(count)=={"safe","unsafe_"},"malformed Count")
                for field,n in count.items():
                    require(type(n) is int and 0<=n<=2**64-1,"non-u64 counter")
                    totals[block][field]+=n
                    require(totals[block][field]<=2**64-1,"counter overflow")
    return totals["used"]["unsafe_"]


def validate_record(repository_root,row,live=False):
    root=Path(repository_root).resolve()
    require(row.get("schema")=="legion-cargo-geiger-sdk-accuracy/1" and row.get("provider")==ID and row.get("stage")=="candidate" and row.get("scope")==FAMILY_SCOPE,"wrong constructed native identity/scope")
    require(row.get("productionQualification") is False and row.get("qualificationEligible") is True and row.get("status")=="pass" and type(row.get("modelCalls")) is int and row["modelCalls"]==0,"incomplete constructed qualification")
    require(row.get("admissionScope")=="explicit constructed SDK authorizer; no production CLI owner-admission claim","owner admission scope expanded")
    require(row["qualificationDigest"]==digest(encoded({k:v for k,v in row.items() if k!="qualificationDigest"})),"original record digest differs")
    spec=next(x for x in parsed(source_file(root,"src/registry/providers.json").read_bytes())["providers"] if x["id"]==ID)
    spec={k:v for k,v in spec.items() if k!="benchmark"}
    require(spec["execution"]["resourceClaims"]["projectExecution"]==1,"project execution incorrectly declared")
    bound=row["binding"];same(bound["providerSpec"],spec,"shipped provider differs")
    require(bound["providerSpecDigest"]==digest(encoded(spec)) and bound["fixture"]==HARNESS,"spec/harness binding differs")
    expected_sources=sources(root);same(bound["sources"],expected_sources,"source closure differs")
    require(bound["sourcesDigest"]==digest(encoded(expected_sources)),"source closure digest differs")
    upstream=parsed(source_file(root,FIXTURES+"/upstream.json").read_bytes())
    for path,expected in upstream["files"].items(): require(digest(source_file(root,FIXTURES+"/"+path).read_bytes())==expected,"pinned inspected upstream bytes differ")
    provision=row["provision"];require(provision["schema"]=="legion-cargo-geiger-ci-provision/1" and provision["sourceCommit"]==COMMIT and provision["archiveDigest"]==ARCHIVE and provision["lockDigest"]==LOCK,"source provision pin differs")
    require(provision["archiveUrl"]=="https://api.github.com/repos/geiger-rs/cargo-geiger/tarball/"+COMMIT,"source URL differs")
    source=absolute(provision["source"]);base=source.parent;toolchain=absolute(provision["toolchainBin"]);tool=absolute(provision["tool"])
    require(source==base/"source" and tool==base/"tools/bin/cargo-geiger" and absolute(provision["archivePath"])==base/"upstream.tar.gz","source build roots differ")
    build=provision["build"]
    same(build["argv"],[str(toolchain/"cargo"),"install","--debug","--locked","--path",str(source/"cargo-geiger"),"--root",str(base/"tools"),"--target-dir",str(base/"build")],"exact pinned source build differs")
    require(build["cwd"]==str(source) and build["exitCode"]==0 and build["timedOut"] is False and build["timeoutSeconds"]==1200 and all(build[k+"Digest"]==digest(build[k].encode()) for k in ["stdout","stderr"]),"actual source build completion absent")
    require(provision["sourceFiles"]["Cargo.lock"]==LOCK and all(re.fullmatch(r"sha256:[0-9a-f]{64}",v) for v in provision["sourceFiles"].values()),"source build closure absent")
    require(provision["sourceLinks"] == {"cargo-geiger/README.md":"../README.md"},"reviewed upstream source link differs")
    for path,expected in upstream["files"].items():
        if path.startswith("upstream/") and path not in ("upstream/tag.json","upstream/tree.json"):
            require(provision["sourceFiles"][path.removeprefix("upstream/")]==expected,"built source differs from inspected commit")
    for name in ["cargo","rustc"]:
        version=provision["toolchainVersions"][name]
        require(version["argv"]==[str(toolchain/name),"--version"] and version["exitCode"]==0 and version["timedOut"] is False and version["timeoutSeconds"]==1200 and version["stdout"].startswith(name+" 1.98.0 ") and all(version[k+"Digest"]==digest(version[k].encode()) for k in ["stdout","stderr"]),"actual pinned toolchain version absent")
    require(row["tool"]["version"]=="0.13.0" and row["tool"]["digest"]==provision["toolDigest"] and re.fullmatch(r"sha256:[0-9a-f]{64}",provision["toolDigest"]),"native source-built identity differs")
    if live:
        require(digest(Path(provision["archivePath"]).read_bytes())==ARCHIVE and digest(Path(tool).read_bytes())==provision["toolDigest"],"retained provision identity changed")
        for p,target in provision["sourceLinks"].items():
            link=Path(source)/p
            require(link.is_symlink() and link.readlink().as_posix()==target and link.resolve().is_relative_to(Path(source)),"retained source link differs")
        for name in ["cargo","rustc"]:require(digest((Path(toolchain)/name).read_bytes())==provision["toolchainDigests"][name],"retained toolchain changed")
        for path,expected in provision["sourceFiles"].items():require(digest(source_file(Path(source),path).read_bytes())==expected,"retained upstream source changed")
        require((Path(base)/"build.stdout.log").read_text()==build["stdout"] and (Path(base)/"build.stderr.log").read_text()==build["stderr"],"raw build logs differ")
    require([x["control"] for x in row["cases"]]==["positive","absence","process-error","missing-tool"],"native controls missing/reordered")
    fixture_hashes={}
    for case in row["cases"]:
        control=case["control"];missing=control=="missing-tool";failed=control=="process-error"
        cwd,run=absolute(case["root"]),absolute(case["run"]);retained=cwd.parent.parent
        require(cwd==retained/control/"source" and run==retained/control/"run" and retained.name=="cargo-geiger" and retained.parent.name=="legion-provider-qualification","disposable scratch roots differ")
        template="absence" if missing else control;require(case["fixtureTemplate"]==template and case["provider"]==ID and case["matched"] is True,"case identity differs")
        files={p:source_file(root,FIXTURES+"/"+template+"/"+p).read_bytes() for p in ["Cargo.toml","Cargo.lock","build.rs","src/lib.rs"]}
        hashes={p:digest(data) for p,data in files.items()};same(case["fixtureSources"],hashes,"fixture byte closure differs");same(case["sourceBefore"],hashes,"source-before differs");same(case["sourceAfter"],hashes,"source mutated")
        fixture_hashes.update({control+"/"+p:h for p,h in hashes.items()})
        entries=[{"path":p,"symbols":[],"dependencies":[],"packageScripts":[],"sourceFile":p.endswith(".rs"),"digest":hashes[p]} for p in sorted(files)]
        inv,plan,provider=case["inventory"],case["frozenPlan"],case["frozenProvider"]
        same(inv["entries"],entries,"inventory differs")
        require(inv["schemaVersion"]==1 and inv["repositoryId"]==control and inv["generation"]=="filesystem:"+digest(encoded(entries)) and inv["digest"]==digest(encoded([1,control,inv["generation"],entries])),"inventory seal differs")
        require(plan["repositoryId"]==control and plan["inventoryDigest"]==inv["digest"] and plan["inventoryGeneration"]==inv["generation"] and case["planDigest"]==digest(encoded(plan)) and case["planSignature"]=="hmac-sha256:"+hmac.new(b"constructed-cargo-geiger-fixture-key",encoded(plan),hashlib.sha256).hexdigest(),"plan seal differs")
        same(plan["providers"],[provider],"frozen provider differs")
        selected=[e for e in entries if e["path"].endswith("Cargo.toml") or e["path"].endswith(".rs")];denominator=digest(encoded([inv["digest"],spec["selector"],selected]))
        require(provider["id"]==ID and provider["version"]==spec["providerVersion"] and provider["configuration"]["denominatorDigest"]==denominator and provider["configuration"]["denominatorCount"]==len(selected),"denominator differs")
        policy,receipt,result=case["policyDefinition"],case["actualSdkReceipt"],case["nativeResult"]
        escaped=str(cwd).replace("\\","\\\\").replace('"','\\"');text=f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "{escaped}"))\n'
        profile_digest=digest(text.encode());profile=run/"sandbox"/("audit-"+profile_digest[7:]+".sb");sandbox="sandbox:macos:"+profile_digest[7:];wrapper=PurePosixPath("/usr/bin/sandbox-exec");prefix=["-f",str(profile),"--",str(tool)]
        same(policy["profile"],{"path":str(profile),"text":text,"digest":profile_digest,"receiptId":sandbox},"native deny-network sandbox differs")
        require(policy["tool"]=={"path":str(tool),"digest":provision["toolDigest"]} and policy["wrapper"]["path"]==str(wrapper) and policy["id"]==POLICY and policy["version"]==1 and policy["provider"]==ID and policy["task"]=="cargo_unsafe" and policy["plan"]==case["planDigest"] and policy["cwd"]==str(cwd) and policy["args"]==ARGV and policy["wrappedArgs"]==prefix+ARGV and policy["versionArgs"]==prefix+["--version"] and policy["acceptedExitCodes"]==[0,1,2] and policy["timeoutMs"]==120000 and policy["stdoutLimit"]==policy["stderrLimit"]==8388608 and policy["sandbox"]=="native-macos-deny-network-project-code-cargo-geiger-contract","scoped admission differs")
        cache={"TMPDIR":"tmp","TEMP":"tmp","TMP":"tmp","XDG_CACHE_HOME":"cache/xdg","CARGO_TARGET_DIR":"cache/cargo-target","npm_config_cache":"cache/npm","RUFF_CACHE_DIR":"cache/ruff","MYPY_CACHE_DIR":"cache/mypy","PYTHONPYCACHEPREFIX":"cache/pycache","GOCACHE":"cache/go-build"}
        path=[str(toolchain),"/usr/bin","/bin"] if missing else [str(tool.parent),str(toolchain),"/usr/bin","/bin"]
        env={"PATH":":".join(path),"HOME":str(retained/"home"),"PYTHONDONTWRITEBYTECODE":"1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1",**{k:str(run/v) for k,v in cache.items()}}
        same(policy["environment"],env,"scrubbed native environment differs");same(policy["environmentAllowlist"],sorted({"PATH","PATHEXT","SystemRoot","COMSPEC","HOME","USERPROFILE","PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM",*cache}),"allowlist differs")
        require(result["provider"]==ID and result["findings"]==[],"native provider differs")
        projected=result["details"]["executionReceipt"]
        for key in ["schemaVersion","receiptId","requestId","providerId","planId","policyId","policy","taskId","state","complete","command","cwd","environmentNames","sandbox","processTree","timing","exitCode","signal","parser","gaps"]:same(projected[key],receipt[key],"actual SDK projection differs: "+key)
        require(receipt["providerId"]==ID and receipt["planId"]==case["planDigest"] and receipt["taskId"]=="cargo_unsafe" and receipt["cwd"]==str(cwd),"actual SDK identity differs")
        candidates=result["details"]["candidates"]
        if missing:
            require(receipt["state"]=="missing_executable" and receipt["complete"] is False and receipt["exitCode"] is None and receipt["processTree"]["started"] is False and result["complete"] is False and result["coverage"]["examined"]==0 and result["details"]["capabilityAbsence"]["blocking"] is False and result["details"]["capabilityAbsence"]["tool"]=="cargo-geiger" and candidates==[] and case["policyDecisions"]==[] and case["projectExecutionMarkers"]=={} and case["actualToolReport"] is None,"missing tool became clean/executed")
            continue
        require(receipt["schemaVersion"]==1 and re.fullmatch(r"legion-audit/[0-9a-f]{64}",receipt["requestId"]) and receipt["receiptId"]=="receipt:"+receipt["requestId"] and receipt["policyId"]==receipt["policy"]["id"]==POLICY and receipt["policy"]["allowed"] is True and receipt["policy"]["digest"]==digest(encoded(policy)),"actual SDK admission absent")
        same(receipt["command"]["args"],prefix+ARGV,"shipped full-scan argv differs")
        version=receipt["executable"]["version"]
        require(receipt["command"]["executable"]==receipt["executable"]["canonicalPath"]==str(wrapper) and receipt["executable"]["digest"]==policy["wrapper"]["digest"] and version["args"]==prefix+["--version"] and version["output"].strip()=="cargo-geiger 0.13.0" and version["qualified"] is True and version["exitCode"]==0 and version["skippedByPolicy"] is False,"native identity/version differs")
        require(receipt["state"]=="completed" and receipt["complete"] is True and receipt["exitCode"]==(1 if failed else 0) and receipt["signal"] is None and receipt["gaps"]==[] and all(receipt["processTree"][k] is True for k in ["started","terminated","reaped"]),"actual process completion absent")
        # Source authenticator's flag proves enforcement; exact profile text
        # checked above still requires `(deny network*)` & its bound receipt ID.
        same(receipt["sandbox"],{"required":True,"receiptId":sandbox,"networkEnabled":True},"network-denied sandbox proof absent")
        require(len(case["policyDecisions"])==1,"admission count differs");decision=case["policyDecisions"][0]
        require(decision["allowed"] is True and decision["requestId"]==receipt["requestId"] and decision["providerId"]==ID and decision["planId"]==case["planDigest"] and decision["taskId"]=="cargo_unsafe" and decision["cwd"]==str(cwd) and decision["args"]==prefix+ARGV and decision["versionArgs"]==prefix+["--version"] and decision["environmentDigest"]==digest(encoded(env)) and decision["expectedDigest"]==policy["wrapper"]["digest"] and decision["acceptedExitCodes"]==[0,1,2],"actual scoped request differs")
        same(receipt["environmentNames"],sorted(env),"actual environment differs")
        for stream in ["stdout","stderr"]:
            item=receipt[stream];raw=case["actual"+stream.capitalize()];relative=PurePosixPath(item["path"])
            require(not relative.is_absolute() and ".." not in relative.parts and str(relative).startswith(receipt["requestId"]+"/") and item["raw"]==raw and item["digest"]==digest(raw.encode()) and item["bytes"]==len(raw.encode()) and item["immutable"] is True,"actual immutable stream differs")
            same({k:v for k,v in item.items() if k!="raw"},projected[stream],"projected stream differs")
            if live:require((Path(run)/"artifacts"/item["path"]).read_bytes()==raw.encode(),"retained artifact changed")
        if failed:
            require(result["complete"] is False and result["status"]=="partial" and result["coverage_gaps"] and result["details"]["findingsCount"] is None and candidates==[] and not case["actualStdout"].strip() and "LEGION_GEIGER_PROCESS_ERROR_CONTROL" in case["actualStderr"],"compiler failure became clean/findings")
        else:
            actual=parsed(case["actualStdout"]);same(case["actualToolReport"],actual,"raw full report differs");count=safety_report(actual);require(count==(1 if control=="positive" else 0),"actual unsafe positive/absence differs")
            require(result["complete"] is True and result["status"] in ["ok","complete"] and result["coverage_gaps"]==[] and result["degradation"]==[] and result["details"]["findingsCount"]==count,"native completion differs")
            coverage=result["coverage"];require(coverage["expected"]==coverage["examined"]==len(selected) and coverage["denominator_digest"]==denominator and coverage["gaps"]==[],"coverage differs")
            expected=[]
            if count:
                rule="legacy.cargo_unsafe.cargo-geiger";anchor=selected[0]["path"]
                expected=[{"id":digest(f"{rule}\0{anchor}\0{1}".encode()),"ruleId":rule,"role":"candidate-generator","claim":"cargo_unsafe reported 1 finding(s)","severityHint":"medium","evidence":[{"file":anchor,"line":1}],"evidenceStrength":"candidate","verdict":"UNADJUDICATED","adjudicationRequired":True}]
            same(candidates,expected,"aggregate native candidate differs")
            markers=case["projectExecutionMarkers"];require(markers and all(absolute(p).is_relative_to(run/"cache/cargo-target") and absolute(p).name=="geiger-project-execution-marker" and h==digest(b"LEGION_GEIGER_PROJECT_CODE_EXECUTED") for p,h in markers.items()),"actual build-script project execution proof absent")
            if live:
                for p,h in markers.items():require(digest(Path(p).read_bytes())==h,"project execution marker changed")
        if live:
            for p,data in files.items():require((Path(cwd)/p).read_bytes()==data,"disposable fixture source changed")
            require(Path(profile).read_bytes()==text.encode() and digest(Path(wrapper).read_bytes())==policy["wrapper"]["digest"],"native wrapper/profile changed")
    same(bound["fixtureSources"],fixture_hashes,"fixture corpus binding differs");require(bound["fixtureSourcesDigest"]==digest(encoded(fixture_hashes)),"corpus digest differs")
    same(row["metrics"],{"cases":4,"matched":4,"mismatched":0},"metrics differ")
    return {"provider":ID,"stage":"candidate","scope":FAMILY_SCOPE,"productionQualification":False,"qualificationDigest":row["qualificationDigest"],"positiveCases":1,"cleanCases":1,"errorCases":1,"missingToolCases":1}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--root",type=Path,required=True);parser.add_argument("--receipts",type=Path,required=True);args=parser.parse_args()
    files=list(args.receipts.glob("legacy_security_rust-unsafe.json"));require(len(files)==1,"exact real geiger receipt missing")
    summary=validate_record(args.root,parsed(files[0].read_bytes()),live=True)
    print("CARGO_GEIGER_PROVIDER_ACCURACY_SUMMARY "+json.dumps({"records":[summary],"modelCalls":0},sort_keys=True,separators=(",",":")))


if __name__=="__main__":main()
