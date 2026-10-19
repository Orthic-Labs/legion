#!/usr/bin/env python3
"""Reconcile retained real pip-audit native SDK output. Never runs scanner or network."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

PROVIDER = "legacy.security.python-dependencies"
SOURCE = "engine/crates/legion-audit/tests/pip_audit_accuracy.rs"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/pip-audit"
HELPER = "scripts/ci/provision-python-qualification-tools.py"
LOCKS = "scripts/ci/python-tool-locks"
LOCK = LOCKS + "/pip-audit-macos-arm64-cp314.json"
WHEEL = "sha256:16e02093872fac97580303f0848fa3ad64f7ecf600736ea7835a2b24de49613f"
ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src",
         "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls", FIXTURES, LOCKS]
FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-effects/Cargo.toml",
         "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml", "engine/crates/legion-rules/Cargo.toml",
         SOURCE, HELPER, "scripts/ci/audit-pip-audit-provider-accuracy.py"]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def load(path):
    return parsed(path.read_bytes())


def absolute(value):
    require(isinstance(value, str) and value.startswith("/") and ".." not in PurePosixPath(value).parts
            and str(PurePosixPath(value)) == value, "noncanonical absolute execution path")
    return PurePosixPath(value)


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def source_files(root):
    result = {}
    def walk(path):
        require(not path.is_symlink(), "symlink in source closure")
        if path.is_dir():
            for item in path.iterdir(): walk(item)
        else:
            require(path.is_file(), "missing source file")
            if not generated_session_provenance(path.relative_to(root).as_posix()):
                result[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    for relative in ROOTS + FILES: walk(root / relative)
    return result


def source_ids(raw):
    # v2.10.0 VulnerabilityResult.create + Auditor.audit: PYSEC precedes CVE,
    # then other IDs. First pass retains every PYSEC row; second pass merges aliases.
    rows = []
    for row in raw["vulnerabilities"]:
        if row.get("withdrawn") is not None: continue
        ids = [row["id"], *row["aliases"]]
        order = lambda item: 1 if item.startswith("PYSEC") else 2 if item.startswith("CVE") else 3
        primary = sorted(ids, key=order)[0]
        rows.append((primary, set(ids)))
    unique = [(primary, set(ids)) for primary, ids in rows if primary.startswith("PYSEC")]
    seen = set().union(*(ids for _, ids in unique)) if unique else set()
    for primary, ids in rows:
        if seen & ids:
            index = next(i for i, (_, existing) in enumerate(unique) if existing & ids)
            unique[index][1].update(ids)
        else:
            seen.update(ids); unique.append((primary, set(ids)))
    return sorted(primary for primary, _ in unique)


def runtime_closure(closure, live):
    require(closure.get("root") == "/", "runtime root changed")
    roots = closure.get("roots", [])
    require(roots and len(roots) == len(set(roots)), "runtime roots missing/duplicated")
    for root in roots: absolute(root)
    files, links, absent = closure.get("files"), closure.get("links"), closure.get("absent")
    require(isinstance(files, dict) and files and isinstance(links, dict), "runtime file/link closure absent")
    require(isinstance(absent, list) and absent == sorted(set(absent)), "absent loader candidates not sealed")
    for path in absent: require(isinstance(path, str) and path.startswith("/"), "relative absent loader candidate")
    require(not set(files) & set(links), "runtime file/link overlap")
    excluded = closure.get("exclusions")
    require(isinstance(excluded, list), "runtime exclusion declaration absent")
    def inside(path):
        return any(path == PurePosixPath(root) or PurePosixPath(root) in path.parents for root in roots)
    def excluded_path(path):
        return any(path == PurePosixPath(item) or PurePosixPath(item) in path.parents for item in excluded)
    for key, value in {**files, **links}.items():
        require(not key.startswith("/") and str(PurePosixPath(key)) == key and ".." not in PurePosixPath(key).parts,
                "unsafe runtime file key")
        if key in files:
            require(inside(PurePosixPath("/") / key) and is_digest(value), "runtime file outside roots/digest absent")
        else: require(isinstance(value, str) and value, "runtime link target absent")
    def resolve(path, allow_missing=False):
        pending = path.split("/")
        current, hops = [], 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."): continue
            if part == "..":
                require(bool(current), "runtime path escapes filesystem root")
                current.pop(); continue
            current.append(part)
            node = "/" + "/".join(current)
            require(not excluded_path(PurePosixPath(node)), "runtime alias enters global packages")
            relative = node[1:]
            if live:
                try: mode = Path(node).lstat().st_mode
                except FileNotFoundError:
                    require(allow_missing, "runtime path missing")
                    return None
                if stat.S_ISLNK(mode):
                    require(relative in links and str(Path(node).readlink()) == links[relative], "unsealed runtime alias hop")
            if relative in links:
                if live: require(Path(node).is_symlink(), "sealed alias is no longer a symlink")
                hops += 1; require(hops <= 40, "runtime alias cycle")
                target = links[relative]
                current.pop()
                if target.startswith("/"): current = []
                pending = target.split("/") + pending
        result = PurePosixPath("/", *current)
        if live: require(Path(path).resolve(strict=True) == Path(str(result)), "runtime alias resolution differs")
        return result
    for key in links:
        path = PurePosixPath("/") / key
        resolved = resolve(str(path))
        relative = str(resolved).lstrip("/")
        retained = relative in files or any(item.startswith(relative + "/") for item in files)
        require(retained, "runtime alias target omitted")
        require(inside(resolved) if inside(path) else inside(resolved) or retained, "runtime alias escapes closure")
    require(closure.get("digest") == sha(encoded({"absent":absent,"files":files,"links":links,"roots":roots})), "runtime closure digest differs")
    if live:
        actual_files, actual_links = {}, {}
        def walk(path):
            if str(path) in excluded: return
            if path.is_symlink(): actual_links[path.relative_to("/").as_posix()] = str(path.readlink())
            elif path.is_dir():
                for child in path.iterdir(): walk(child)
            else:
                require(path.is_file(), "runtime special file")
                actual_files[path.relative_to("/").as_posix()] = sha(path.read_bytes())
        for root in roots:
            require(Path(root).resolve(strict=True) == Path(root), "runtime root is not canonical")
            walk(Path(root))
        for key, target in links.items():
            path = Path("/") / key
            require(path.is_symlink() and str(path.readlink()) == target, "retained alias changed")
            actual_links[key] = target
        for path in absent:
            try: Path(path).lstat()
            except FileNotFoundError: pass
            else: require(False, "loader candidate appeared")
            resolve(path, allow_missing=True)
        require(actual_files == files and actual_links == links, "live runtime closure changed")


def validate_record(repository_root, record, live=False):
    root = Path(repository_root).resolve()
    require(type(live) is bool, "live flag type")
    require(record.get("schema") == "legion-pip-audit-sdk-accuracy/1", "schema differs")
    require(record.get("provider") == PROVIDER and record.get("stage") == "candidate" and record.get("status") == "pass", "provider/stage/status differs")
    require(record.get("scope") == "exact-listed-online-pins-fixture-controls", "scope differs")
    require(record.get("productionQualification") is False and record.get("selfProducerQualification") is False, "unsupported production/self-producer claim")
    require(record.get("qualificationEligible") is True and record.get("modelCalls") == 0 and record.get("coverageState") == "complete", "control coverage differs")
    require(record.get("executionPath") == "native-sdk-frozen-plan-real-pip-audit-online", "execution path differs")
    require(record.get("advisoryDatabase") == "mutable online PyPI responses; no immutable database identity claim", "database claim differs")
    unsigned = dict(record); unsigned.pop("qualificationDigest", None)
    require(record.get("qualificationDigest") == sha(encoded(unsigned)), "record digest differs")
    binding = record.get("binding", {})
    files = source_files(root)
    require(binding.get("sources") == files and binding.get("sourcesDigest") == sha(encoded(files)), "source closure changed/incomplete")
    require(binding.get("fixture") == SOURCE, "fixed harness differs")
    specs = [row for row in load(root / "src/registry/providers.json")["providers"] if row["id"] == PROVIDER]
    require(len(specs) == 1, "provider missing/duplicated")
    spec = dict(specs[0]); spec.pop("benchmark", None)
    require(record.get("providerVersion") == spec["providerVersion"], "provider version differs")
    require(binding.get("providerSpec") == spec and binding.get("providerSpecDigest") == sha(encoded(spec)), "provider spec differs")
    expectation = load(root / FIXTURES / "expected.json")
    for control, filename in [("positive", "pypi-urllib3-1.26.5.json"), ("absence", "pypi-six-1.17.0.json")]:
        raw_bytes = (root / FIXTURES / filename).read_bytes()
        raw = parsed(raw_bytes)
        fetched = load(root / FIXTURES / ("urllib3-fetch.json" if control == "positive" else "six-fetch.json"))
        require(fetched.get("url") == f"https://pypi.org/pypi/{expectation[control]['name']}/{expectation[control]['version']}/json"
                and fetched.get("sha256") == sha(raw_bytes)[7:] and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.+[+]00:00", fetched.get("fetchedAt", "")), "official response fetch evidence differs")
        require(raw["info"]["name"] == expectation[control]["name"] and raw["info"]["version"] == expectation[control]["version"], "official package source identity differs")
        require(source_ids(raw) == expectation[control]["vulnerabilityIds"], "source advisory expectation differs from pinned semantics")
    require(expectation["positive"]["vulnerabilityIds"] and not expectation["absence"]["vulnerabilityIds"], "positive/absence controls invalid")
    closures = record.get("runtimeClosures", {})
    require(isinstance(closures, dict) and closures, "runtime closure retention absent")
    for key, value in closures.items():
        require(key == value.get("digest"), "runtime closure key differs"); runtime_closure(value, live)
    rows = record.get("cases", [])
    require(len(rows) == 4 and [row.get("control") for row in rows] == ["positive", "absence", "error", "missing-tool"], "controls missing/duplicated/reordered")
    fixture_sources, used_runtime = {}, set()
    for case in rows:
        control = case["control"]; successful = control in ("positive", "absence"); planted = control == "positive"
        expected = expectation["absence" if control == "missing-tool" else control]
        text = f"{expected['name']}=={expected['version']}\n"; source_digest = sha(text.encode())
        require(case.get("fixtureFiles") == {"requirements.txt":text} and case.get("fixtureSources") == {"requirements.txt":source_digest}, "fixture source differs")
        fixture_sources[f"{control}/requirements.txt"] = source_digest
        fixture = absolute(case["fixtureRoot"]); scratch = absolute(case["scratchRoot"])
        require(fixture.name == "source" and scratch == fixture.parent / "run", "fixture/scratch boundary differs")
        enrollment = case.get("toolEnrollment", {})
        require(enrollment.get("schema") == "legion-python-tool-enrollment/1" and enrollment.get("tool") ==
                {"name":"pip-audit","version":"2.10.0","wheelSha256":WHEEL}, "tool official wheel/version differs")
        runtime = enrollment.get("runtimeDigest"); used_runtime.add(runtime)
        require(runtime in closures and case.get("runtimeBefore") == runtime == case.get("runtimeAfter"), "runtime drift/unretained closure")
        closure = closures[runtime]
        interpreter = enrollment.get("interpreter", {})
        require(interpreter.get("version") == "3.14.7", "managed runtime differs from qualified lock target")
        stdlib = absolute(interpreter["stdlibRoot"]); absolute(interpreter["basePrefix"])
        require(closure["exclusions"] == [str(stdlib / "site-packages")], "runtime exclusion scope expanded")
        launcher = enrollment.get("launcher", {})
        for item in (launcher, interpreter):
            path = absolute(item["path"]); require(is_digest(item.get("digest")), "runtime identity digest absent")
            require(closure["files"].get(str(path).lstrip("/")) == item["digest"], "launcher/interpreter absent from full closure")
            require(not (path == fixture or fixture in path.parents), "tool installed into audited fixture")
            if live: require(sha(Path(path).read_bytes()) == item["digest"], "runtime binary changed")
        require(str(stdlib) in closure["roots"] and interpreter["path"] in closure["roots"]
                and str(PurePosixPath(launcher["path"]).parent.parent) in closure["roots"], "managed interpreter/stdlib/venv roots missing")
        native = enrollment.get("nativeDiscovery", {})
        unsigned_native = dict(native); unsigned_native.pop("digest", None)
        require(native.get("digest") == sha(encoded(unsigned_native)), "native dependency graph digest differs")
        inspector = native.get("inspector", {})
        require(inspector.get("path") == "/usr/bin/otool" and is_digest(inspector.get("digest")), "native inspector identity absent")
        if live: require(sha(Path(inspector["path"]).read_bytes()) == inspector["digest"], "native inspector changed")
        require(native.get("systemExemptions") == ["/usr/lib", "/System/Library"], "native dependency exemptions expanded")
        images = native.get("images")
        require(isinstance(images, list) and images, "native graph absent")
        for image in images:
            for field in ("path", "executable"):
                require(str(absolute(image[field])).lstrip("/") in closure["files"], "native image absent from sealed runtime")
            require(isinstance(image.get("rpathStack"), list) and all(isinstance(item, str) and item.startswith("/") for item in image["rpathStack"]), "native loader search context absent")
            require(isinstance(image.get("dependencies"), list), "native dependency edges absent")
            for dependency in image["dependencies"]:
                target = absolute(dependency["resolved"])
                require(dependency.get("command") in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_DYLINKER")
                        and isinstance(dependency.get("requested"), str) and dependency["requested"], "native load command unsupported")
                system = any(target == PurePosixPath(item) or PurePosixPath(item) in target.parents for item in native["systemExemptions"])
                require(type(dependency.get("systemExempt")) is bool and dependency["systemExempt"] is system, "native exemption classification differs")
                if not system: require(str(target).lstrip("/") in closure["files"] and str(target) in closure["roots"], "native dependency bytes omitted")
        lock = enrollment.get("lock", {})
        require(absolute(lock["path"]).name == Path(LOCK).name and lock.get("digest") == files[LOCK], "wheel lock source differs")
        require(enrollment.get("provisioner", {}).get("digest") == files[HELPER] and absolute(enrollment["provisioner"]["path"]).name == Path(HELPER).name, "enrollment helper source differs")
        require(enrollment.get("requirements", {}).get("digest") == files[LOCK[:-5] + ".txt"]
                and absolute(enrollment["requirements"]["path"]).name == Path(LOCK[:-5] + ".txt").name, "enrollment requirements lock differs")
        wheel_lock = load(root / LOCK)
        expected_wheels = {item["filename"]:"sha256:" + item["sha256"] for item in wheel_lock["wheels"]}
        wheels = enrollment.get("wheels", [])
        require(len(wheels) == len(expected_wheels) and {item["filename"]:item["digest"] for item in wheels} == expected_wheels, "enrolled wheel closure differs")
        for item in wheels: require(absolute(item["path"]).name == item["filename"], "retained wheel identity differs")
        details = case.get("nativeDetails", {}); receipt = case.get("executionReceipt", {})
        require(details.get("executionReceipt") == receipt, "native receipt projection differs")
        require(case.get("nativeFindings") == [] and case.get("complete") is successful, "native outcome differs")
        require(bool(case.get("coverageGaps")) is (not successful), "native gap classification differs")
        coverage = case.get("coverage", {})
        require(coverage.get("expected") == 1 and coverage.get("examined") == int(successful), "original denominator coverage differs")
        require(is_digest(coverage.get("denominatorDigest")) and is_digest(case.get("inventoryDigest")) and is_digest(case.get("planDigest")), "frozen plan/inventory/denominator binding absent")
        inventory = case.get("inventory", {})
        entries = [{"path":"requirements.txt","symbols":[],"dependencies":[expected["name"]],"packageScripts":[],"sourceFile":False,"digest":source_digest}]
        content_digest = sha(encoded(entries))
        require(inventory == {"schemaVersion":1,"repositoryId":control,"generation":"filesystem:" + content_digest,
                             "entries":entries,"digest":case["inventoryDigest"]}, "original inventory entries differ")
        require(case["inventoryDigest"] == sha(encoded([1,control,"filesystem:" + content_digest,entries])), "original inventory digest differs")
        require(case.get("selector") == spec["selector"] and coverage["denominatorDigest"] == sha(encoded([case["inventoryDigest"],spec["selector"],entries])), "original selector/denominator replaced")
        input_binding = details.get("pythonRequirements", {})
        require(input_binding.get("schemaVersion") == 1 and input_binding.get("scope") == "exact-listed-pins-only; transitive dependencies not resolved", "input binding scope differs")
        require(input_binding.get("inventoryDigest") == case["inventoryDigest"] and input_binding.get("denominatorDigest") == coverage["denominatorDigest"], "input inventory binding differs")
        require(input_binding.get("expectedPackages") == {expected["name"]:expected["version"]}, "explicit package set differs")
        snapshots = input_binding.get("files", [])
        require(len(snapshots) == 1, "requirements snapshot count differs")
        snapshot = snapshots[0]
        snapshot_path = absolute(snapshot["snapshot"])
        require(snapshot_path.parent.parent == scratch / "reports" and re.fullmatch(r"pip-audit-[0-9]+-0", snapshot_path.parent.name)
                and snapshot_path.name == "requirements-0.txt", "snapshot path differs")
        require(snapshot == {"path":"requirements.txt","digest":source_digest,"snapshot":str(snapshot_path),"snapshotDigest":source_digest}, "original path/digest snapshot binding differs")
        policy = case.get("policyDefinition", {})
        profile = f'(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath "{str(fixture).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"))\n(deny file-write* (subpath "{str(fixture).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"))\n'
        args = ["--format","json","--disable-pip","--no-deps","--strict","-r",str(snapshot_path)]
        require(policy.get("id") == "legion-pip-audit-sdk-qualification-v1" and policy.get("version") == 1
                and policy.get("provider") == PROVIDER and policy.get("task") == "py_deps_cve" and policy.get("plan") == case["planDigest"]
                and policy.get("cwd") == str(fixture), "fixture policy identity differs")
        require(policy.get("tool") == launcher and policy.get("args") == args, "fixture command differs")
        require(policy.get("profile", {}).get("text") == profile and policy["profile"]["digest"] == sha(profile.encode()), "network/project-write policy altered")
        require(policy["profile"]["receiptId"] == "sandbox:macos:" + sha(profile.encode())[7:], "sandbox identity differs")
        require(absolute(policy["profile"]["path"]) == scratch / "sandbox" / ("audit-" + sha(profile.encode())[7:] + ".sb"), "profile artifact path differs")
        wrapper = policy.get("wrapper", {})
        require(wrapper.get("path") == "/usr/bin/sandbox-exec" and is_digest(wrapper.get("digest")), "native sandbox identity absent")
        wrapped = ["-f",policy["profile"]["path"],"--",launcher["path"]]
        require(policy.get("wrappedArgs") == wrapped + args and policy.get("versionArgs") == wrapped + ["--version"], "wrapper/version argv differs")
        require(policy.get("acceptedExitCodes") == [0,1,2] and policy.get("timeoutMs") == 120000 and policy.get("stdoutLimit") == 8388608
                and policy.get("stderrLimit") == 8388608 and policy.get("sandbox") == "native-macos-allow-network-deny-project-write-pip-audit", "bounds/sandbox declaration differs")
        environment = policy.get("environment", {})
        base_names = {"PATH","PATHEXT","SystemRoot","COMSPEC","HOME","USERPROFILE"}
        overrides = {"TMPDIR":str(scratch / "tmp"),"TEMP":str(scratch / "tmp"),"TMP":str(scratch / "tmp"),
                     "XDG_CACHE_HOME":str(scratch / "cache/xdg"),"CARGO_TARGET_DIR":str(scratch / "cache/cargo-target"),
                     "npm_config_cache":str(scratch / "cache/npm"),"RUFF_CACHE_DIR":str(scratch / "cache/ruff"),
                     "MYPY_CACHE_DIR":str(scratch / "cache/mypy"),"PYTHONPYCACHEPREFIX":str(scratch / "cache/pycache"),
                     "GOCACHE":str(scratch / "cache/go-build"),"PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1", "GIT_CONFIG_NOSYSTEM": "1"}
        require({key:environment.get(key) for key in overrides} == overrides and set(environment) <= base_names | set(overrides)
                and policy.get("environmentAllowlist") == sorted(base_names | set(overrides)), "Python runtime env isolation differs")
        require(environment.get("HOME") == str(fixture.parent / "home"), "fixture HOME isolation differs")
        decisions = case.get("policyDecisions")
        stdout, stderr = case.get("actualStdout"), case.get("actualStderr")
        require(isinstance(stdout,str) and isinstance(stderr,str), "raw streams absent")
        if control == "missing-tool":
            require(decisions == [] and receipt.get("processTree", {}).get("started") is False
                    and receipt.get("stdout") is None and receipt.get("stderr") is None and stdout == stderr == "", "missing-tool invented execution")
            require(receipt.get("state") == "missing_executable" and receipt.get("complete") is False, "missing-tool classification differs")
        else:
            require(receipt.get("state") == "completed" and receipt.get("complete") is True and receipt.get("gaps") == [] and receipt.get("signal") is None, "actual SDK lifecycle incomplete")
            require(receipt.get("exitCode") == (0 if control == "absence" else 1), "real scanner exit differs")
            require(receipt.get("providerId") == PROVIDER and receipt.get("planId") == case["planDigest"] and receipt.get("taskId") == "py_deps_cve"
                    and receipt.get("cwd") == str(fixture), "receipt request binding differs")
            require(receipt.get("policyId") == policy["id"] and receipt.get("policy") == {"allowed":True,"id":policy["id"],"version":1,"digest":sha(encoded(policy)),"reason":"exact pip-audit online fixture admission"}, "actual admission receipt differs")
            command = receipt.get("command", {})
            require(command.get("executable") == wrapper["path"] and command.get("args") == wrapped + args
                    and command.get("environmentNames") == sorted(policy["environment"]) and command.get("redactedArgumentIndexes") == []
                    and command.get("redactedEnvironmentNames") == [], "actual launch differs")
            identity = receipt.get("executable", {})
            require(identity.get("canonicalPath") == wrapper["path"] and identity.get("digest") == wrapper["digest"], "actual wrapper differs")
            version = identity.get("version", {})
            require(version.get("qualified") is True and version.get("exitCode") == 0 and version.get("args") == wrapped + ["--version"]
                    and version.get("output", "").strip() == "pip-audit 2.10.0", "actual version probe differs")
            process = receipt.get("processTree", {})
            require(all(process.get(key) is True for key in ("started","terminated","reaped")), "native process cleanup unproven")
            require(receipt.get("sandbox") == {"required":True,"networkEnabled":True,"receiptId":policy["profile"]["receiptId"]}, "sandbox receipt differs")
            timing = receipt.get("timing", {})
            require(all(type(timing.get(key)) is int for key in ("startedAtMs","completedAtMs","durationMs"))
                    and timing["startedAtMs"] > 0 and timing["completedAtMs"] >= timing["startedAtMs"]
                    and timing["durationMs"] == timing["completedAtMs"] - timing["startedAtMs"], "actual timing absent/inconsistent")
            require(len(decisions) == 1 and decisions[0].get("allowed") is True and decisions[0].get("requestId") == receipt.get("requestId")
                    and decisions[0].get("args") == wrapped + args and decisions[0].get("versionArgs") == wrapped + ["--version"], "actual policy decision differs")
            for key, text_stream in [("stdout",stdout),("stderr",stderr)]:
                artifact = receipt.get(key, {})
                require(artifact.get("immutable") is True and artifact.get("digest") == sha(text_stream.encode())
                        and artifact.get("bytes") == len(text_stream.encode()), "retained raw artifact differs")
                path = PurePosixPath(artifact.get("path", ""))
                require(not path.is_absolute() and path.parts and ".." not in path.parts, "artifact escapes original sink")
        ids = []
        if successful:
            raw = parsed(stdout)
            require(set(raw) == {"dependencies","fixes"} and raw["fixes"] == [] and len(raw["dependencies"]) == 1, "raw report envelope differs")
            row = raw["dependencies"][0]
            require(row.get("name") == expected["name"] and row.get("version") == expected["version"] and "skip_reason" not in row
                    and isinstance(row.get("vulns"), list), "raw package/version/skipped response differs")
            for vuln in row["vulns"]:
                require(isinstance(vuln.get("id"),str) and vuln["id"] and isinstance(vuln.get("fix_versions"),list)
                        and all(isinstance(v,str) for v in vuln["fix_versions"]), "malformed vulnerability row")
            ids = sorted(vuln["id"] for vuln in row["vulns"])
            require(ids == expected["vulnerabilityIds"] and details.get("findingsCount") == len(ids), "actual mutable online response differs from source-fetched expectation")
        else:
            require(details.get("findingsCount") is None, "failure presented as clean count")
            if control == "error":
                require(stderr and expected["name"] in stderr, "strict lookup failure evidence absent")
                try: parsed(stdout)
                except (ValueError, AssertionError): pass
                else: require(False, "error control unexpectedly emitted parseable report")
        require(case.get("actualVulnerabilityIds") == ids, "raw advisory projection differs")
        candidates = details.get("candidates", [])
        require(len(candidates) == int(planted), "candidate count differs")
        if planted:
            item = candidates[0]; rule = "legacy.py_deps_cve.pip-audit"
            require(item.get("id") == sha((f"{rule}\0requirements.txt\0" + "1").encode()) and item.get("ruleId") == rule
                    and item.get("role") == "candidate-generator" and item.get("claim") == f"py_deps_cve reported {len(ids)} finding(s)"
                    and item.get("verdict") == "UNADJUDICATED" and item.get("adjudicationRequired") is True, "native candidate projection differs")
            require(item.get("evidence", [{}])[0].get("file") == "requirements.txt" and item["evidence"][0].get("line") == 1, "candidate original path lost")
    require(set(closures) == used_runtime, "unconsumed runtime closure")
    require(binding.get("fixtureSources") == fixture_sources and binding.get("fixtureSourcesDigest") == sha(encoded(fixture_sources)), "fixture closure digest differs")
    require(record.get("metrics") == {"cases":4,"matched":4,"mismatched":0}, "control metrics differ")
    return {"provider":PROVIDER,"cases":4,"matched":4,"modelCalls":0,"fixtureOnly":True,"scope":record["scope"],"qualificationDigest":record["qualificationDigest"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    path = args.receipts / "legacy_security_python-dependencies.json"
    result = validate_record(args.root, load(path), live=True)
    print("PIP_AUDIT_SDK_ACCURACY_SUMMARY " + json.dumps({"records":[result],"modelCalls":0}, separators=(",",":")))


if __name__ == "__main__":
    main()
