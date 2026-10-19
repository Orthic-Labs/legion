#!/usr/bin/env python3
"""Validate npm SDK reconciliation controls & original runtime/artifacts; no production admission."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.stack.node-outdated"
HARNESS = "engine/crates/legion-audit/tests/node_outdated_accuracy.rs"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/node-outdated"
FAMILY_SCOPE = "constructed native SDK; official tiny-invariant installed-data npm outdated positive/nonempty absence + registry/process failure + missing-tool; run-scoped public registry responses only, no production owner-admission claim"
POLICY = "legion-npm-outdated-fixture-v1"
NODE_PINS = {"sha256:18e387c90ab8a8400183e8bdd396376e1e875b91b4c874b894dcade7b35bf572", "sha256:0b4f059915f3bf3c6cbb02422f4a529bfb21cbbec2d29851c9a5d833f78a04f6"}
NPM_CLI = "sha256:8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7"
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


def runtime(root, provision, live):
    require(provision["schema"] == "legion-node-outdated-ci-provision/1" and provision["nodeVersion"] == "22.23.2" and provision["npmVersion"] == "10.9.8", "shared pinned runtime differs")
    require(provision["nodeDigest"] in NODE_PINS and provision["npmCliDigest"] == NPM_CLI, "official runtime pin differs")
    node, npm, package = (absolute(provision[key]) for key in ("nodePath", "npmPath", "npmRoot"))
    require(npm == package / "bin/npm-cli.js" and node.parent.parent == package.parent.parent.parent, "shared Node/npm prefix differs")
    pin = parsed(source_file(root, FIXTURES + "/npm-source-pin.json").read_bytes())
    same(provision["npmSource"], pin, "official npm source binding differs")
    require(pin["version"] == "10.9.8" and pin["sourceCommit"] == "e7aef0275b74070c022a626bbe7ec8c97febe4ad" and pin["npmCliDigest"] == NPM_CLI and pin["url"] == "https://registry.npmjs.org/npm/-/npm-10.9.8.tgz", "npm upstream pin differs")
    files = provision["npmFiles"]
    require(files and provision["npmFilesDigest"] == digest(encoded(files)), "runtime closure digest differs")
    for relative, item in files.items():
        path = PurePosixPath(relative)
        require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "escaping runtime path")
        if "digest" in item:
            require(set(item) == {"digest", "bytes"} and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) and type(item["bytes"]) is int and item["bytes"] >= 0, "runtime file identity malformed")
        else:
            target = PurePosixPath(item["canonicalTarget"])
            require(set(item) == {"symlink", "canonicalTarget"} and not target.is_absolute() and ".." not in target.parts and str(target) in files, "runtime link escapes closure")
    for relative, expected in pin["files"].items():
        require(files[relative]["digest"] == expected, "npm published bytes differ: " + relative)
    if live:
        require(digest(Path(node).read_bytes()) == provision["nodeDigest"], "live Node differs")
        actual = {}
        for path in Path(package).rglob("*"):
            relative = path.relative_to(str(package)).as_posix()
            if path.is_symlink():
                target = path.resolve(strict=True)
                require(target.is_relative_to(str(package)), "runtime link escapes")
                actual[relative] = {"symlink": str(path.readlink()), "canonicalTarget": target.relative_to(str(package)).as_posix()}
            elif path.is_file():
                data = path.read_bytes()
                actual[relative] = {"digest": digest(data), "bytes": len(data)}
            else:
                require(path.is_dir(), "special runtime file")
        same(actual, files, "live runtime closure changed")
    return node, npm


def fixture(root, control):
    template = "absence" if control == "missing-tool" else control
    data = source_file(root, FIXTURES + "/" + template + "/package.json").read_bytes()
    manifest = parsed(data)
    version = manifest["dependencies"]["tiny-invariant"]
    directory = root / FIXTURES / "packages" / version
    files = {"package.json": data}
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "fixture package symlink")
        if path.is_file():
            files["node_modules/tiny-invariant/" + path.relative_to(directory).as_posix()] = path.read_bytes()
    pins = parsed(source_file(root, FIXTURES + "/package-pins.json").read_bytes())
    official = next(pin for pin in pins["packages"] if pin["version"] == version)
    same({p.removeprefix("node_modules/tiny-invariant/"): digest(b) for p, b in files.items() if p != "package.json"}, official["files"], "installed official package data differs")
    require(official["name"] == "tiny-invariant" and official["tarball"] == f"https://registry.npmjs.org/tiny-invariant/-/tiny-invariant-{version}.tgz", "official fixture source differs")
    return manifest, files


def operations(manifest):
    deps = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, version in manifest[section].items():
            require(name not in deps or deps[name] == version, "fixture declaration conflict")
            deps[name] = version
    result = [(["outdated", "--json"], [0, 1]), (["ls", "--depth=0", "--json", "--include=dev", "--include=optional", "--include=peer"], [0])]
    for name, version in sorted(deps.items()):
        result += [(["view", name + "@" + version, "--json"], [0]), (["view", name + "@latest", "--json"], [0])]
    return deps, result


def report_rows(value):
    require(isinstance(value, dict) and "error" not in value, "operational report envelope")
    rows = {}
    for name, entry in value.items():
        items = entry if isinstance(entry, list) else [entry]
        require(items, "empty array row")
        triples = []
        for item in items:
            require(isinstance(item, dict) and "error" not in item, "malformed outdated row")
            triple = [item.get(k) for k in ("current", "wanted", "latest")]
            require(all(isinstance(v, str) and re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", v) for v in triple) and len(set(triple)) > 1, "invalid/unchanged row")
            triples.append(triple)
        rows[name] = triples
    return rows


def validate_record(repository_root, row, live=False):
    root = Path(repository_root).resolve()
    require(row.get("schema") == "legion-node-outdated-sdk-accuracy/1" and row.get("provider") == ID and row.get("stage") == "finding" and row.get("scope") == FAMILY_SCOPE, "fixed native identity/scope differs")
    require(row.get("productionQualification") is False and row.get("qualificationEligible") is True and row.get("status") == "pass" and type(row.get("modelCalls")) is int and row["modelCalls"] == 0, "not completed constructed qualification")
    require(row["admissionScope"] == "explicit constructed SDK authorizer; no production CLI owner-admission claim", "admission scope expanded")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "original record digest differs")
    spec = next(s for s in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if s["id"] == ID)
    spec = {k: v for k, v in spec.items() if k != "benchmark"}
    require(spec["execution"]["resourceClaims"]["projectExecution"] == 0 and spec["selector"]["patterns"] == ["**/package.json"], "authority/denominator changed")
    bound = row["binding"]
    same(bound["providerSpec"], spec, "provider spec differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)) and bound["fixture"] == HARNESS, "source-owned binding differs")
    actual_sources = sources(root)
    same(bound["sources"], actual_sources, "runtime/SDK/parser/fixture source closure differs")
    require(bound["sourcesDigest"] == digest(encoded(actual_sources)), "source closure digest differs")
    node, npm = runtime(root, row["provision"], live)
    require([c["control"] for c in row["cases"]] == ["positive", "absence", "process-error", "missing-tool"], "controls missing/reordered")
    corpus = {}
    retained = None
    for case in row["cases"]:
        control = case["control"]
        missing = control == "missing-tool"
        cwd, run = absolute(case["root"]), absolute(case["run"])
        require(cwd.name == "source" and run.name == "run" and cwd.parent == run.parent and cwd.parent.name == control, "original scratch paths differ")
        require(retained is None or retained == cwd.parent.parent, "cases do not share original retained root")
        retained = cwd.parent.parent
        manifest, files = fixture(root, control)
        hashes = {p: digest(b) for p, b in files.items()}
        for key in ("sourceBefore", "sourceAfter", "fixtureSources"):
            same(case[key], hashes, "audited package files changed")
        corpus.update({control + "/" + p: h for p, h in hashes.items()})
        deps, commands = operations(manifest)
        entry = {"path": "package.json", "symbols": [], "dependencies": sorted(deps), "packageScripts": ["preinstall"], "sourceFile": False, "digest": hashes["package.json"]}
        inv, plan, provider = case["inventory"], case["frozenPlan"], case["frozenProvider"]
        same(inv["entries"], [entry], "root inventory/denominator narrowed or changed")
        require(inv["schemaVersion"] == 1 and inv["repositoryId"] == control and inv["generation"] == "filesystem:" + digest(encoded([entry])) and inv["digest"] == digest(encoded([1, control, inv["generation"], [entry]])), "inventory seal differs")
        require(plan["repositoryId"] == control and plan["inventoryDigest"] == inv["digest"] and plan["inventoryGeneration"] == inv["generation"] and case["planDigest"] == digest(encoded(plan)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"constructed-node-outdated-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        same(plan["providers"], [provider], "frozen provider differs")
        denominator = digest(encoded([inv["digest"], spec["selector"], [entry]]))
        require(provider["configuration"]["denominatorCount"] == 1 and provider["configuration"]["denominatorDigest"] == denominator, "full selected denominator differs")
        policy, receipts, result = case["policyDefinition"], case["actualSdkReceipts"], case["nativeResult"]
        same(policy["operations"], commands, "exact shipped npm operation set differs")
        require(policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == ID and policy["task"] == "outdated" and policy["plan"] == case["planDigest"] and policy["cwd"] == str(cwd), "constructed scoped policy differs")
        same(policy["tool"], {"path": str(npm), "digest": NPM_CLI}, "pinned npm CLI differs")
        require(policy["wrapper"]["path"] == "/usr/bin/sandbox-exec" and re.fullmatch(r"sha256:[0-9a-f]{64}", policy["wrapper"]["digest"]), "native wrapper differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
        profile = run / "sandbox" / ("audit-" + digest(text.encode())[7:] + ".sb")
        sandbox = "sandbox:macos:" + digest(text.encode())[7:]
        same(policy["profile"], {"path": str(profile), "text": text, "digest": digest(text.encode()), "receiptId": sandbox}, "native project-write-denied sandbox differs")
        prefix = ["-f", str(profile), "--", str(npm)]
        same(policy["versionArgs"], prefix + ["--version"], "npm version argv differs")
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        env = {"PATH": "/usr/bin:/bin" if missing else ":".join([str(node.parent), "/usr/bin", "/bin"]), "HOME": str(retained / "home"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", **{name: str(run / path) for name, path in cache.items()}}
        same(policy["environment"], env, "isolated environment differs")
        allowlist = sorted({"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM", *cache})
        same(policy["environmentAllowlist"], allowlist, "production allowlist differs")
        completion = result["details"]["npmOutdatedCompletion"]
        same(completion["expected"], deps, "expected declarations differ")
        same(completion["rootManifest"], {"path": "package.json", "digest": hashes["package.json"]}, "frozen source digest differs")
        projected = completion["probes"]
        require(len(receipts) == len(projected) == (1 if missing else len(commands)), "required actual command missing")
        for i, (receipt, projection) in enumerate(zip(receipts, projected)):
            require(receipt["schemaVersion"] == 1 and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["taskId"] == "outdated" and receipt["cwd"] == str(cwd), "actual SDK receipt linkage differs")
            for key in ("receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "parser", "gaps"):
                same(receipt[key], projection["receipt"][key], "producer projection differs: " + key)
            if missing:
                require(receipt["state"] == "missing_executable" and receipt["complete"] is False and receipt["processTree"]["started"] is False and receipt["exitCode"] is None and case["policyDecisions"] == [], "missing npm tool fabricated process")
                continue
            require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) and receipt["receiptId"] == "receipt:" + receipt["requestId"], "real SDK request identity differs")
            scoped_env = {**env, "npm_config_cache": str(run / "cache" / f"npm-outdated-{i}")}
            fresh = run / "cache" / f"npm-outdated-{i}"
            args = commands[i][0] + ["--registry=https://registry.npmjs.org/", "--online", "--offline=false", "--prefer-offline=false", "--prefer-online=true", "--ignore-scripts=true", "--audit=false", "--fund=false", "--cache=" + str(fresh), "--userconfig=" + str(fresh / "empty.npmrc"), "--globalconfig=" + str(fresh / "global.npmrc")]
            same(receipt["command"]["args"], prefix + args, "exact public online command differs")
            decision = case["policyDecisions"][i]
            require(decision["allowed"] is True and decision["requestId"] == receipt["requestId"] and decision["args"] == prefix + args and decision["acceptedExitCodes"] == commands[i][1] and decision["environmentDigest"] == digest(encoded(scoped_env)) and decision["environmentNames"] == sorted(scoped_env) and 0 < decision["timeoutMs"] <= 120000, "actual command-specific admission differs")
            require(receipt["policyId"] == receipt["policy"]["id"] == POLICY and receipt["policy"]["allowed"] is True and receipt["policy"]["digest"] == digest(encoded(policy)), "real scoped policy receipt differs")
            require(receipt["executable"]["canonicalPath"] == receipt["command"]["executable"] == "/usr/bin/sandbox-exec" and receipt["executable"]["digest"] == policy["wrapper"]["digest"], "actual wrapper identity differs")
            version = receipt["executable"]["version"]
            require(version["args"] == prefix + ["--version"] and version["output"].strip() == "10.9.8" and version["qualified"] is True and version["skippedByPolicy"] is False and version["exitCode"] == 0, "actual pinned npm version differs")
            same(receipt["sandbox"], {"required": True, "receiptId": sandbox, "networkEnabled": True}, "native sandbox evidence differs")
            require(all(receipt["processTree"][k] is True for k in ("started", "terminated", "reaped")) and receipt["signal"] is None, "actual process cleanup unproven")
            for stream in ("stdout", "stderr"):
                item = receipt[stream]
                raw = item["raw"].encode()
                path = PurePosixPath(item["path"])
                require(not path.is_absolute() and ".." not in path.parts and str(path).startswith(receipt["requestId"] + "/") and item["immutable"] is True and item["digest"] == digest(raw) and item["bytes"] == len(raw), "raw immutable SDK artifact differs")
                same({k: v for k, v in item.items() if k != "raw"}, projection["receipt"][stream], "original artifact reference differs")
                require(projection[stream] == item["raw"], "original raw bytes differ")
                if live:
                    require((Path(run) / "artifacts" / item["path"]).read_bytes() == raw, "live retained raw artifact changed")
            if control != "process-error":
                require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == (1 if i == 0 and control == "positive" else 0) and receipt["gaps"] == [], "actual process completion differs")
        require(result["provider"] == ID and result["applicable"] is True and result["details"]["candidates"] == [], "deterministic provider role differs")
        if control in ("process-error", "missing-tool"):
            require(result["complete"] is False and result["coverage_gaps"] and result["findings"] == [] and result["details"]["findingsCount"] is None and result["coverage"]["examined"] == 0, "error/missing tool became clean")
            if not missing:
                require(any(r["complete"] is False and type(r["exitCode"]) is int and r["exitCode"] != 0 for r in receipts), "actual operational failure absent")
        else:
            version = manifest["dependencies"]["tiny-invariant"]
            latest = "1.3.3"
            raw_outdated = parsed(receipts[0]["stdout"]["raw"])
            measured = report_rows(raw_outdated)
            same(measured, {"tiny-invariant": [[version, version, latest]]} if control == "positive" else {}, "actual outdated rows differ")
            ls = parsed(receipts[1]["stdout"]["raw"])
            require(ls["dependencies"]["tiny-invariant"]["version"] == version and "problems" not in ls and "error" not in ls, "installed binding differs")
            for i, wanted in ((2, version), (3, latest)):
                view = parsed(receipts[i]["stdout"]["raw"])
                require(view["name"] == "tiny-invariant" and view["version"] == wanted and (i == 2 or "engines" not in view), "actual exact/latest registry response differs")
            count = int(control == "positive")
            require(result["complete"] is True and result["coverage_gaps"] == result["degradation"] == [] and result["details"]["findingsCount"] == count, "native complete result differs")
            same(result["coverage"], {"denominator_digest": denominator, "expected": 1, "examined": 1, "gaps": []}, "native denominator completion differs")
            expected_findings = [{"id": digest(b"legacy.outdated.npm:tiny-invariant\0package.json\0" + b"1"), "severity": "low"}] if count else []
            same(result["findings"], expected_findings, "native findings differ")
            same(completion["reconciled"], [{"name": "tiny-invariant", "installed": version, "declared": version, "latest": latest, "changed": bool(count)}], "native dependency reconciliation differs")
        if live:
            require(missing or Path(profile).read_bytes() == text.encode(), "live sandbox profile differs")
            for p, data in files.items():
                require((Path(cwd) / p).read_bytes() == data, "audited installed/source file changed")
    same(bound["fixtureSources"], corpus, "full fixture corpus differs")
    require(bound["fixtureSourcesDigest"] == digest(encoded(corpus)), "fixture corpus digest differs")
    same(row["metrics"], {"cases": 4, "matched": 4, "mismatched": 0}, "control metrics differ")
    return {"provider": ID, "stage": "finding", "scope": FAMILY_SCOPE, "productionQualification": False, "qualificationDigest": row["qualificationDigest"], "positiveCases": 1, "cleanCases": 1, "errorCases": 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    path = args.receipts / "legacy_stack_node-outdated.json"
    summary = validate_record(args.root, parsed(path.read_bytes()), live=True)
    print("NODE_OUTDATED_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [summary], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
