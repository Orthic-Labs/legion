#!/usr/bin/env python3
"""Validate constructed live runtime SDK controls; never authenticate or promote."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import zlib

ID = "legacy.runtime.app"
SOURCE = "engine/bins/legion/tests/runtime_app_accuracy.rs"
PLAN = "bench/runtime-app-accuracy-plan.json"
OWNER = "engine/crates/legion-audit/src/native_providers/legacy_checks/runtime_capture.rs"
POLICY = "legion-runtime-app-constructed-sdk-v1"
SCOPE = "Constructed live URL/surface SDK controls via explicit attested fixture executable mapping; not production admission, unmodified resolver identity or whole-provider clean"
ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-audit/assets", "engine/crates/legion-runtime/src/wf_port/r54", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "engine/bins/legion/src", "src/registry/rules", "src/registry/controls", "bench/fixtures/runtime-app"]
FILES = [PLAN, SOURCE, "scripts/ci/audit-runtime-app-accuracy.py", "engine/Cargo.toml", "engine/Cargo.lock", "engine/bins/legion/Cargo.toml", "engine/crates/legion-runtime/Cargo.toml", "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-effects/Cargo.toml", "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml", "engine/crates/legion-rules/Cargo.toml"]
FILES += ["engine/crates/legion-runtime/src/lib.rs", "engine/crates/legion-runtime/src/wf_port/mod.rs", "scripts/ci/tests/test_audit_runtime_app_accuracy.py"]
FALSE_CLAIMS = ("productionQualification", "wholeProviderQualified", "unmodifiedResolverQualified", "productionAdmissionQualified")


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def load(path):
    return parsed(path.read_bytes())


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def relative(root, name):
    require(isinstance(name, str) and "\\" not in name and ":" not in name, "unsafe artifact/source path")
    parts = PurePosixPath(name)
    require(not parts.is_absolute() and ".." not in parts.parts and str(parts) == name, "escaping artifact/source path")
    path = Path(root)
    for part in parts.parts:
        path /= part
        require(not path.is_symlink(), "artifact/source symlink refused")
    require(path.is_file(), "missing original artifact/source")
    return path


def source_files(root):
    root = Path(root)
    paths = set(FILES)
    for name in ROOTS:
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink(), "missing runtime source root")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source symlink refused")
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    return sorted(paths)


def retained_files(row):
    paths = []
    for case in row["cases"]:
        for mapping in case["mappings"]:
            paths.extend(mapping[name]["path"] for name in ("actions", "stdout", "stderr"))
        paths.extend(ref["path"] for ref in case["screenshots"])
    require(len(paths) == len(set(paths)), "duplicate retained runtime evidence")
    require(all(path.startswith("evidence/") for path in paths), "runtime retained evidence scope differs")
    return paths


def artifact(retained, ref, expected_native=None):
    require(set(ref) == {"path", "nativePath", "sha256", "bytes"}, "runtime artifact descriptor differs")
    if expected_native is not None:
        require(ref["nativePath"] == expected_native, "native runtime artifact linkage differs")
    raw = relative(retained, ref["path"]).read_bytes()
    require(digest(raw) == ref["sha256"] and len(raw) == ref["bytes"], "original runtime artifact bytes differ")
    return raw


def png(raw):
    require(raw.startswith(b"\x89PNG\r\n\x1a\n"), "screenshot is not PNG")
    position, kinds = 8, []
    while position < len(raw):
        require(position + 12 <= len(raw), "truncated PNG chunk")
        size = int.from_bytes(raw[position:position + 4], "big")
        kind, data = raw[position + 4:position + 8], raw[position + 8:position + 8 + size]
        require(position + size + 12 <= len(raw), "truncated PNG bytes")
        crc = int.from_bytes(raw[position + 8 + size:position + 12 + size], "big")
        require(zlib.crc32(kind + data) == crc, "screenshot CRC differs")
        if kind == b"IHDR":
            require(len(data) == 13 and struct.unpack(">II", data[:8]) == (640, 480), "screenshot viewport differs")
        kinds.append(kind)
        position += size + 12
    require(kinds[0] == b"IHDR" and kinds[-1] == b"IEND" and b"IDAT" in kinds, "PNG capture incomplete")


def expected_actions(root, shot):
    source = relative(root, OWNER).read_text()
    values = {}
    for name in ("LOAD_CHECK", "PERFORMANCE_METRICS"):
        match = re.search(r"^const " + name + r": &str = (.+);$", source, re.M)
        require(match is not None, "runtime owner capture expression missing")
        values[name] = json.loads(match[1])
    match = re.search(r'fn axe_expression\(.*?\n    format!\(\n        ("(?:[^"\\]|\\.)*")\n    \)', source, re.S)
    require(match is not None, "runtime owner axe expression missing")
    template = json.loads(match[1])
    axe = relative(root, "engine/crates/legion-audit/assets/axe-core-4.14.0.min.js").read_text()
    expression = template.replace("{source}", "\0").replace("{{", "{").replace("}}", "}").replace("\0", axe)
    return [{"type": "eval", "expression": values["LOAD_CHECK"]}, {"type": "screenshot", "out": shot},
            {"type": "eval", "expression": values["PERFORMANCE_METRICS"]}, {"type": "eval", "expression": expression}]


def qa_output(raw):
    values, shots, completed, console, clean, total = {}, [], False, [], False, None
    for line in raw.decode("utf-8").splitlines():
        if not line.startswith("[qa] "):
            continue
        rest = line[5:]
        match = re.fullmatch(r"([1-9][0-9]*):eval value (.+)", rest)
        if match and not completed:
            index = int(match[1])
            require(index not in values, "duplicate QA eval evidence")
            values[index] = parsed(match[2])
        elif rest.startswith("screenshot "):
            shots.append(rest[len("screenshot "):].strip())
        elif rest.startswith("actions complete "):
            require(not completed, "duplicate QA completion")
            completed = True
        elif rest == "no console errors or warnings":
            clean = True
        elif "console error/warning(s)" in rest:
            total = int(rest.split()[0])
        elif rest.startswith("  ") and rest.strip().startswith(("console.", "exception:")):
            console.append(rest.strip())
        elif rest.startswith("gap "):
            require(False, "QA reported typed gap")
    require(not (clean and console) and (total is None or total == len(console)), "QA console evidence incomplete/fabricated")
    return values, shots, completed, console, clean


def validate_record(root, row, live=False, retained=None):
    root = Path(root).resolve()
    require(row["schema"] == "legion-runtime-app-sdk-accuracy/1" and row["provider"] == ID
            and row["family"] == "runtime-app-sdk" and row["stage"] == "finding" and row["scope"] == SCOPE
            and row["status"] == "pass" and row["qualificationEligible"] is True and type(row["modelCalls"]) is int
            and row["modelCalls"] == 0 and all(row[name] is False for name in FALSE_CLAIMS), "runtime identity/scope/claim differs")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "runtime digest differs")
    require(Path(row["retainedRoot"]).is_absolute() and row["retainedRoot"].endswith("/legion-provider-qualification/runtime-app"), "runtime retained root differs")
    retained = Path(retained) if retained is not None else Path(row["retainedRoot"])
    retained_files(row)
    bound = row["binding"]
    files = {name: digest(relative(root, name).read_bytes()) for name in source_files(root)}
    same(bound["sources"], files, "runtime original source closure differs")
    require(bound["sourcesDigest"] == digest(encoded(files)), "runtime source digest differs")
    definition = load(relative(root, PLAN))
    same(bound["plan"], definition, "frozen runtime qualification plan differs")
    require(bound["planDigest"] == digest(encoded(definition)) and definition["scope"] == SCOPE, "runtime plan seal differs")
    specs = load(relative(root, "src/registry/providers.json"))["providers"]
    spec = next(spec for spec in specs if spec["id"] == ID)
    same(bound["providerSpec"], {key: value for key, value in spec.items() if key != "benchmark"}, "runtime shipped provider differs")
    browser = bound["browser"]
    require(browser["installerMarker"]["version"] == definition["browser"]["version"]
            and browser["installerMarker"]["platform"] == "mac-arm64"
            and browser["installerMarker"]["files"] == [{"kind": "chrome", "url": definition["browser"]["archiveUrl"], "sha256": definition["browser"]["archiveSha256"]}]
            and re.fullmatch(r"Google Chrome for Testing 155\.0\.8059\.39\s*", browser["versionOutput"]) is not None,
            "runtime browser pin/provisioning differs")
    tree = browser["installedTree"]
    require(tree["digest"] == digest(encoded(tree["files"])) and len({item["path"] for item in tree["files"]}) == len(tree["files"]), "runtime browser tree seal differs")
    installed = Path(browser["installedRoot"])
    require(installed.is_absolute() and Path(browser["path"]).is_relative_to(installed), "runtime browser selected outside provisioned tree")
    executable = Path(browser["path"]).relative_to(installed).as_posix()
    require(any(item.get("path") == executable and item.get("digest") == browser["sha256"] and item.get("kind") == "file" for item in tree["files"]), "runtime browser executable bytes absent from tree")
    require(bound["axeDigest"] == digest(relative(root, definition["axe"]["path"]).read_bytes()), "runtime axe bytes differ")
    for key in ("originalExecutable", "mappedExecutable"):
        identity = bound[key]
        require(Path(identity["path"]).is_absolute() and re.fullmatch(r"sha256:[0-9a-f]{64}", identity["sha256"]) is not None, "runtime executable identity missing")
        if live:
            require(digest(Path(identity["path"]).read_bytes()) == identity["sha256"], "runtime executable bytes changed")
    require(bound["originalExecutable"]["path"] != bound["mappedExecutable"]["path"], "runtime fixture mapping not explicit")
    if live:
        require(digest(Path(browser["path"]).read_bytes()) == browser["sha256"], "runtime browser bytes changed")
        for item in tree["files"]:
            path = installed / item["path"]
            if item["kind"] == "file":
                require(not path.is_symlink() and digest(path.read_bytes()) == item["digest"] and path.stat().st_size == item["bytes"], "runtime installed browser tree changed")
            else:
                require(path.is_symlink() and str(path.readlink()) == item["target"] and path.resolve().is_relative_to(installed), "runtime installed browser link changed")
    require(re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]*", row["origin"]) is not None, "runtime loopback origin differs")
    same([case["caseId"] for case in row["cases"]], [case["id"] for case in definition["cases"]], "runtime positive/clean/refusal controls missing")
    for case, expected in zip(row["cases"], definition["cases"]):
        name = expected["id"]
        route = "clean" if name == "owner-denied" else name
        urls = [row["origin"] + "/" + route + "/" + surface + ".html" for surface in expected["surfaces"]]
        require(case["url"] == urls[0] and len(case["mappings"]) == (0 if name == "owner-denied" else len(urls)), "runtime executed URL/case mapping differs")
        same(case["extraSurfaces"], [["secondary", urls[1]]] if len(urls) == 2 else [], "runtime frozen surface mapping differs")
        frozen = case["frozenPlan"]
        require(case["planDigest"] == digest(encoded(frozen)) and frozen["inventoryDigest"] == case["inventory"]["digest"]
                and len(frozen["providers"]) == 1 and frozen["providers"][0]["id"] == ID, "runtime original frozen plan differs")
        config = frozen["providers"][0]["configuration"]
        runtime = config["runner"]["runtime"]
        require(runtime["url"] == urls[0] and runtime["width"] == 640 and runtime["height"] == 480
                and runtime["surfaces"] == ([{"label": "secondary", "url": urls[1]}] if len(urls) == 2 else [])
                and runtime["unsupportedSurfaces"] == [] and not runtime.get("interactions"), "runtime live frozen surface input differs")
        result = case["actualProviderResult"]
        require(result["provider"] == ID and result["applicable"] is True and result["complete"] is False, "runtime result falsely claims whole-provider completion")
        observation = result["details"]["runtime"]
        require(observation["source"] == "legion script qa/qa-functional" and observation["complete"] is False
                and observation["status"] == "unproven" and observation["fixtureBoundSurfaces"] == []
                and observation["interactions"] == [], "fixture-only evidence masquerades as live runtime")
        receipts = result["details"]["executionReceipts"]
        require(len(receipts) == len(urls) and len(observation["surfaces"]) == len(urls), "runtime native receipt/surface cardinality differs")
        if name == "owner-denied":
            require(not case["screenshots"] and not case["mappings"] and not result["findings"], "owner denial fabricated live evidence")
            receipt = receipts[0]
            require(receipt["state"] == "unauthorized_effect" and receipt["complete"] is False
                    and receipt["processTree"]["started"] is False and receipt["policy"]["allowed"] is False
                    and receipt["policy"]["reason"] == "native-owner-admission-unavailable", "production owner refusal weakened")
            continue
        for index, (mapping, receipt, surface, url) in enumerate(zip(case["mappings"], receipts, observation["surfaces"], urls)):
            original, mapped = mapping["originalRequest"], mapping["mappedRequest"]
            require(original["executable"] == bound["originalExecutable"]["path"] and original["expectedDigest"] == bound["originalExecutable"]["sha256"], "original resolver identity absent")
            remapped = dict(original, executable=bound["mappedExecutable"]["path"], expectedDigest=bound["mappedExecutable"]["sha256"])
            same(mapped, remapped, "runtime mapping changed more than one executable identity")
            require(mapped["providerId"] == ID and mapped["planId"] == case["planDigest"] and mapped["taskId"] == "runtime"
                    and mapped["origin"] == "LegionOwned" and mapped["shell"] is False and mapped["acceptedExitCodes"] == [0]
                    and mapped["versionArgs"] == ["--version"] and mapped["skipVersionProbe"] is False
                    and mapped["versionRequirement"] is None and mapped["timeoutMs"] == 120000
                    and mapped["stdoutLimit"] == mapped["stderrLimit"] == 8388608
                    and mapped["requiresNetworkSandbox"] is False and mapped["sandbox"] is None
                    and mapped["sensitiveArgumentIndexes"] == mapped["sensitiveEnvironmentNames"] == [], "runtime admitted request contract differs")
            cwd = Path(mapped["cwd"])
            require(cwd.is_relative_to(Path(case["scratchRoot"])) and mapped["environment"]["CHROME_PATH"] == browser["path"]
                    and set(mapped["environment"]) <= set(mapped["environmentAllowlist"]), "runtime environment/scratch/browser differs")
            actions_path = str(cwd / "actions.json")
            same(mapped["args"], ["script", "qa/qa-functional", "--url", url, "--actions", actions_path, "--width", "640", "--height", "480"], "runtime actual QA command differs")
            actions = parsed(artifact(retained, mapping["actions"], actions_path))
            shot = str(Path(case["scratchRoot"]) / "tmp" / "unused") if name == "http-failure" else surface["screenshot"]["path"]
            if name == "http-failure":
                shot = actions[1]["out"]
            require(Path(shot).is_relative_to(Path(case["scratchRoot"])), "runtime screenshot escaped scratch")
            same(actions, expected_actions(root, shot), "runtime capture/axe action inputs changed")
            same(mapping["admission"], {"original": original, "mapped": mapped, "actionsDigest": digest(encoded(actions))}, "runtime exact fixture admission differs")
            require(mapping["policyDigest"] == digest(encoded(mapping["admission"])) == receipt["policy"]["digest"]
                    and receipt["policy"]["id"] == POLICY and receipt["policy"]["allowed"] is True, "runtime native admission receipt differs")
            require(receipt["requestId"] == mapped["requestId"] and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"]
                    and receipt["command"]["executable"] == mapped["executable"] and receipt["command"]["args"] == mapped["args"]
                    and receipt["executable"]["digest"] == mapped["expectedDigest"]
                    and receipt["executable"]["canonicalPath"] == mapped["executable"]
                    and receipt["executable"]["version"]["qualified"] is True
                    and receipt["processTree"]["started"] is receipt["processTree"]["terminated"] is receipt["processTree"]["reaped"] is True,
                    "runtime original native receipt identity/lifecycle differs")
            stdout = artifact(retained, mapping["stdout"], receipt["stdout"]["path"])
            stderr = artifact(retained, mapping["stderr"], receipt["stderr"]["path"])
            for name_stream, raw in (("stdout", stdout), ("stderr", stderr)):
                require(receipt[name_stream]["digest"] == digest(raw) and receipt[name_stream]["bytes"] == len(raw)
                        and receipt[name_stream]["immutable"] is True, "runtime raw native stream differs")
            values, shots, completed, console, no_console = qa_output(stdout)
            require(surface["url"] == url and surface["label"] == expected["surfaces"][index]
                    and surface["viewport"] == definition["viewport"], "runtime observed surface identity differs")
            if name == "http-failure":
                require(receipt["exitCode"] != 0 and not completed and surface["status"] == "failed"
                        and surface["screenshot"] is None and any("runtime-surface-load" in gap for gap in surface["gaps"]), "HTTP failure accepted as live evidence")
                continue
            require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == 0
                    and completed and set(values) == {1, 3, 4} and shots == [shot] and surface["status"] == "captured"
                    and surface["gaps"] == [] and surface["processState"] == "completed" and surface["exitCode"] == 0, "runtime capture incomplete/failed")
            require(values[1]["ok"] is True and values[1]["href"] == url and values[1]["status"] == 200, "browser error/HTTP failure accepted")
            metrics = values[3]
            require(set(metrics) == {"domContentLoaded", "loadEventEnd", "responseStart", "ttfb", "firstContentfulPaint", "transferSize", "resourceCount"}
                    and all(value is None or type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in metrics.values())
                    and all(metrics[key] is not None for key in ("domContentLoaded", "loadEventEnd", "ttfb")), "missing/invalid runtime metrics")
            same(surface["performance"], metrics, "runtime metric projection differs from original output")
            accessibility = values[4]
            require(accessibility["status"] == "ran" and accessibility["truncated"] is False
                    and accessibility["totalViolations"] == len(accessibility["violations"])
                    and [item["id"] for item in accessibility["violations"]] == expected["axeRuleIds"], "runtime positive/clean axe controls differ")
            same(surface["accessibility"], accessibility, "runtime axe projection differs from original output")
            same(surface["consoleErrors"], console, "runtime console projection fabricated")
            require(surface["consoleWarnings"] == [] and ((not console and no_console) if name == "clean" else len(console) == 1 and "legion-runtime-planted" in console[0]), "runtime positive/clean console control differs")
            screenshot = case["screenshots"][index]
            raw_png = artifact(retained, screenshot, shot)
            png(raw_png)
            require(surface["screenshot"]["sha256"] == digest(raw_png) and surface["screenshot"]["bytes"] == len(raw_png), "runtime screenshot projection differs")
        if name in ("clean", "planted"):
            require(len(case["screenshots"]) == 2 and len(result["findings"]) == (0 if name == "clean" else 4), "runtime actual findings differ")
            for url in urls:
                fixture_bytes = relative(root, expected["fixture"]).read_bytes()
                path = url.removeprefix(row["origin"])
                require(any(item["path"] == path and item["status"] == 200 and item["bodySha256"] == digest(fixture_bytes)
                            and item["bodyBytes"] == len(fixture_bytes) for item in row["serverRequests"]), "runtime original served fixture bytes differ")
    same(row["cleanup"], {"fixtureServerStopped": True, "nativeProcessTreesReaped": True, "retainedEvidence": True}, "runtime cleanup incomplete")
    return summary(row)


def summary(row):
    return {"provider": ID, "scope": SCOPE, "qualificationDigest": row["qualificationDigest"], "cases": 4, "liveCapturedSurfaces": 4,
            "originalExecutableDigest": row["binding"]["originalExecutable"]["sha256"], "mappedExecutableDigest": row["binding"]["mappedExecutable"]["sha256"],
            **{name: False for name in FALSE_CLAIMS}}


def rejection_controls(root, row, retained):
    def reseal(value):
        value["qualificationDigest"] = digest(encoded({k: v for k, v in value.items() if k != "qualificationDigest"}))
        return value
    mutations = []
    for name in FALSE_CLAIMS:
        value = copy.deepcopy(row); value[name] = True; mutations.append(value)
    value = copy.deepcopy(row); value["binding"]["sourcesDigest"] = "sha256:" + "0" * 64; mutations.append(value)
    value = copy.deepcopy(row); value["binding"]["plan"]["viewport"]["width"] = 1; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][0]["screenshots"] = []; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][0]["actualProviderResult"]["details"]["runtime"]["surfaces"][0]["performance"] = None; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][0]["actualProviderResult"]["details"]["runtime"]["surfaces"][0]["accessibility"]["status"] = "unavailable"; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][0]["actualProviderResult"]["details"]["runtime"]["surfaces"][0]["consoleErrors"] = ["fabricated"]; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][0]["actualProviderResult"]["details"]["runtime"]["source"] = "rightkit-browser/fixture-session"; mutations.append(value)
    value = copy.deepcopy(row); value["cases"][3]["actualProviderResult"]["details"]["executionReceipts"][0]["policy"]["allowed"] = True; mutations.append(value)
    for value in mutations:
        try:
            validate_record(root, reseal(value), live=False, retained=retained)
        except (AssertionError, KeyError, IndexError, TypeError, ValueError):
            continue
        raise AssertionError("runtime resealed tamper control accepted")
    return len(mutations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    args = parser.parse_args()
    row = load(relative(args.receipts, "legacy_runtime_app.json"))
    result = validate_record(args.root, row, live=True, retained=args.receipts)
    result["validatorRejectionControls"] = rejection_controls(args.root, row, args.receipts)
    print("RUNTIME_APP_SDK_ACCURACY_SUMMARY " + json.dumps({"records": [result], "modelCalls": 0}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
