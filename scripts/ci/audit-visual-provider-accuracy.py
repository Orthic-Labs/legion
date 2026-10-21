#!/usr/bin/env python3
"""Validate explicit PNG comparison controls, never authenticate CI or promote a provider.

Live mode rebinds retained source/PNG/browser bytes. Actual rendering, PNG pixel
assertions & native replay belong to source-bound Rust harness terminal success.
Offline registration validates retained semantics; authenticated retrieval of both
successful commands remains mandatory in audit-qualification-records.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

ID = "legacy.visual.core"
SOURCE = "engine/crates/legion-audit/tests/visual_accuracy.rs"
LABEL = "visual.regression|viewport|shots/viewport.png|artifact"
VERSION = "155.0.8059.39"
URL = f"https://storage.googleapis.com/chrome-for-testing-public/{VERSION}/mac-arm64/chrome-mac-arm64.zip"
ARCHIVE = "529a71bd61aaa2ef266a4d4bd300ae9572ba6a3468a8d55c3023ffeffb5b6b4e"
ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-provider-sdk/src",
         "engine/crates/legion-contracts/src", "engine/crates/legion-effects/src",
         "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
FILES = ["engine/Cargo.lock", "engine/Cargo.toml", "engine/crates/legion-audit/Cargo.toml",
         "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
         "engine/crates/legion-effects/Cargo.toml", "engine/crates/legion-rules/Cargo.toml", SOURCE]
SCOPE = "Two flat-color constructed controls; explicit sealed PNG comparison only, not UI quality, runtime capture, population accuracy or production admission"
READY = "document.readyState === 'complete'"
START_ANIMATION_FRAMES = "(() => { const state = {rafAvailable: typeof window.requestAnimationFrame === 'function', frameCallbacks: 0, frameProbeComplete: false}; window.__legionVisualFrames = state; if (state.rafAvailable) requestAnimationFrame(() => { state.frameCallbacks += 1; requestAnimationFrame(() => { state.frameCallbacks += 1; state.frameProbeComplete = true; }); }); return true; })()"
ANIMATION_STATE = "Object.assign({}, window.__legionVisualFrames, {visibilityState: document.visibilityState, readyState: document.readyState, hasFocus: document.hasFocus()})"
HIGH_ENTROPY_UA = "(async () => await navigator.userAgentData.getHighEntropyValues(['fullVersionList']))()"
OBSERVE = "({ready:document.readyState,background:getComputedStyle(document.documentElement).backgroundColor,width:innerWidth,height:innerHeight,devicePixelRatio:devicePixelRatio,userAgent:navigator.userAgent})"


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def encoded(value, canonical=False):
    return json.dumps(value, sort_keys=canonical, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load(path):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "non-JSON number"))


def same(actual, expected, message):
    require(encoded(actual, True) == encoded(expected, True), message)


def relative(root, name):
    require(isinstance(name, str) and "\\" not in name, "unsafe relative path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == name, "escaping path")
    target = root
    for part in path.parts:
        target /= part
        require(not target.is_symlink(), "artifact/file link refused")
    require(target.is_file() and target.resolve().is_relative_to(root.resolve()), "missing/escaping file")
    return target


def tree(root):
    root = root.resolve(strict=True)
    rows = []
    def visit(path):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(root), "tree link escapes root")
            rows.append({"path": name, "kind": "symlink", "target": os.readlink(path),
                         "resolved": resolved.relative_to(root).as_posix()})
        elif path.is_dir():
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            require(path.is_file(), "special file in source/browser tree")
            data = path.read_bytes()
            rows.append({"path": name, "kind": "file", "digest": digest(data), "bytes": len(data)})
    visit(root)
    return {"digest": digest(encoded(rows)), "files": rows}


def html(planted):
    rgb = "255,0,0" if planted else "0,0,255"
    return ('<!doctype html><html style="background:rgb(' + rgb + ');width:100%;height:100%;margin:0"><head><meta charset="utf-8"><link rel="icon" href="data:,"></head><body style="margin:0"></body></html>').encode()


def frame_completion(observed):
    frames = observed.get("animationFrames")
    require(isinstance(frames, dict) and frames.get("rafAvailable") is True
            and type(frames.get("frameCallbacks")) is int and frames["frameCallbacks"] == 2
            and frames.get("frameProbeComplete") is True and frames.get("readyState") == "complete",
            "two actual renderer animation callbacks not observed")


def capture_admissions(captured, admissions, session):
    polls = sum(a["action"] == "Eval" and a["detail"] == ANIMATION_STATE for a in admissions)
    require(polls > 0 and len(admissions) == 5 + polls
            and all(a["allowed"] is True and a["sessionId"] == session and a["url"] == captured["url"] for a in admissions)
            and sum(a["action"] == "Navigate" for a in admissions) == 1
            and all(sum(a["action"] == "Eval" and a["detail"] == expression for a in admissions) == 1
                    for expression in (READY, START_ANIMATION_FRAMES, HIGH_ENTROPY_UA, OBSERVE)),
            "exact admission actions differ")


def capture(captured, name, planted, session, artifacts=None):
    rgba = bytes([255, 0, 0, 255] if planted else [0, 0, 255, 255]) * (64 * 48)
    require(captured["captureId"] == "viewport" and captured["sourcePath"] == "index.html"
            and captured["path"] == "shots/viewport.png" and captured["sourceDigest"] == digest(html(planted))
            and captured["width"] == 64 and captured["height"] == 48 and captured["pixelDigest"] == digest(rgba)
            and captured["sessionId"] == session and isinstance(captured["pageId"], str) and captured["pageId"], "capture/control binding differs")
    require(re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]*/" + name + r"/index\.html", captured["url"]) is not None, "fixture URL differs")
    observed = captured["rendererObservation"]
    frame_completion(observed)
    require(observed["ready"] == "complete" and observed["background"] == ("rgb(255, 0, 0)" if planted else "rgb(0, 0, 255)")
            and observed["width"] == 64 and observed["height"] == 48 and observed["devicePixelRatio"] == 1
            and "HeadlessChrome/155." in observed["userAgent"]
            and any(b["brand"] == "Chromium" and b["version"] == VERSION for b in observed["fullVersionList"]), "renderer observation differs")
    if artifacts is not None:
        source = relative(artifacts, name + "/index.html")
        png = relative(artifacts, name + "/shots/viewport.png").read_bytes()
        require(source.read_bytes() == html(planted) and digest(png) == captured["digest"] and len(png) == captured["bytes"], "retained rendered bytes differ")
        require(png[:16] == b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' and png[16:24] == b'\x00\x00\x00@\x00\x00\x000', "PNG dimensions differ")


def validate_record(root, row, live=True, receipts=None):
    root = Path(root).resolve()
    require(row["schema"] == "legion-external-provider-accuracy/1" and row["provider"] == ID
            and row["stage"] == "finding" and row["outputKind"] == "findings"
            and row["executionPath"] == "native-sdk-frozen-plan-real-rightkit-browser-png" and type(row["modelCalls"]) is int
            and row["modelCalls"] == 0 and row["scope"] == SCOPE, "visual record identity differs")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "record digest differs")
    require(row["qualificationEligible"] is True and row["status"] == "pass" and row["coverageState"] == "complete" and row["coverageGaps"] == [], "visual controls incomplete")
    same(row["metrics"], {"truePositives": 1, "falsePositives": 0, "falseNegatives": 0, "precision": 1.0, "recall": 1.0, "positiveCases": 1, "cleanCases": 1}, "measured metrics differ")
    bound = row["binding"]
    specs = load(root / "src/registry/providers.json")["providers"]
    matches = [spec for spec in specs if spec["id"] == ID]
    require(len(matches) == 1, "shipped visual provider missing")
    # serde_json preserve_order Map::remove uses swap_remove. Promotion metadata
    # is omitted from both spec identity & source closure, never raw-hashed here.
    items = list(matches[0].items())
    index = next(i for i, (key, _) in enumerate(items) if key == "benchmark")
    items[index] = items[-1]
    items.pop()
    spec = dict(items)
    same(bound["providerSpec"], spec, "shipped spec differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)) and bound["harnessPath"] == SOURCE
            and bound["harnessDigest"] == digest((root / SOURCE).read_bytes()), "spec/harness binding stale")
    same(bound["files"], [{"path": name, "digest": digest((root / name).read_bytes())} for name in FILES], "source file binding stale")
    roots = [{"path": name, "tree": tree(root / name)} for name in ROOTS]
    same(bound["implementation"], {"digest": digest(encoded(roots)), "roots": roots}, "native implementation binding stale")
    browser = bound["browser"]
    marker = {"version": VERSION, "platform": "mac-arm64", "files": [{"kind": "chrome", "url": URL, "sha256": ARCHIVE}]}
    require(browser["versionPin"] == VERSION and browser["archiveUrl"] == URL and browser["archiveSha256"] == ARCHIVE, "renderer pin differs")
    same(browser["installerMarker"], marker, "shared installer identity differs")
    require(browser["installedTree"]["digest"] == digest(encoded(browser["installedTree"]["files"])), "installed byte inventory digest differs")
    require(any(f["path"] == browser["executable"] and f["kind"] == "file" and f["digest"] == browser["executableDigest"] for f in browser["installedTree"]["files"]), "renderer executable outside bound tree")
    artifacts = None
    if live:
        require(receipts is not None, "live receipt root required")
        artifacts = Path(row["artifactDirectory"]).resolve(strict=True)
        require(artifacts.is_relative_to(Path(receipts).resolve(strict=True)), "artifact directory outside retained output")
        installed = (Path(os.environ["RIGHTKIT_CHROME_FOR_TESTING_ROOT"]) / "current").resolve(strict=True)
        require(installed.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)), "renderer outside CI scratch")
        same(tree(installed), browser["installedTree"], "installed renderer bytes changed")
        same(load(installed / "install.json"), marker, "installed marker changed")
        require(digest(relative(installed, browser["executable"]).read_bytes()) == browser["executableDigest"], "installed executable changed")
    evidence = row["browserEvidence"]
    session = evidence["sessionId"]
    require(evidence["profileRemoved"] is True and evidence["fixtureServerJoined"] is True, "capture lifecycle incomplete")
    require(evidence["processTerminationEvidence"] == "Actual RightKit shutdown lifecycle event only; no authenticated process-tree receipt is exposed by BrowserSession::shutdown"
            and evidence["receiptBoundary"] == "RightKit BrowserSession supplies actual lifecycle/admission/network records, not EffectExecutor process receipts; native explicit visual provider supplies actual comparison result", "receipt boundary overstated")
    events = evidence["events"]
    require(all(e["session_id"] == session and e["event"] != "crash" for e in events), "browser lifecycle mismatch")
    starts, stops = ([e for e in events if e["event"] == name] for name in ("start", "stop"))
    require(len(starts) == len(stops) == 1 and starts[0]["reason"] == "launched (headless)" and stops[0]["reason"] == "shutdown"
            and type(starts[0]["pid"]) is int and starts[0]["pid"] > 0 and starts[0]["pid"] == stops[0]["pid"]
            and starts[0]["ts_ms"] <= stops[0]["ts_ms"], "browser lifecycle missing")
    cases = row["cases"]
    require([c["caseId"] for c in cases] == ["planted", "clean"], "controls missing/duplicated")
    baseline = evidence["baseline"]
    captures = [("baseline", baseline, False)] + [(c["caseId"], c["capture"], c["caseId"] == "planted") for c in cases]
    require(len({c["pageId"] for _, c, _ in captures}) == 3, "capture page reused")
    require(len(evidence["servedRequests"]) == 3
            and all(a["pageId"] in {c["pageId"] for _, c, _ in captures} for a in evidence["admissionDecisions"]),
            "admission/request inventory differs")
    for name, captured, planted in captures:
        capture(captured, name, planted, session, artifacts)
        admissions = [a for a in evidence["admissionDecisions"] if a["pageId"] == captured["pageId"]]
        capture_admissions(captured, admissions, session)
        served = [r for r in evidence["servedRequests"] if r["path"] == f"/{name}/index.html"]
        require(len(served) == 1 and served[0]["method"] == "GET" and served[0]["accepted"] is True and served[0]["bodyDigest"] == captured["sourceDigest"] and served[0]["bytes"] == len(html(planted)), "actual fixture response differs")
        require(any(n["allowed"] is True and n["url"] == captured["url"] for n in evidence["networkDecisions"]), "admitted network request missing")
    origin = baseline["url"].rsplit("/baseline/index.html", 1)[0]
    require(all(c["url"].startswith(origin + "/") for _, c, _ in captures), "fixture origins differ")
    require(all(n["allowed"] is (n["url"].startswith(origin + "/")) for n in evidence["networkDecisions"]), "network disposition differs")
    if live:
        baseline_png = relative(artifacts, "baselines/viewport.png").read_bytes()
        require(digest(baseline_png) == baseline["digest"] and len(baseline_png) == baseline["bytes"], "sealed baseline changed")
    for case, planted in zip(cases, (True, False)):
        require(case["stage"] == "finding" and case["controlMatched"] is True and case["coverageContractMatched"] is True and case["complete"] is True and case["coverageGaps"] == [], "case incomplete")
        same(case["expected"], [LABEL] if planted else [], "expected labels differ")
        same(case["actual"], case["expected"], "actual labels differ/duplicate")
        same(case["source"], {"path": "index.html", "digest": digest(html(planted))}, "source control differs")
        result, coverage = case["actualProviderResult"], case["coverage"]
        require(result["provider"] == ID and result["applicable"] is True and result["status"] == "complete" and result["complete"] is True
                and result["coverage_gaps"] == result["degradation"] == [] and "availability" not in result["details"], "native result incomplete")
        same(result["coverage"], coverage, "native coverage differs")
        require(coverage["expected"] == coverage["examined"] == 1 and coverage["gaps"] == [] and coverage["denominator_digest"] == case["selectedDenominator"]["digest"], "native denominator incomplete")
        plan = case["frozenPlan"]
        require(case["planDigest"] == digest(encoded(plan, True)) and len(plan["providers"]) == 1 and plan["providers"][0]["id"] == ID and plan["inventoryDigest"] == case["inventoryDigest"], "frozen plan identity differs")
        config = plan["providers"][0]["configuration"]
        require(config["denominatorCount"] == 1 and config["denominatorDigest"] == coverage["denominator_digest"], "plan denominator differs")
        visual = case["visualSpec"]
        same(config["runner"]["visual"], visual, "frozen visual spec differs")
        expected_spec = {"expected": {"cases": [{"route": "/", "state": "default", "viewport": "64x48"}]},
                         "captures": [{"id": "viewport", "path": "shots/viewport.png", "baseline": "viewport.png", "route": "/", "state": "default", "viewport": "64x48"}]}
        same(visual["spec"], expected_spec, "explicit visual contract differs")
        require(visual["specDigest"] == digest(encoded(expected_spec)), "spec byte identity differs")
        same(visual["baselines"]["files"], [{"path": "viewport.png", "sha256": baseline["digest"]}], "sealed baseline listing differs")
        require(visual["baselines"]["digest"] == digest(("viewport.png\0" + baseline["digest"] + "\n").encode())
                and Path(visual["baselines"]["path"]) == Path(row["artifactDirectory"]) / "baselines", "baseline seal differs")
        entries = case["selectedDenominator"]["entries"]
        require(len(entries) == 1 and entries[0]["path"] == "index.html" and entries[0]["digest"] == case["source"]["digest"], "selected source differs")
        require(coverage["denominator_digest"] == digest(encoded([case["inventoryDigest"], spec["selector"], entries], True)), "selected denominator seal differs")
        analysis = result["details"]["analysis"]
        require(analysis["complete"] is True and analysis["reviewRequired"] is False and analysis["coverageGaps"] == [] and analysis["status"] == ("fail" if planted else "pass"), "native comparison incomplete")
        matrix = analysis["coverage"]
        require(matrix["expectedCount"] == matrix["coveredCount"] == 1 and matrix["missingCount"] == 0 and matrix["complete"] is True and len(matrix["cases"]) == 1 and matrix["cases"][0]["covered"] is True, "visual matrix incomplete")
        same(analysis["denominator"], {"kind": "visual-artifacts", "expected": 1, "examined": 1}, "artifact denominator differs")
        require(len(analysis["captures"]) == 1, "capture observation count differs")
        observed = analysis["captures"][0]
        require(observed["id"] == "viewport" and observed["path"] == "shots/viewport.png" and observed["baseline"] == "viewport.png" and observed["status"] == ("different" if planted else "match"), "capture locus differs")
        diff = observed["diff"]
        for key, value in {"width": 64, "height": 48, "compared_pixels": 3072, "changed_pixels": 3072 if planted else 0,
                           "changed_ratio": 1.0 if planted else 0.0, "max_channel_delta": 255 if planted else 0,
                           "mean_channel_delta": 127.5 if planted else 0.0, "channel_threshold": 0.0, "max_changed_ratio": 0.0, "masks": []}.items():
            same(diff[key], value, "observed pixel difference differs: " + key)
        require(case["observedDiffDigest"] == digest(encoded(diff)), "diff digest differs")
        findings, details = result["findings"], result["details"]
        require(len(findings) == len(analysis["findings"]) == len(details["findingEvidence"]) == len(details["findingLocations"]) == int(planted), "finding count differs")
        if planted:
            finding = findings[0]
            require(analysis["findings"][0]["ruleId"] == "visual.regression", "actual finding rule differs")
            same(details["findingLocations"][finding["id"]], [], "artifact observation invents source line")
            expected = {"kind": "visual-artifact-difference", "captureId": "viewport",
                        "actual": {"path": "shots/viewport.png", "digest": case["capture"]["digest"], "bytes": case["capture"]["bytes"]},
                        "baseline": {"path": "viewport.png", "digest": baseline["digest"], "bytes": baseline["bytes"]},
                        "diff": diff, "specDigest": case["visualSpec"]["specDigest"]}
            same(details["findingEvidence"][finding["id"]], expected, "native finding artifact evidence differs")
    return {"provider": ID, "stage": "finding", "qualificationDigest": row["qualificationDigest"], "metrics": row["metrics"], "coverageState": "complete"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.receipts.glob("*.json"))
    require([p.name for p in paths] == ["legacy_visual-core.json"], "missing/extra visual receipt")
    record = validate_record(args.root, load(paths[0]), receipts=args.receipts)
    print("VISUAL_PROVIDER_ACCURACY_SUMMARY " + encoded({"records": [record], "modelCalls": 0}).decode())


if __name__ == "__main__":
    main()
