#!/usr/bin/env python3
"""Fixed checks for constructed ast-grep receipt; source/output are re-derived."""
import hashlib
import json
import pathlib
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def candidate_labels(rows, root):
    labels = []
    for row in rows:
        raw_file = row.get("file")
        require(isinstance(raw_file, str), "raw stream row missing file")
        candidate_path = pathlib.Path(raw_file)
        try:
            candidate_path = candidate_path.relative_to(root)
        except ValueError:
            pass
        path = candidate_path.as_posix().removeprefix("./")
        line = row.get("range", {}).get("start", {}).get("line")
        require(isinstance(line, int), "raw stream row missing source line")
        labels.append(f"{row.get('ruleId')}|{path}|{line + 1}")
    return sorted(labels)


def validate_record(repository_root, record, live=False):
    root = pathlib.Path(repository_root).resolve()
    require(isinstance(record, dict), "record must be a JSON object")
    require(isinstance(live, bool), "live must be a boolean")
    require(record.get("schema") == "legion-ast-grep-accuracy/1", "schema mismatch")
    require(record.get("providerId") == "structural.ast-grep", "provider mismatch")
    require(record.get("claimScope") == "constructed-native-sdk-artifact-fixture", "claim scope mismatch")
    require(record.get("productionQualification") is False, "must remain fixture-only")
    require(record.get("selfProducerQualification") is False, "must remain constructed SDK/artifact evidence")

    binding = record.get("sourceBinding", {})
    # Retained execution paths remain tied to their original checkout. Only
    # source/fixture byte verification is relocated to this checkout in replay.
    recorded_root = pathlib.Path(binding.get("repositoryRoot", ""))
    require(recorded_root.is_absolute() and ".." not in recorded_root.parts, "original repository root missing or noncanonical")
    if live:
        require(recorded_root == root, "live repository root differs from recorded execution root")
    bound = binding.get("files", {})
    require(bound, "source file binding missing")
    roots = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls",
        "engine/crates/legion-audit/tests/fixtures/ast-grep"]
    require(binding.get("roots") == roots, "source binding roots changed")
    expected_bound = set()
    for relative in roots:
        base = root / relative
        require(base.is_dir() and not base.is_symlink(), f"bound root absent or symlink: {relative}")
        for source in base.rglob("*"):
            if source.is_file():
                require(not source.is_symlink(), f"symlink in bound source root: {source}")
                expected_bound.add(source.relative_to(root).as_posix())
    expected_bound.update(["engine/crates/legion-audit/tests/ast_grep_accuracy.rs",
        "engine/Cargo.toml", "engine/Cargo.lock", "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml", "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml", "engine/crates/legion-rules/Cargo.toml"])
    require(set(bound) == expected_bound, "source binding file closure is incomplete or unexpected")
    required_paths = {"src/registry/rules/ast-grep/structural-core.json", "engine/Cargo.lock", "engine/Cargo.toml", "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-audit/tests/ast_grep_accuracy.rs"}
    require(required_paths <= set(bound), "fixed harness/spec/fixture source closure incomplete")
    for prefix in ("engine/crates/legion-audit/src/", "engine/crates/legion-effects/src/", "engine/crates/legion-provider-sdk/src/", "engine/crates/legion-contracts/src/"):
        require(any(path.startswith(prefix) for path in bound), f"implementation closure missing: {prefix}")
    for relative, expected_digest in bound.items():
        source = root / relative
        require(source.is_file() and not source.is_symlink(), f"bound source absent or symlink: {relative}")
        require(sha(source.read_bytes()) == expected_digest, f"bound source changed: {relative}")

    registry = json.loads((root / "src/registry/providers.json").read_text(encoding="utf-8"))
    matches = [item for item in registry["providers"] if item.get("id") == "structural.ast-grep"]
    require(len(matches) == 1, "live provider spec missing or duplicated")
    provider_spec = dict(matches[0])
    provider_spec.pop("benchmark", None)
    require(binding.get("providerSpec") == provider_spec, "sanitized provider spec differs from current registry")
    spec_bytes = json.dumps(provider_spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    require(binding.get("providerSpecDigest") == sha(spec_bytes), "sanitized provider spec digest mismatch")

    tool = record.get("tool", {})
    require(tool.get("versionToken") == "0.51.0", "actual tool version mismatch")
    require(tool.get("executablePath") and tool.get("executableDigest", "").startswith("sha256:"), "missing executable identity")
    pins = {
        "sha256:e18e13c27ed6c4b3ec4de00745b0755dee9dc26c035e226f4dd5d147dca99cc8",
        "sha256:8438fe549da59da28518c45bdaab5b851aabafe8fb4f8dc05c261a7649b4eca6",
    }
    require(tool.get("assetDigest") in pins, "asset is not an official pinned macOS release")
    executable_path = pathlib.Path(tool["executablePath"])
    if live:
        require(executable_path.is_file() and not executable_path.is_symlink(), "real provisioned executable missing")
        require(sha(executable_path.read_bytes()) == tool.get("executableDigest"), "real executable digest mismatch")
    require("0.51.0" in tool.get("rawVersionStdout", ""), "raw SDK version output missing")

    case_rows = record.get("cases", [])
    require(len(case_rows) == 2, "must retain exactly two case rows")
    cases = {item.get("id"): item for item in case_rows}
    require(len(cases) == 2 and set(cases) == {"planted", "clean"}, "duplicate or missing controls")
    expected = {
        "planted": ["no-console-error-leak|src/probe.ts|2", "no-inner-html|src/probe.ts|4"],
        "clean": [],
    }
    for case_id, literals in expected.items():
        case = cases[case_id]
        require(case.get("expected") == literals, f"{case_id}: literal expectations changed")
        fixture_root = pathlib.Path(case.get("fixtureRoot", ""))
        fixture_relative = pathlib.Path("engine/crates/legion-audit/tests/fixtures/ast-grep") / case_id
        require(fixture_root == recorded_root / fixture_relative, f"{case_id}: fixture root differs from original checked-in fixture")
        current_fixture_root = root / fixture_relative
        # No reads/stat/canonicalization of original CI paths during offline replay.
        content_root = fixture_root if live else current_fixture_root
        fixture_files = case.get("fixtureFiles", [])
        require(len(fixture_files) == 4, f"{case_id}: fixture file list incomplete")
        require(len({row.get("path") for row in fixture_files}) == 4, f"{case_id}: duplicate fixture source")
        for row in fixture_files:
            bound_fixture = f"engine/crates/legion-audit/tests/fixtures/ast-grep/{case_id}/{row['path']}"
            require(bound.get(bound_fixture) == sha(row["text"].encode()), f"{case_id}: fixture omitted from source binding: {row['path']}")
        digests = {row["path"]: sha(row["text"].encode()) for row in fixture_files}
        claimed = {row["path"]: row["digest"] for row in case.get("fixtureSourceDigests", [])}
        require(digests == claimed, f"{case_id}: fixture source digest mismatch")
        for relative, text in ((row["path"], row["text"]) for row in fixture_files):
            path = content_root / relative
            require(path.is_file() and not path.is_symlink(), f"{case_id}: fixture file missing: {relative}")
            require(path.read_text(encoding="utf-8") == text, f"{case_id}: fixture bytes changed: {relative}")

        coverage = case.get("coverage", {})
        require((coverage.get("expected"), coverage.get("examined")) == (4, 4), f"{case_id}: frozen denominator incomplete")
        require(coverage.get("gaps") == [] and coverage.get("denominatorDigest"), f"{case_id}: denominator gap or digest missing")
        supported = {"rs","ts","tsx","js","jsx","mjs","cjs","py","go","java","c","h","cpp","cc","cxx","hpp","cs","rb","php","swift","kt","kts","scala","lua","sh","bash","html","css","json","yaml","yml","ex","exs","nix"}
        expected_unsupported = sorted({pathlib.Path(row["path"]).suffix.removeprefix(".") for row in case.get("fixtureFiles", [])} - supported)
        require(case.get("unsupportedGrammars") == expected_unsupported, f"{case_id}: unsupported grammar evidence mismatch")
        result = case.get("providerResult", {})
        require(result.get("applicable") is True and result.get("complete") is True, f"{case_id}: provider incomplete")
        require(result.get("findings") == [] and result.get("coverage_gaps") == [], f"{case_id}: finding or coverage gap present")
        require(result.get("coverage", {}).get("expected") == 4 and result["coverage"].get("examined") == 4, f"{case_id}: serialized coverage mismatch")
        require(result["coverage"].get("denominator_digest") == coverage.get("denominatorDigest"), f"{case_id}: frozen digest mismatch")

        receipt = case.get("sdkReceipt", {})
        require(receipt.get("state") == "completed" and receipt.get("complete") is True, f"{case_id}: SDK command incomplete")
        require(receipt.get("providerId") == "structural.ast-grep" and receipt.get("planId"), f"{case_id}: receipt identity missing")
        require(receipt.get("policy", {}).get("allowed") is True, f"{case_id}: policy did not allow exact request")
        require(receipt.get("cwd") == str(fixture_root), f"{case_id}: SDK cwd differs from fixture root")
        require(receipt.get("processTree", {}).get("started") is True and receipt["processTree"].get("terminated") is True and receipt["processTree"].get("reaped") is True, f"{case_id}: process lifecycle incomplete")
        require(receipt.get("gaps") == [], f"{case_id}: SDK receipt gap")
        require(receipt.get("exitCode") in (0, 1), f"{case_id}: unaccepted scanner exit code")
        sandbox = receipt.get("sandbox", {})
        require(sandbox.get("required") is True and sandbox.get("networkEnabled") is True, f"{case_id}: authenticated sandbox receipt absent")
        require(sandbox.get("receiptId", "").startswith("sandbox:macos:"), f"{case_id}: not authenticated macOS sandbox")
        profile = sandbox.get("profileRaw", "")
        escaped_root = str(fixture_root).replace("\\", "\\\\").replace('"', '\\"')
        expected_profile = ('(version 1)\n(allow default)\n(deny network*)\n'
            f'(allow file-read* (subpath "{escaped_root}"))\n'
            f'(deny file-write* (subpath "{escaped_root}"))\n')
        require(profile == expected_profile, f"{case_id}: profile does not match shipped fixture-scoped denial")
        require(sha(profile.encode()) == sandbox.get("profileDigest"), f"{case_id}: sandbox profile digest mismatch")
        require(sandbox["receiptId"].endswith(sandbox["profileDigest"].removeprefix("sha256:")), f"{case_id}: sandbox ID/profile binding mismatch")
        profile_path = pathlib.Path(sandbox.get("profilePath", ""))
        if live:
            require(profile_path.is_file() and not profile_path.is_symlink(), f"{case_id}: live authenticated sandbox profile missing")
            require(sha(profile_path.read_bytes()) == sandbox.get("profileDigest"), f"{case_id}: live sandbox profile differs from retained bytes")
        executable = receipt.get("executable", {})
        wrapper = receipt.get("wrapperIdentity", {})
        require(wrapper.get("requestedPath") == "/usr/bin/sandbox-exec", f"{case_id}: native macOS wrapper absent")
        wrapper_path = pathlib.Path(wrapper.get("canonicalPath", ""))
        require(wrapper_path.is_absolute() and ".." not in wrapper_path.parts and wrapper_path.name == "sandbox-exec", f"{case_id}: wrapper canonical identity missing")
        require(wrapper.get("digest", "").startswith("sha256:"), f"{case_id}: wrapper digest absent")
        require(executable.get("requestedPath") == wrapper["requestedPath"] and executable.get("canonicalPath") == str(wrapper_path)
            and executable.get("digest") == wrapper["digest"] and executable.get("digestState") == "Sealed", f"{case_id}: SDK wrapper identity differs")
        if live:
            require(pathlib.Path("/usr/bin/sandbox-exec").resolve() == wrapper_path, f"{case_id}: native wrapper resolution differs")
            require(wrapper_path.is_file() and not wrapper_path.is_symlink() and sha(wrapper_path.read_bytes()) == wrapper["digest"], f"{case_id}: live wrapper digest differs")
        require(case.get("tool") == tool and case.get("assetDigest") == tool.get("assetDigest"), f"{case_id}: actual scanner identity differs across controls")
        require(executable.get("version", {}).get("qualified") is True, f"{case_id}: actual SDK version probe not qualified")
        require(executable["version"].get("output") == tool.get("rawVersionStdout") and "0.51.0" in executable["version"]["output"], f"{case_id}: SDK version evidence mismatch")
        require(executable["version"].get("exitCode") == 0 and executable["version"].get("skippedByPolicy") is False, f"{case_id}: version probe did not execute successfully")
        require(receipt.get("parser") == {"attempted": False, "succeeded": False, "error": None}, f"{case_id}: SDK parser receipt does not match actual executor state")
        parsing = case.get("streamParsing", {})
        require(parsing.get("attempted") is True and parsing.get("succeeded") is True, f"{case_id}: captured stream parsing failed")
        require(receipt.get("command", {}).get("args"), f"{case_id}: command args absent")
        contract = case.get("commandContract", {})
        require(contract.get("args", [])[:4] == ["scan", "--config", "sgconfig.yml", "--json=stream"], f"{case_id}: shipped command contract mismatch")
        require(contract.get("cwd") == str(fixture_root) and contract.get("executable") == tool["executablePath"], f"{case_id}: command contract scope mismatch")
        require(contract.get("timeoutMs") == 30000 and contract.get("maxOutputBytes") == 1048576, f"{case_id}: command bounds mismatch")
        decisions = case.get("policyDecisions", [])
        require(len(decisions) == 1 and decisions[0].get("allowed") is True, f"{case_id}: exact authorizer decision missing/denied")
        prefix = ["-f", str(profile_path), "--", tool["executablePath"]]
        require(profile_path.is_absolute() and ".." not in profile_path.parts, f"{case_id}: profile path is not canonical")
        require(receipt["command"].get("executable") == wrapper["requestedPath"], f"{case_id}: receipt command wrapper differs")
        require(receipt["command"].get("args") == prefix + contract["args"], f"{case_id}: wrapped scanner argv differs from shipped contract")
        require(executable["version"].get("args") == prefix + ["--version"], f"{case_id}: wrapped version probe differs from actual scanner")
        require(decisions[0].get("args") == receipt["command"].get("args")
            and decisions[0].get("versionArgs") == executable["version"]["args"]
            and decisions[0].get("executable") == wrapper["requestedPath"]
            and decisions[0].get("expectedDigest") == wrapper["digest"]
            and decisions[0].get("cwd") == str(fixture_root), f"{case_id}: authorization differs from executed wrapper/scanner request")
        expected_paths = sorted(row["path"] for row in fixture_files)
        require(contract["args"] == ["scan", "--config", "sgconfig.yml", "--json=stream", *expected_paths], f"{case_id}: frozen command paths mismatch")

        raw_rows = [json.loads(line) for line in receipt.get("stdout", {}).get("raw", "").splitlines()]
        require(len(raw_rows) == parsing.get("rowCount"), f"{case_id}: parsed stream row count mismatch")
        stdout, stderr = receipt["stdout"], receipt["stderr"]
        for output in (stdout, stderr):
            raw = output.get("raw")
            require(isinstance(raw, str), f"{case_id}: raw stream missing")
            require(len(raw.encode()) == output.get("bytes"), f"{case_id}: stream byte count mismatch")
            require(sha(raw.encode()) == output.get("digest"), f"{case_id}: raw stream digest mismatch")
            require(output.get("immutable") is True and output.get("path"), f"{case_id}: immutable artifact reference absent")
        require(stderr.get("raw") == "", f"{case_id}: unexpected stderr output")
        derived = candidate_labels(raw_rows, fixture_root)
        require(derived == literals, f"{case_id}: raw scanner stream does not derive expected observations")
        require(case.get("actual") == derived, f"{case_id}: native observations not derived from raw output")
        native_candidates = result.get("details", {}).get("candidates", [])
        projected = sorted(f"{item['ruleId']}|{item['file']}|{item['range']['start']['line']}" for item in native_candidates)
        require(projected == derived, f"{case_id}: ProviderResult candidates differ from raw scanner output")

    return {"providerId": record["providerId"], "caseCount": 2, "fixtureOnly": True}


def main(record_path, repository_root):
    record = json.loads(pathlib.Path(record_path).read_text(encoding="utf-8"))
    summary = validate_record(repository_root, record, live=True)
    print("AST_GREP_PROVIDER_ACCURACY_SUMMARY=" + json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--root" or sys.argv[3] != "--receipts":
        raise SystemExit("usage: audit-ast-grep-provider-accuracy.py --root REPOSITORY_ROOT --receipts RECEIPT_DIR")
    receipt_dir = pathlib.Path(sys.argv[4])
    files = sorted(receipt_dir.glob("*.json"))
    if len(files) != 1:
        raise SystemExit("receipt directory must contain exactly one JSON record")
    main(files[0], sys.argv[2])
