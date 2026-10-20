#!/usr/bin/env python3
"""Independently replay retained native macOS controls; no execution or CI authentication."""
import argparse
import copy
import json
from pathlib import Path, PurePosixPath
import re
import runpy

prep = runpy.run_path(str(Path(__file__).with_name("audit-mobile-native-enrollment.py")))
require, encoded, digest, parsed = (prep[name] for name in ("require", "encoded", "digest", "parsed"))
source_files = prep["source_files"]
source_digest = prep["source_digest"]
ID, FAMILY = "code.mobile", "code-mobile-sdk"
FAMILY_SCOPE = "constructed macOS SwiftPM Swift/Objective-C/Objective-C++ compiler/analyzer/XCTest controls"
SELECTOR = "native_providers::code::tools::mobile_sdk::tests::native::native_mobile_sdk_controls"
CONTROLS = ("nonempty-clean", "standalone", "planted", "malformed", "objc-compiler-failure", "test-failure", "objc-test-failure", "objcpp-test-failure", "rejected-admission", "absent-sandbox", "missing-tool", "source-drift", "enrollment-drift")
CONTRACT = {"extensions": ["swift", "m", "mm"], "variants": [["swift", ["swift"]], ["objectiveC", ["m"]], ["objectiveCpp", ["mm"]]], "tools": ["compiler", "analyzer", "test"], "requiredContext": ["platform"]}
NATIVE = ("Sources/ObjCBridge/Bridge.m", "Sources/ObjCppBridge/Bridge.mm")
CASES = ("testSwift", "testObjC", "testObjCpp")
GAPS = ["iOS/iPadOS device & simulator", "tvOS/watchOS/visionOS/Catalyst", "Xcode schemes/destinations/test plans", "project-defined flags/frameworks/dependencies"]
CODE = prep["CODE"]
COMPILED = {name: CODE + name for name in ("mobile.rs", "mobile_sdk.rs", "mobile_sdk_enrollment.rs", "mobile_sdk_tests.rs", "tools.rs", "native_commands.rs", "evidence.rs")}
COMPILED["execution_policy.rs"] = "engine/crates/legion-audit/src/execution_policy.rs"
LINT_CONFIG = "only_rules:\n  - force_cast\n  - force_try\n  - trailing_whitespace\n"


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def producer_encoded(value):
    # These seals hash serde_json::to_vec(Value), with preserve_order enabled.
    # Keep retained nested field order; enrollment seals remain canonical JSON.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def record_digest(row):
    return digest(producer_encoded({key:value for key, value in row.items() if key != "qualificationDigest"}))


def plan_digest(inventory, commands, binding):
    # Match the producer's explicit json! field order, after command replay.
    return digest(producer_encoded({"inventory":inventory, "commands":commands, "inputBinding":binding}))


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "object fields differ")


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n\\"), "absolute path malformed")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "absolute path noncanonical")
    return path


def relative(value, empty=False):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n\\"), "relative path malformed")
    if value == "" and empty:
        return PurePosixPath()
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and str(path) == value and ".." not in path.parts, "relative path noncanonical")
    return path


def fixture(control):
    files = {
        "Package.swift": '// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "MobileSDK", targets: [.target(name: "MobileSDK"), .target(name: "ObjCBridge", publicHeadersPath: "include"), .target(name: "ObjCppBridge", publicHeadersPath: "include"), .testTarget(name: "MobileSDKTests", dependencies: ["MobileSDK", "ObjCBridge", "ObjCppBridge"])])\n',
        "Sources/MobileSDK/Answer.swift": "import Foundation\npublic func answer() -> Int { return NSNumber(value: 42).intValue }\n",
        "Tests/MobileSDKTests/AnswerTests.swift": "import XCTest\n@testable import MobileSDK\nimport ObjCBridge\nimport ObjCppBridge\nfinal class AnswerTests: XCTestCase {\n    func testSwift() { XCTAssertEqual(answer(), 42) }\n    func testObjC() { XCTAssertEqual(mobile_objc_answer(), 42) }\n    func testObjCpp() { XCTAssertEqual(mobile_objcpp_answer(), 42) }\n}\n",
        "Sources/ObjCBridge/include/ObjCBridge.h": "int mobile_objc_answer(void);\n",
        NATIVE[0]: '#import <Foundation/Foundation.h>\n#include "include/ObjCBridge.h"\nint mobile_objc_answer(void) { @autoreleasepool { return [[NSNumber numberWithInt:42] intValue]; } }\n',
        "Sources/ObjCppBridge/include/ObjCppBridge.h": '#ifdef __cplusplus\nextern "C" {\n#endif\nint mobile_objcpp_answer(void);\n#ifdef __cplusplus\n}\n#endif\n',
        NATIVE[1]: '#import <Foundation/Foundation.h>\n#include "include/ObjCppBridge.h"\nnamespace mobile { int answer() { @autoreleasepool { return [[NSNumber numberWithInt:42] intValue]; } } }\nextern "C" int mobile_objcpp_answer(void) { return mobile::answer(); }\n',
    }
    if control == "planted":
        files["Sources/MobileSDK/Answer.swift"] = "import Foundation\npublic func answer() -> Int { let value: Any = NSNumber(value: 42).intValue; return value as! Int }\n"
        for path in NATIVE:
            files[path] += "int mobile_analyzer_issue(void) { int *pointer = 0; return *pointer; }\n"
    elif control == "malformed":
        files["Sources/MobileSDK/Answer.swift"] = "public func answer( -> Int {\n"
    elif control == "standalone":
        del files["Package.swift"], files["Tests/MobileSDKTests/AnswerTests.swift"]
    elif control == "objc-compiler-failure":
        for path in NATIVE:
            files[path] += "int mobile_compiler_issue(void) { return missing_symbol; }\n"
    elif control == "test-failure":
        path = "Tests/MobileSDKTests/AnswerTests.swift"
        files[path] = files[path].replace("XCTAssertEqual(answer(), 42)", "XCTAssertEqual(answer(), -1)")
    elif control in ("objc-test-failure", "objcpp-test-failure"):
        path = NATIVE[control == "objcpp-test-failure"]
        files[path] = files[path].replace("numberWithInt:42", "numberWithInt:-1")
    return dict(sorted(files.items()))


def evidence_bytes(reference, live, evidence):
    keys(reference, ("path", "digest"))
    path = absolute(reference["path"])
    if live:
        actual = Path(path)
        require(all(not parent.is_symlink() for parent in (actual, *actual.parents)), "retained path crosses symlink")
        require(actual.is_file() and not actual.is_symlink(), "retained input absent/unsafe")
        raw = actual.read_bytes()
    else:
        require(evidence is not None and str(path) in evidence, "offline original retained input absent")
        raw = evidence[str(path)]
    require(digest(raw) == reference["digest"], "retained input changed")
    return raw


def native_descriptor(value, path, sha):
    return {"path": path, "digest": sha, "fileBytes": value["fileBytes"], "sdkRoot": value["sdkRoot"], "swiftlintExecutable": value["swiftlintExecutable"], "swiftlintInvocation":value["swiftlintInvocation"],
            "roots": {name: {"root": tree["root"], "digest": tree["digest"], "entries": len(tree["files"])} for name, tree in value["roots"].items()}}


def validate_native(value, live):
    keys(value, ("schema", "host", "sdkRoot", "sdkSettingsRawBytes", "swiftlintExecutable", "swiftlintInvocation", "roots", "fileBytes", "osRuntimeBoundary", "scope"))
    require(value["schema"] == "legion-mobile-native-enrollment/1" and value["host"] in ({"os": "macos", "arch": "aarch64"}, {"os": "macos", "arch": "x86_64"})
            and value["osRuntimeBoundary"] == prep["OS_BOUNDARY"] and value["scope"] == prep["SCOPE"], "native enrollment scope differs")
    sdk, lint = absolute(value["sdkRoot"]), absolute(value["swiftlintExecutable"])
    token = "/Platforms/MacOSX.platform/Developer/SDKs/"
    require(str(sdk).count(token) == 1 and str(sdk).endswith(".sdk"), "macOS SDK root differs")
    developer = PurePosixPath(str(sdk).split(token)[0])
    roots = {"toolchain": developer / "Toolchains/XcodeDefault.xctoolchain", "macosSdk": sdk,
             "macosTestRuntime": developer / "Platforms/MacOSX.platform/Developer/Library", "developerTools": developer / "usr", "developerLibrary": developer / "Library",
             "xcodeSharedFrameworks": developer.parent / "SharedFrameworks", "xcodeVersion": developer.parent / "version.plist",
             "swiftlintRuntime": lint.parent.parent if "/Cellar/swiftlint/" in str(lint) else lint,
             "osBuild": PurePosixPath("/System/Library/CoreServices/SystemVersion.plist"), "xcrun": PurePosixPath("/usr/bin/xcrun"),
             "xcodeSelect": PurePosixPath("/usr/bin/xcode-select"), "sandboxExec": PurePosixPath("/usr/bin/sandbox-exec")}
    same(set_as_list(value["roots"]), sorted(roots), "native enrollment root denominator differs")
    total = 0
    for name, tree in value["roots"].items():
        keys(tree, ("root", "files", "digest"))
        require(absolute(tree["root"]) == roots[name] and isinstance(tree["files"], dict) and "" in tree["files"] and len(tree["files"]) <= prep["MAX_NODES"], "native tree root/denominator differs")
        require(tree["digest"] == digest(encoded(tree["files"])), "native tree digest differs")
        for name_, file in tree["files"].items():
            path = relative(name_, empty=True)
            if name_:
                parent = path.parent.as_posix()
                require(tree["files"].get("" if parent == "." else parent, {}).get("kind") == "directory", "native tree orphan entry")
            if file["kind"] == "file":
                keys(file, ("kind", "bytes", "digest"))
                require(type(file["bytes"]) is int and file["bytes"] >= 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", file["digest"]), "native file row differs")
                total += file["bytes"]
            elif file["kind"] == "directory":
                keys(file, ("kind",))
            else:
                keys(file, ("kind", "target"))
                require(file["kind"] == "symlink" and isinstance(file["target"], str) and file["target"], "native symlink row differs")
    require(type(value["fileBytes"]) is int and total == value["fileBytes"] <= prep["MAX_BYTES"], "native byte denominator differs")
    require(isinstance(value["sdkSettingsRawBytes"], list) and all(type(byte) is int and 0 <= byte <= 255 for byte in value["sdkSettingsRawBytes"]), "SDK settings original bytes malformed")
    settings_raw = bytes(value["sdkSettingsRawBytes"])
    settings_row = value["roots"]["macosSdk"]["files"]["SDKSettings.json"]
    require(settings_row["kind"] == "file" and settings_row["digest"] == digest(settings_raw) and settings_row["bytes"] == len(settings_raw), "SDK settings original bytes not enrolled")
    settings = parsed(settings_raw)
    require(settings["CanonicalName"].startswith("macosx") and isinstance(settings["Version"], str), "SDK platform metadata differs")
    for tree in value["roots"].values():
        for name, file in tree["files"].items():
            if file["kind"] != "symlink":
                continue
            require(not any(char in file["target"] for char in "\0\r\n"), "native symlink target malformed")
            link = absolute(tree["root"]) / name
            target = PurePosixPath(file["target"])
            combined = target if target.is_absolute() else link.parent / target
            normalized = []
            for part in combined.parts:
                if part == "..":
                    require(len(normalized) > 1, "native symlink escapes filesystem")
                    normalized.pop()
                elif part != ".":
                    normalized.append(part)
            target = PurePosixPath(*normalized)
            if any(target.is_relative_to(root) for root in roots.values()):
                enrolled_file(value, target, require_file=False)
            else:
                require(any(target.is_relative_to(PurePosixPath(prefix)) for prefix in ("/System/Library", "/usr/lib", "/System/Volumes/Preboot")), "native symlink outside enrolled/runtime boundary")
    invocation = value["swiftlintInvocation"]
    keys(invocation, ("path", "canonicalPath", "linkTarget"))
    invocation_path = absolute(invocation["path"])
    require(invocation["canonicalPath"] == str(lint), "SwiftLint invocation canonical target differs")
    canonical, _ = enrolled_file(value, lint)
    require(canonical == lint, "SwiftLint canonical executable is alias")
    if invocation_path != lint:
        target = PurePosixPath(invocation["linkTarget"] or "")
        require(invocation["linkTarget"] and isinstance(invocation["linkTarget"], str), "SwiftLint invocation link absent")
        combined = target if target.is_absolute() else invocation_path.parent / target
        normalized = []
        for part in combined.parts:
            if part == "..":
                require(len(normalized) > 1, "SwiftLint link escapes filesystem")
                normalized.pop()
            elif part != ".":
                normalized.append(part)
        require(PurePosixPath(*normalized) == lint, "SwiftLint invocation link differs")
    else:
        require(invocation["linkTarget"] is None, "SwiftLint direct invocation falsely aliased")
    if live:
        same(prep["capture"](Path(sdk), Path(value["swiftlintInvocation"]["path"]), Path("/nonexistent-legion-audited-fixture")), value, "live installed native closure differs")
    return roots


def enrolled_file(enrollment, path, require_file=True):
    """Resolve recorded component symlinks only; never consult validator host."""
    path = absolute(str(path))
    seen = set()
    for _ in range(64):
        require(str(path) not in seen, "native symlink cycle")
        seen.add(str(path))
        matching = [tree for tree in enrollment["roots"].values() if path.is_relative_to(absolute(tree["root"]))]
        if not matching and not require_file and any(path.is_relative_to(PurePosixPath(prefix)) for prefix in ("/System/Library", "/usr/lib", "/System/Volumes/Preboot")):
            return path, None
        require(matching, "executable outside enrolled roots")
        tree = max(matching, key=lambda tree:len(tree["root"]))
        root = absolute(tree["root"])
        parts = path.relative_to(root).parts
        restarted = False
        for length in range(len(parts) + 1):
            name = "/".join(parts[:length])
            row = tree["files"].get(name)
            require(row is not None, "native executable component missing")
            if row["kind"] == "symlink":
                target = PurePosixPath(row["target"])
                target = target if target.is_absolute() else (root.joinpath(*parts[:length]).parent / target)
                normalized = []
                for part in (target.joinpath(*parts[length:])).parts:
                    if part == "..":
                        require(len(normalized) > 1, "native symlink escapes filesystem")
                        normalized.pop()
                    elif part != ".":
                        normalized.append(part)
                path = PurePosixPath(*normalized)
                restarted = True
                break
            if length == len(parts):
                require(row["kind"] in (("file",) if require_file else ("file", "directory")), "native executable kind differs")
            else:
                require(row["kind"] == "directory", "native executable parent differs")
        if not restarted:
            return path, row.get("digest")
    raise AssertionError("native symlink depth")


def set_as_list(value):
    require(isinstance(value, dict), "object missing")
    return sorted(value)


def artifact(receipt, retained, scratch, live):
    if retained is None:
        require(receipt is None, "missing raw artifact")
        return b""
    keys(retained, ("path", "digest", "bytes", "rawBytes"))
    require(isinstance(retained["rawBytes"], list) and all(type(byte) is int and 0 <= byte <= 255 for byte in retained["rawBytes"]), "raw bytes malformed")
    raw = bytes(retained["rawBytes"])
    path = relative(retained["path"])
    same(receipt, {"path":str(path), "digest":digest(raw), "bytes":len(raw), "immutable":True}, "original SDK stream/raw linkage differs")
    require(retained["digest"] == digest(raw) and type(retained["bytes"]) is int and retained["bytes"] == len(raw), "raw artifact digest/size differs")
    if live:
        actual = Path(scratch) / "artifacts" / path
        require(all(not parent.is_symlink() for parent in (actual, *actual.parents)), "immutable stream path crosses symlink")
        require(actual.is_file() and not actual.is_symlink() and actual.read_bytes() == raw, "live immutable artifact differs")
    return raw


def native_test_lines(stdout, stderr, failed=None):
    lines = (stdout + stderr).decode("utf-8").splitlines()
    for case in CASES:
        matches = [line for line in lines if "Test Case" in line and f"AnswerTests {case}]" in line and (" passed " in line or " failed " in line)]
        require(len(matches) == 1 and (" failed " if case == failed else " passed ") in matches[0], "actual native XCTest case completion differs")


def plan_commands(files, stage, scratch, sdk):
    selected = sorted(path for path in files if path.endswith((".swift", ".m", ".mm")))
    commands = []
    def add(tool, programs, args, accepted):
        commands.append({"tool":tool, "programs":programs, "argv":args, "accepted":accepted})
    if "Package.swift" in files:
        for tool, action in (("compiler", "build"), ("test", "test")):
            args = [action, "--package-path", str(stage), "--skip-update", "--disable-automatic-resolution", "--disable-sandbox", "--cache-path", str(scratch / "cache/mobile-spm-cache"),
                    "--config-path", str(scratch / "cache/mobile-spm-config"), "--security-path", str(scratch / "cache/mobile-spm-security"), "--disable-netrc", "--disable-keychain", "--scratch-path", str(scratch / "cache/mobile-package-0")]
            add(tool, ["swift"], args, [0])
    else:
        add("compiler", ["swiftc"], ["-typecheck", "-sdk", str(sdk), "-module-cache-path", str(scratch / "cache/mobile-modules")] + [str(stage / path) for path in selected if path.endswith(".swift")], [0, 1])
    for path in selected:
        if path.endswith(".swift"):
            add("analyzer", ["swiftlint"], ["lint", "--quiet", "--no-cache", "--config", str(stage / ".legion-swiftlint.yml"), "--reporter", "json", "--strict", str(stage / path)], [0, 2])
        else:
            for tool, mode in (("compiler", "-fsyntax-only"), ("analyzer", "--analyze")):
                args = [mode, "-x", "objective-c++" if path.endswith(".mm") else "objective-c", "-isysroot", str(sdk), "-fno-color-diagnostics", "-fno-caret-diagnostics", "-fmodules-cache-path=" + str(scratch / "cache/mobile-clang-modules")]
                add(tool, ["clang"], args + (["-Xanalyzer", "-analyzer-output=text"] if tool == "analyzer" else []) + [str(stage / path)], [0, 1])
    return commands, selected


def compiler_findings(stderr, stdout, exit_code, command, files, selected, stage):
    require(stdout == b"" and exit_code in (0, 1), "compiler output/exit differs")
    findings = []
    for line in stderr.decode("utf-8").splitlines():
        match = re.fullmatch(r"(.+):([0-9]+):([0-9]+): (warning|error|fatal error): (.+)", line)
        if match:
            file, number, _, severity, message = match.groups()
            path = PurePosixPath(file)
            path = path.relative_to(stage).as_posix() if path.is_absolute() else str(path)
            require(path in selected and 0 < int(number) <= len(files[path].splitlines()) + 1, "compiler finding outside frozen denominator")
            if command["programs"] == ["clang"]:
                require(stage / path == PurePosixPath(command["argv"][-1]), "native finding wrong source")
            findings.append({"path":path, "line":int(number), "rule":"clang" if command["programs"] == ["clang"] else "swiftc", "severity":"warning" if severity == "warning" else "error", "message":" ".join(message.split())[:300]})
        else:
            require("error:" not in line and "warning:" not in line, "unmapped compiler diagnostic")
            require(not line.strip() or ": note:" in line or "|" in line or line.endswith(" generated."), "unrecognized native diagnostic output")
    require((exit_code == 1) == any(row["severity"] == "error" for row in findings), "compiler exit/diagnostic coherence differs")
    return findings


def derive_runs(case, enrollment, roots, live):
    keys(case, ("control", "matched", "fixtureRoot", "scratchRoot", "inputBinding", "plannedCommands", "plannedRequests", "planDigest", "inventoryDigest", "fixtureSources", "runs", "sdkExecutions", "gaps", "positiveNativeTestCalls"))
    control = case["control"]
    files = fixture(control)
    expected_gaps = ["mobile-context-scope:macos-host-swiftpm-and-explicit-clang-source-checks", "mobile-platform-gap:ios-ipados-tvos-watchos-visionos-catalyst-simulator-unqualified"]
    if control == "standalone":
        expected_gaps.append("mobile-swift-context-gap:standalone-host-typecheck-not-target-build")
    expected_gaps += ["mobile-objc-context-gap:default-host-flags:" + path for path in NATIVE]
    same(case["gaps"], expected_gaps, "native platform/framework gaps differ")
    same(case["positiveNativeTestCalls"], ["AnswerTests." + name for name in CASES] if control in ("nonempty-clean", "planted") else None, "native positive call declaration differs")
    require(type(case["matched"]) is bool, "native matched marker malformed")
    same(case["fixtureSources"], files, "fixture denominator/content differs")
    root, scratch = absolute(case["fixtureRoot"]), absolute(case["scratchRoot"])
    require(root.name == "source" and root.parent.name == control and scratch == root.parent / "run", "native fixture/scratch scope differs")
    stage = scratch / "tmp/mobile-sdk"
    expected_commands, selected = plan_commands(files, stage, scratch, absolute(enrollment["sdkRoot"]))
    same(case["plannedCommands"], expected_commands, "native command denominator/argv differs")
    binding = case["inputBinding"]
    keys(binding, ("bindingDigest", "inputs"))
    inputs = binding["inputs"]
    keys(inputs, ("nativeEnrollment", "schema", "root", "stage", "sources", "selected", "platform"))
    same(inputs["sources"], {path:digest(text.encode()) for path, text in files.items()}, "frozen source closure differs")
    same(inputs["selected"], selected, "selected variant denominator differs")
    require(inputs["schema"] == "legion-mobile-inputs/1" and inputs["root"] == str(root) and inputs["stage"] == str(stage)
            and binding["bindingDigest"] == digest(producer_encoded(inputs)), "input binding/root digest differs")
    keys(inputs["platform"], ("os", "arch", "sdkRoot", "sdkSettings", "sdkSettingsDigest", "sdkSettingsValue"))
    same(inputs["platform"]["sdkSettingsValue"], parsed(bytes(enrollment["sdkSettingsRawBytes"])), "platform metadata differs from original SDK bytes")
    same(inputs["platform"]["os"], "macos", "platform OS differs")
    same(inputs["platform"]["arch"], enrollment["host"]["arch"], "platform architecture differs")
    require(inputs["platform"]["sdkRoot"] == enrollment["sdkRoot"] and inputs["platform"]["sdkSettings"] == str(absolute(enrollment["sdkRoot"]) / "SDKSettings.json")
            and inputs["platform"]["sdkSettingsDigest"] == enrollment["roots"]["macosSdk"]["files"]["SDKSettings.json"]["digest"], "SDK metadata not enrolled")
    inventory = digest(encoded(files))
    require(case["inventoryDigest"] == inventory and case["planDigest"] == plan_digest(inventory, case["plannedCommands"], binding), "frozen inventory/plan seal differs")
    runs, planned, raw = case["runs"], case["plannedRequests"], case["sdkExecutions"]
    require(len(runs) == len(planned) == len(expected_commands), "native run/request denominator differs")
    no_execution = control in ("missing-tool", "source-drift", "enrollment-drift")
    require(len(raw) == (0 if no_execution else len(planned)), "original execution receipt denominator differs")
    derived, streams = [], []
    for sequence, (command, request, run) in enumerate(zip(expected_commands, planned, runs, strict=True)):
        tool = command["tool"]
        keys(run, ("tool", "programCandidates", "outcome", "receipt", "findings"))
        keys(request, ("requestId", "providerId", "planId", "policyId", "executable", "args", "versionArgs", "cwd", "expectedDigest", "environment", "allowlist", "acceptedExitCodes", "requiresNetworkSandbox", "schemaVersion", "taskId", "origin", "shell", "skipVersionProbe", "versionRequirement", "sensitiveArgumentIndexes", "sensitiveEnvironmentNames", "timeoutMs", "stdoutLimit", "stderrLimit", "sandbox"))
        require(run["tool"] == tool and run["programCandidates"] == command["programs"], "run command identity differs")
        require(request["requestId"] == f"audit:code:code.mobile:{tool}:{sequence}:{inventory}" and request["providerId"] == ID and request["planId"] == case["planDigest"] and request["taskId"] == tool and request["policyId"] == "audit", "typed request identity differs")
        require(request["schemaVersion"] == 1 and request["origin"] == "TargetProject" and request["shell"] is False and request["skipVersionProbe"] is False and request["versionRequirement"] is None
                and request["sensitiveArgumentIndexes"] == request["sensitiveEnvironmentNames"] == [] and request["timeoutMs"] == 120000 and request["stdoutLimit"] == request["stderrLimit"] == 32 * 1024**2, "typed request limits/mode differs")
        require(request["executable"] == "/usr/bin/sandbox-exec" and request["expectedDigest"] == enrollment["roots"]["sandboxExec"]["files"][""]["digest"] and request["cwd"] == str(stage)
                and request["requiresNetworkSandbox"] is True and request["acceptedExitCodes"] == command["accepted"], "native launch/sandbox differs")
        argv = request["args"]
        require(len(argv) >= 4 and argv[:1] == ["-f"] and argv[2] == "--" and argv[4:] == command["argv"], "native wrapper argv differs")
        target = absolute(argv[3])
        if command["programs"] == ["swiftlint"]:
            require(target == absolute(enrollment["swiftlintInvocation"]["path"]) and enrollment["swiftlintInvocation"]["canonicalPath"] == enrollment["swiftlintExecutable"], "SwiftLint invocation outside enrollment")
            canonical_lint = absolute(enrollment["swiftlintExecutable"])
            target_digest = enrollment["roots"]["swiftlintRuntime"]["files"][str(canonical_lint.relative_to(roots["swiftlintRuntime"])) if canonical_lint != roots["swiftlintRuntime"] else ""]["digest"]
        else:
            require(target.parent == roots["toolchain"] / "usr/bin" and target.name == command["programs"][0], "native compiler alias outside enrolled toolchain")
            _, target_digest = enrolled_file(enrollment, target)
        require(target_digest is not None, "native executable content missing from enrollment")
        profile = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "{str(stage).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"))\n'.encode()
        sandbox_id = "sandbox:macos:" + digest(profile).split(":")[1]
        require(request["sandbox"] == {"id":sandbox_id,"network":True,"filesystemScope":str(stage)}
                and absolute(argv[1]) == scratch / "sandbox" / ("audit-" + digest(profile).split(":")[1] + ".sb")
                and request["versionArgs"] == argv[:4] + ["--version"], "authenticated native profile/version differs")
        env = request["environment"]
        base_allowed = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "CARGO_TARGET_DIR", "npm_config_cache", "RUFF_CACHE_DIR", "MYPY_CACHE_DIR", "PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GOCACHE", "GIT_CONFIG_NOSYSTEM", "NO_COLOR", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR", "CFFIXED_USER_HOME", "SDKROOT", "TOOLCHAIN_DIR", "XCODE_DEFAULT_TOOLCHAIN_OVERRIDE", "DEVELOPER_DIR", "LEGION_MOBILE_FROZEN_BINDING_DIGEST"}
        optional = {"CARGO_HOME", "RUSTUP_HOME", "GOPATH", "GOROOT", "GOMODCACHE"}
        same(request["allowlist"], sorted(base_allowed | (set(env) & optional)), "native environment allowlist expanded")
        require(set(env) <= set(request["allowlist"]) and env["HOME"] == env["CFFIXED_USER_HOME"] == str(scratch / "tmp/mobile-home")
                and env["SDKROOT"] == enrollment["sdkRoot"] and env["TOOLCHAIN_DIR"] == env["XCODE_DEFAULT_TOOLCHAIN_OVERRIDE"] == str(roots["toolchain"])
                and env["DEVELOPER_DIR"] == str(roots["developerTools"].parent) and env["LEGION_MOBILE_FROZEN_BINDING_DIGEST"] == binding["bindingDigest"], "native environment/platform binding differs")
        for name in ("TMPDIR", "TEMP", "TMP"):
            require(env[name] == str(scratch / "tmp"), "native temp scope differs")
        for name, directory in {"XDG_CACHE_HOME":"xdg", "CARGO_TARGET_DIR":"cargo-target", "npm_config_cache":"npm", "RUFF_CACHE_DIR":"ruff", "MYPY_CACHE_DIR":"mypy", "PYTHONPYCACHEPREFIX":"pycache", "GOCACHE":"go-build"}.items():
            require(env[name] == str(scratch / "cache" / directory), "native cache scope differs")
        for name, value in {"PYTHONDONTWRITEBYTECODE":"1", "PYTHONNOUSERSITE":"1", "GIT_CONFIG_NOSYSTEM":"1", "NO_COLOR":"1", "CARGO_NET_OFFLINE":"true", "CARGO_TERM_COLOR":"never"}.items():
            require(env[name] == value, "native inherited execution setting differs")
        if no_execution:
            require(run["receipt"] is None and run["findings"] == [], "pre-execution refusal contains execution/finding")
            expected_outcome = "Missing" if control == "missing-tool" else 'Failed("tool-failed:' + tool + ':input-before:' + ("mobile-source-changed" if control == "source-drift" else "mobile-native-enrollment-changed") + '")'
            require(run["outcome"] == expected_outcome, "pre-execution refusal reason differs")
            derived.append([])
            continue
        observed = raw[sequence]
        keys(observed, ("request", "controlRemovedSandboxEvidence", "originalSandboxId", "executionReceipt", "stdout", "stderr"))
        actual_request = copy.deepcopy(request)
        if control == "absent-sandbox":
            actual_request["sandbox"] = None
        same(observed["request"], actual_request, "original executed request differs from frozen native request")
        require(observed["controlRemovedSandboxEvidence"] is (control == "absent-sandbox") and observed["originalSandboxId"] == sandbox_id, "sandbox negative control differs")
        receipt = observed["executionReceipt"]
        summary = run["receipt"]
        require(receipt["schemaVersion"] == 1 and receipt["receiptId"] == "receipt:" + request["requestId"], "original SDK receipt identity differs")
        same(summary["sdkReceipt"], receipt, "provider original SDK receipt differs")
        require(receipt["requestId"] == request["requestId"] and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["policyId"] == ("audit-native-owner-admission-v1" if control == "rejected-admission" else "legion-mobile-constructed-exact-sdk-v1") and receipt["taskId"] == tool, "SDK receipt typed identity differs")
        if control in ("rejected-admission", "absent-sandbox"):
            expected = "AdmissionUnavailable" if control == "rejected-admission" else "SandboxMissing"
            require(run["outcome"] == expected and receipt["processTree"]["started"] is False and receipt["complete"] is False and receipt["exitCode"] is None
                    and observed["stdout"] is observed["stderr"] is None and run["findings"] == [], "refusal became native success")
            require(receipt["state"] == ("unauthorized_effect" if control == "rejected-admission" else "sandbox_missing"), "SDK refusal state differs")
            if control == "absent-sandbox":
                same(receipt["sandbox"], {"required":True,"receiptId":None,"networkEnabled":False}, "sandbox refusal requirement disabled")
            if control == "rejected-admission":
                require(receipt["policy"]["allowed"] is False and receipt["policy"]["id"] == "audit-native-owner-admission-v1" and receipt["policy"]["reason"] == "native-owner-admission-unavailable", "production denial policy was replaced")
            derived.append([])
            continue
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["policy"]["digest"]) is not None and receipt["policy"]["reason"] == "exact constructed mobile SDK fixture only; no CLI owner admission", "exact SDK authorizer receipt differs")
        require(receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == "legion-mobile-constructed-exact-sdk-v1" and receipt["policy"]["version"] == 1
                and receipt["sandbox"] == {"required":True,"receiptId":sandbox_id,"networkEnabled":True}, "native admission/sandbox receipt differs")
        require(receipt["processTree"]["started"] is True and receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True and receipt["processTree"]["hardKilled"] is False and receipt["signal"] is None, "native process lifecycle incomplete")
        require(receipt["cwd"] == request["cwd"] and receipt["environmentNames"] == sorted(env), "SDK cwd/environment differs")
        same(receipt["command"], {"executable":request["executable"], "args":request["args"], "environmentNames":sorted(env), "redactedArgumentIndexes":[], "redactedEnvironmentNames":[]}, "SDK original command differs")
        timing = receipt["timing"]
        require(all(type(timing[key]) is int and timing[key] >= 0 for key in ("startedAtMs", "completedAtMs", "durationMs")) and timing["completedAtMs"] >= timing["startedAtMs"], "SDK lifecycle timing absent")
        require(receipt["parser"] == {"attempted":False,"succeeded":False,"error":None}, "SDK execution receipt parser state differs")
        identity = receipt["executable"]
        require(identity["requestedPath"] == identity["canonicalPath"] == request["executable"] and identity["digestState"] == "sealed" and identity["digest"] == request["expectedDigest"] and identity["version"]["qualified"] is True and identity["version"]["exitCode"] == 0
                and identity["version"]["args"] == request["versionArgs"] and identity["version"]["skippedByPolicy"] is False and identity["version"]["output"].strip(), "native real version/launcher identity missing")
        require(summary["nativeToolIdentity"]["digest"] == target_digest and absolute(summary["nativeToolIdentity"]["path"]) == target, "native executable identity differs")
        same(summary["nativeInputSnapshots"]["before"], binding, "executed native input binding differs")
        same(summary["nativeInputSnapshots"]["after"], binding, "executed native inputs drifted")
        require(summary["nativeInputSnapshots"]["unchanged"] is True and summary["nativeInputSnapshots"]["afterError"] is None, "native input closure incomplete")
        require(observed["stdout"] is not None and observed["stderr"] is not None, "native original immutable stream absent")
        stdout, stderr = (artifact(receipt[name], observed[name], scratch, live) for name in ("stdout", "stderr"))
        require(summary["executableDigest"] == target_digest and summary["artifactDigest"] == digest(stdout) and summary["stderrDigest"] == digest(stderr)
                and summary["receiptId"] == receipt["receiptId"] and summary["exitCode"] == receipt["exitCode"] and summary["state"] == receipt["state"] and summary["complete"] is receipt["complete"]
                and summary["version"] == next((line.strip() for line in identity["version"]["output"].splitlines() if line.strip()), "") and summary["durationMs"] == receipt["timing"]["durationMs"], "provider native receipt projection differs")
        exit_code = receipt["exitCode"]
        findings = []
        accepted = exit_code in command["accepted"]
        if command["programs"] == ["swift"]:
            accepted = accepted and exit_code == 0
        elif command["programs"] == ["swiftlint"] and accepted:
            require(stderr == b"", "SwiftLint emitted unparsed stderr")
            violations = parsed(stdout)
            require(isinstance(violations, list) and (exit_code == 0) is (not violations), "SwiftLint exit/record mismatch")
            for violation in violations:
                path = absolute(violation["file"]).relative_to(stage).as_posix()
                require(str(stage / path) == command["argv"][-1] and path in selected and type(violation["line"]) is int and 0 < violation["line"] <= len(files[path].splitlines()) + 1
                        and violation["severity"] in ("Warning", "Error") and violation["rule_id"] in ("force_cast", "force_try", "trailing_whitespace") and violation["reason"].strip(), "SwiftLint finding outside source contract")
                findings.append({"path":path,"line":violation["line"],"rule":"swiftlint:" + violation["rule_id"],"severity":violation["severity"].lower(),"message":" ".join(violation["reason"].split())[:300]})
        elif accepted:
            findings = compiler_findings(stderr, stdout, exit_code, command, files, selected, stage)
        same(receipt["gaps"], [] if accepted else ["failed"], "SDK process/coverage gap differs")
        if accepted:
            require(receipt["state"] == "completed" and receipt["complete"] is True and run["outcome"] == "Ran", "successful native run incomplete")
            same(run["findings"], findings, "provider findings differ from original native output")
        else:
            require(exit_code is not None and exit_code != 0 and receipt["state"] == "failed" and receipt["complete"] is False
                    and run["outcome"] == f'Failed("tool-failed:{tool}:exit-{exit_code}")' and run["findings"] == [], "failed native command became pass")
        derived.append(findings)
        streams.append((tool, command, stdout, stderr, exit_code))
    if control in ("nonempty-clean", "standalone"):
        require(all(run["outcome"] == "Ran" for run in runs) and not any(derived), "nonempty native clean control failed")
    if control == "planted":
        require(all(run["outcome"] == "Ran" for run in runs), "planted native runs incomplete")
        require(any(row["rule"] == "swiftlint:force_cast" and row["path"] == "Sources/MobileSDK/Answer.swift" for rows in derived for row in rows), "Swift analyzer planted finding missing")
        for path in NATIVE:
            require(any(row["path"] == path and row["rule"] == "clang" and "null" in row["message"].lower() for rows in derived for row in rows), "native analyzer planted finding missing")
    if control == "objc-compiler-failure":
        for path in NATIVE:
            require(any(row["path"] == path and row["severity"] == "error" and "missing_symbol" in row["message"] for rows in derived for row in rows), "native compiler failure control missing")
    if control == "malformed":
        require(any(tool == "compiler" and exit_code != 0 for tool, _, _, _, exit_code in streams), "malformed source did not fail real compiler")
    failed = {"test-failure":"testSwift", "objc-test-failure":"testObjC", "objcpp-test-failure":"testObjCpp"}.get(control)
    if control in ("nonempty-clean", "planted") or failed:
        tests = [row for row in streams if row[0] == "test"]
        require(len(tests) == 1 and tests[0][4] == (1 if failed else 0), "native XCTest exit differs")
        native_test_lines(tests[0][2], tests[0][3], failed)
    return len(raw)


def validate_record(root, row, live=False, evidence=None):
    keys(row, ("schema", "family", "stage", "scope", "retainedRoot", "repositoryRoot", "modelCalls", "qualificationEligible", "productionQualification", "status", "sourceEnrollment", "compiledSourceBinding", "provider", "contract", "matrixState", "boundedMacosKnownAnswerEligible", "wholePlatformQualified", "productionOwnerAdmissionQualified", "admissionScope", "nativeEnrollment", "boundedScope", "outsideBoundedMacosScope", "cases", "qualificationDigest"))
    require(row["schema"] == "legion-mobile-sdk-controls/2" and row["provider"] == ID and row["family"] == FAMILY and row["stage"] == "finding" and row["scope"] == FAMILY_SCOPE, "dedicated mobile identity/scope differs")
    require(row["qualificationDigest"] == record_digest(row), "mobile original record digest differs")
    require(row["productionQualification"] is row["wholePlatformQualified"] is row["productionOwnerAdmissionQualified"] is False and row["modelCalls"] == 0 and type(row["modelCalls"]) is int
            and row["matrixState"] == "complete" and row["status"] == "observed-known-answer-controls", "mobile scope/terminal state differs")
    require(row["admissionScope"] == "constructed exact SDK admission; production owner admission remains denied" and row["boundedScope"] == "macOS host SwiftPM: Swift + Objective-C + Objective-C++, Foundation + XCTest; SwiftLint & clang analyzer", "native bounded admission/framework scope differs")
    same(row["contract"], CONTRACT, "original mobile tool/variant/platform contract changed")
    same(row["outsideBoundedMacosScope"], GAPS, "unsupported platform/framework gaps removed")
    same(row["compiledSourceBinding"], {name:digest((root / path).read_bytes()) for name, path in COMPILED.items()}, "compiled native source binding differs")
    original_root = absolute(row["repositoryRoot"])
    require(not live or original_root == PurePosixPath(str(root.resolve())), "live original repository root differs")
    retained = absolute(row["retainedRoot"])
    require(retained.name == "code-mobile" and retained.parent.name == "legion-provider-qualification" and not retained.is_relative_to(absolute(row["repositoryRoot"])), "original retained root differs")
    source = row["sourceEnrollment"]
    keys(source, ("path", "digest", "before", "after"))
    require(absolute(source["path"]) == retained / "mobile-source-enrollment.json", "prepared source layout differs")
    source_bytes = evidence_bytes({key:source[key] for key in ("path", "digest")}, live, evidence)
    observed_source = parsed(source_bytes)
    keys(observed_source, ("schema", "root", "files", "digest", "registryRawDigest"))
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", observed_source["registryRawDigest"]) is not None, "original registry raw digest absent")
    require(not live or observed_source["registryRawDigest"] == prep["file_hash"](root / "src/registry/providers.json"), "live raw provider registry drifted")
    same(source["before"], observed_source, "prepared source closure not observed before execution")
    same(source["after"], observed_source, "full source closure drifted during execution")
    same(observed_source["files"], {path:source_digest(root, path) for path in source_files(root)}, "full source closure denominator/content differs")
    require(observed_source["schema"] == "legion-mobile-source-enrollment/1" and observed_source["root"] == row["repositoryRoot"] and observed_source["digest"] == digest(encoded(observed_source["files"])), "source enrollment seal differs")
    native = row["nativeEnrollment"]
    keys(native, ("path", "digest", "before", "after", "observedBefore", "observedAfter"))
    require(absolute(native["observedBefore"]["path"]) == retained / "mobile-native-enrollment.json" and absolute(native["observedAfter"]["path"]) == retained / "mobile-native-after.json", "native before/after retained layout differs")
    before_bytes = evidence_bytes(native["observedBefore"], live, evidence)
    after_bytes = evidence_bytes(native["observedAfter"], live, evidence)
    before, after = parsed(before_bytes), parsed(after_bytes)
    same(before, after, "full before/after native toolchain closure differs")
    roots = validate_native(before, live)
    require(native["path"] == native["observedBefore"]["path"] and native["digest"] == native["observedBefore"]["digest"], "native enrollment preparation binding differs")
    descriptor = native_descriptor(before, native["path"], native["digest"])
    same(native["before"], descriptor, "native before descriptor differs from full observed closure")
    same(native["after"], descriptor, "native after descriptor differs from full observed closure")
    require([case["control"] for case in row["cases"]] == list(CONTROLS), "mobile control matrix incomplete/duplicate/reordered")
    count = 0
    base = absolute(row["cases"][0]["fixtureRoot"]).parent.parent
    require(re.fullmatch(r"mobile-[0-9]+-[0-9]+", base.name), "native fixture matrix identity malformed")
    for case in row["cases"]:
        require(absolute(case["fixtureRoot"]).parent.parent == base, "native case escaped original matrix root")
        require(not absolute(case["fixtureRoot"]).is_relative_to(absolute(row["repositoryRoot"])), "fixture overlaps repository")
        same(case["inputBinding"]["inputs"]["nativeEnrollment"], descriptor, "case source/platform enrollment differs")
        count += derive_runs(case, before, roots, live)
    # Eligibility is a result of replay above, never taken from matched/eligible flags.
    require(row["qualificationEligible"] is True and row["boundedMacosKnownAnswerEligible"] is True, "producer did not retain completed bounded result")
    return {"provider":ID,"family":FAMILY,"stage":"finding","scope":FAMILY_SCOPE,"qualificationEligible":True,
            "productionQualification":False,"wholePlatformQualified":False,"productionOwnerAdmissionQualified":False,
            "controls":len(CONTROLS),"nativeExecutions":count,"qualificationDigest":row["qualificationDigest"],"validatorRejectionControls":17}


def artifact_locator(row, raw):
    return {"provider":ID,"path":str(absolute(row["retainedRoot"]) / "code_mobile.json"),"sha256":digest(raw),"bytes":len(raw),
            "qualificationDigest":row["qualificationDigest"],"qualificationEligible":True,"productionQualification":False}


def erase_native_case(record):
    # Preserve artifact digest/size & original receipt linkage while erasing
    # one actual native assertion: structural checksum checks cannot catch this.
    case = record["cases"][0]
    observed = case["sdkExecutions"][1]
    for stream in ("stdout", "stderr"):
        retained = observed[stream]
        raw = bytes(retained["rawBytes"]).replace(b"testObjCpp", b"ignoredCase")
        retained.update(rawBytes=list(raw), digest=digest(raw), bytes=len(raw))
        observed["executionReceipt"][stream].update(digest=digest(raw), bytes=len(raw))
    summary = case["runs"][1]["receipt"]
    summary["sdkReceipt"] = copy.deepcopy(observed["executionReceipt"])
    summary["artifactDigest"] = observed["stdout"]["digest"]
    summary["stderrDigest"] = observed["stderr"]["digest"]


def rejection_controls(root, row, evidence):
    edits = [lambda r:r.update(productionQualification=True), lambda r:r.update(wholePlatformQualified=True),
             lambda r:r.update(productionOwnerAdmissionQualified=True), lambda r:r["cases"].pop(),
             lambda r:r["contract"]["variants"].pop(), lambda r:r["contract"]["tools"].remove("test"),
             lambda r:r["sourceEnrollment"]["after"]["files"].pop(next(iter(r["sourceEnrollment"]["after"]["files"]))),
             lambda r:r["nativeEnrollment"]["after"].update(fileBytes=0), lambda r:r["cases"][0]["plannedRequests"].pop(),
             lambda r:r["cases"][0]["sdkExecutions"].pop(), lambda r:r["cases"][0]["sdkExecutions"][0]["executionReceipt"].update(complete=False),
             lambda r:r["cases"][0]["sdkExecutions"][0]["stdout"]["rawBytes"].append(0),
             lambda r:r["cases"][0]["plannedRequests"][0].update(requiresNetworkSandbox=False),
             lambda r:r["cases"][1]["inputBinding"]["inputs"]["selected"].pop(),
             lambda r:r["cases"][2]["runs"][3]["findings"].clear(), lambda r:r["outsideBoundedMacosScope"].clear(), erase_native_case]
    for edit in edits:
        modified = copy.deepcopy(row)
        edit(modified)
        modified["qualificationDigest"] = record_digest(modified)
        try:
            validate_record(root, modified, evidence=evidence)
        except (AssertionError, KeyError, ValueError, TypeError, IndexError):
            continue
        raise AssertionError("tampered/incomplete mobile native record accepted")
    return len(edits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    require(args.receipts.name == "code-mobile" and args.receipts.parent.name == "legion-provider-qualification", "dedicated retained mobile root differs")
    raw = (args.receipts / "code_mobile.json").read_bytes()
    row = parsed(raw)
    require(absolute(row["retainedRoot"]) == PurePosixPath(str(args.receipts)), "native original receipt root differs")
    result = validate_record(args.root.resolve(), row, live=True)
    evidence = {reference["path"]:Path(reference["path"]).read_bytes() for reference in
                (row["nativeEnrollment"]["observedBefore"], row["nativeEnrollment"]["observedAfter"], row["sourceEnrollment"])}
    require(rejection_controls(args.root.resolve(), row, evidence) == result["validatorRejectionControls"], "mobile validator tamper coverage incomplete")
    print("CODE_MOBILE_SDK_ACCURACY_SUMMARY " + encoded({"records":[result],"modelCalls":0}).decode())


if __name__ == "__main__":
    main()
