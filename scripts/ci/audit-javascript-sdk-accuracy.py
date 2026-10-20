#!/usr/bin/env python3
"""Replay original native JS/TS SDK observations; never execute tools or mint receipts.

Known-answer fixture accuracy only. Authenticated GitHub retrieval/registration
remain separate maintainer-owned gates; production owner admission stays denied.
"""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
import runpy

HARNESS = "engine/crates/legion-audit/tests/real_javascript_sdk_accuracy.rs"
HELPER = "scripts/ci/audit-javascript-sdk-bootstrap.py"
INPUTS = "scripts/ci/audit-javascript-sdk-inputs.json"
SELF = "scripts/ci/audit-javascript-sdk-accuracy.py"
FIXTURES = "scripts/ci/fixtures/audit-javascript-sdk"
POLICY = "legion-real-javascript-sdk-fixture-v1"
FAMILY_SCOPE = "known-answer-fixture-cases"
PROVIDER = "code.javascript"
EXTENSIONS = ("js", "cjs", "mjs", "ts", "cts", "mts", "jsx", "tsx")
CONTROLS = ("nonempty-clean",) + tuple("positive-" + e for e in EXTENSIONS) + (
    "build-failure", "test-failure", "build-noop", "test-noop", "test-empty", "test-unmet-plan", "malformed", "missing-tool", "rejected-admission",
    "absent-sandbox", "source-tamper", "tool-tamper", "scope-omission", "missing-manager", "manager-mismatch")
TASKS = ("type", "lint", "build", "test")
CONTRACT = {"extensions": ["js", "jsx", "ts", "tsx", "cjs", "mjs", "cts", "mts"],
            "variants": [["javascript", ["js", "cjs", "mjs"]], ["typescript", ["ts", "cts", "mts"]],
                         ["jsx", ["jsx"]], ["tsx", ["tsx"]]],
            "tools": list(TASKS), "requiredContext": []}
SOURCE_ROOTS = ["engine/crates/" + c + "/src" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, HELPER, INPUTS, SELF] + ["engine/crates/" + c + "/Cargo.toml" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]
RECEIPT_FIELDS = {"schemaVersion", "receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "stdout", "stderr", "parser", "gaps"}


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite JSON"))


def same(actual, expected, reason):
    require(encoded(actual) == encoded(expected), reason)


def relative(value):
    p = PurePosixPath(value)
    require(value and not p.is_absolute() and str(p) == value and "\\" not in value and ".." not in p.parts, "unsafe relative path")
    return p


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n"), "invalid absolute path")
    p = PurePosixPath(value)
    require(p.is_absolute() and str(p) == value and ".." not in p.parts and not value.startswith("//"), "noncanonical absolute path")
    return p


def source(root, value):
    p = root
    for part in relative(value).parts:
        p /= part
        require(not p.is_symlink(), "source symlink")
    require(p.is_file(), "source missing: " + value)
    return p


def read(path, limit=256 * 1024 * 1024):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "retained input size/kind")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
    after = path.lstat()
    require(len(data) <= limit and len(data) == before.st_size == opened.st_size == after.st_size
            and (before.st_dev, before.st_ino, before.st_mtime_ns) == (opened.st_dev, opened.st_ino, opened.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_mtime_ns), "retained input grew/changed")
    return data


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    files = set(SOURCE_FILES)
    for directory in SOURCE_ROOTS:
        base = root / directory
        require(base.is_dir() and not base.is_symlink(), "source root missing")
        for p in base.rglob("*"):
            require(not p.is_symlink(), "source closure symlink")
            if p.is_file():
                if generated_session_provenance(p.relative_to(root).as_posix()):
                    continue
                files.add(p.relative_to(root).as_posix())
    return {p: digest(read(source(root, p), 32 * 1024 * 1024)) for p in sorted(files)}


BUILD_SCRIPT = 'tsc --project tsconfig.build.json --outDir "$LEGION_AUDIT_JS_OUTPUT" --listEmittedFiles --pretty false --noCheck --sourceMap --inlineSources'
TEST_SCRIPT = 'node --test --test-reporter=tap test.mjs'
TEST_PREAMBLE = "import test from 'node:test';\nimport path from 'node:path';\nimport {pathToFileURL} from 'node:url';\nconst output = process.env.LEGION_AUDIT_JS_OUTPUT;\nif (!output || !path.isAbsolute(output)) throw new Error('explicit scratch output required');\n"
TEST_BLOCK = re.compile(r"\{\n  const loaded = await import\(pathToFileURL\(path.join\(output, '([A-Za-z0-9_./-]+)'\)\).href\);\n  test\('([A-Za-z0-9_./-]+)', \{plan:1\}, \(t\) => \{\n    t.assert.strictEqual\(\(loaded.answer \|\| loaded.default.answer\)\(\),(-?[0-9]+)\);\n  \}\);\n\}\n")


def assertion_module(text):
    if text.startswith("debugger;\n"):
        text = text[len("debugger;\n"):]
    for prefix in ("const bad: number = 'wrong';\n", "/** @type {number} */ const bad = 'wrong';\n"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    require(re.fullmatch(r"(?:export function answer\(\) \{ return -?[0-9]+; \}\n|function answer\(\) \{ return -?[0-9]+; \}\nmodule.exports = \{answer\};\n|function h\(_type, _props\) \{ return -?[0-9]+; \}\nconst view = <span />;\nexport function answer\(\) \{ return view; \}\n)", text) is not None, "unsupported imported module semantics")


def planned_assertions(text):
    require(text.startswith(TEST_PREAMBLE), "unsupported planned-test preamble")
    text = text[len(TEST_PREAMBLE):]
    out = []
    while text:
        match = TEST_BLOCK.match(text)
        require(match is not None, "unsupported planned-test source material")
        output, source_path, _ = match.groups()
        relative(output)
        relative(source_path)
        require(source_path not in {s for s, _ in out}, "duplicate planned-test source")
        out.append((source_path, output))
        text = text[match.end():]
    require(out, "no planned native assertions")
    return out


def strict_tsc(text, cwd, allowed, exit_code):
    located = re.compile(r"^(.+?)\(([1-9][0-9]*),([1-9][0-9]*)\): (error|warning) (TS[0-9]+): (.+)$")
    listed, diagnostics, detail = set(), [], False
    for line in text.splitlines():
        if not line.strip():
            continue
        match = located.fullmatch(line)
        if match:
            diagnostics.append(match.groups())
            detail = True
            continue
        if detail and line.startswith("  "):
            continue
        detail = False
        path = absolute(line)
        require(line.startswith(str(cwd) + "/") and str(path.relative_to(cwd)) in allowed and line not in listed, "unrecognized TSC output/duplicate/unbound input")
        require(path.suffix in (".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs", ".cts", ".mts", ".json"), "malformed TSC file-list material")
        listed.add(line)
    require(listed and exit_code in (0, 1, 2) and (exit_code == 0) == (not diagnostics), "TSC exit/diagnostic scope mismatch")
    return {str(PurePosixPath(p).relative_to(cwd)) for p in listed}


def operation_replay(task, proof, observed, emitted, files, cwd, output):
    import posixpath
    import math
    require(proof["schema"] == "legion-javascript-operation-observation/1", "operation observation schema differs")
    script = parsed(files["package.json"])["scripts"][task]
    require(script == (BUILD_SCRIPT if task == "build" else TEST_SCRIPT) and proof["script"] == script, "native script grammar differs")
    require(observed[1] == "$ " + script + "\n", "pinned pnpm native lifecycle stderr differs")
    same(proof["artifacts"], emitted, "operation artifact bytes differ from retained native observations")
    mapped = {}
    for name, descriptor in emitted.items():
        relative(name)
        raw = bytes(descriptor["rawBytes"])
        require(len(raw) == descriptor["bytes"] and digest(raw) == descriptor["digest"], "native output bytes unbound")
        if not name.endswith(".map"):
            continue
        code = name[:-4]
        require(code in emitted, "source map lacks actual emitted module")
        value = parsed(raw)
        require(value["version"] == 3 and value["file"] == PurePosixPath(code).name and value["sourceRoot"] == ""
                and len(value["sources"]) == len(value["sourcesContent"]) == 1 and isinstance(value["mappings"], str) and value["mappings"], "source map shape differs")
        original = posixpath.normpath(str(output / name) + "/../" + value["sources"][0])
        require(original.startswith(str(cwd) + "/"), "source map points outside frozen source")
        original = str(PurePosixPath(original).relative_to(cwd))
        require(original in files and original not in mapped and value["sourcesContent"][0] == files[original], "source map frozen input binding differs")
        code_bytes = bytes(emitted[code]["rawBytes"])
        require(code_bytes and code_bytes.decode().rstrip().endswith("//# sourceMappingURL=" + PurePosixPath(name).name), "emitted code/source map reference differs")
        mapped[original] = code
    selected = {p for p in files if p.rsplit(".", 1)[-1] in EXTENSIONS}
    require(len(emitted) == len(mapped) * 2 and selected - {p for p in selected if p.endswith((".d.ts", ".d.cts", ".d.mts"))} <= mapped.keys(), "emitted source coverage incomplete")
    same(proof["sourceToOutput"], mapped, "producer compiler mapping differs")
    lines = [s for s in observed[0].splitlines() if s]
    if task == "build":
        require(proof["kind"] == "typescript-emission", "build observation kind differs")
        expected = {"TSFILE: " + str(output / name) for name in emitted}
        require(len(lines) == len(expected) and set(lines) == expected, "actual native emitted-file list differs")
    else:
        require(proof["kind"] == "node-planned-assertions" and proof["testSource"] == "test.mjs"
                and proof["testSourceDigest"] == digest(files["test.mjs"].encode()), "planned assertion source binding differs")
        plans = planned_assertions(files["test.mjs"])
        asserted = {s for s, _ in plans}
        for source_path, _ in plans:
            assertion_module(files[source_path])
        require(proof["moduleSemantics"] == "closed-pure-answer-forms/1", "imported module semantics binding differs")
        require(all(mapped.get(s) == out for s, out in plans) and selected - {"test.mjs", "eslint.config.mjs", "globals.d.ts"} <= asserted, "planned assertion scope incomplete")
        require(proof["assertionCount"] == len(plans) and proof["assertedSourcePaths"] == sorted(asserted), "planned assertion accounting differs")
        expected = ["TAP version 13"]
        for i, (name, _) in enumerate(plans, 1):
            expected += ["# Subtest: " + name, f"ok {i} - {name}", "  ---", None, "  type: 'test'", "  ..."]
        n = len(plans)
        expected += [f"1..{n}", f"# tests {n}", "# suites 0", f"# pass {n}", "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0", False]
        require(len(lines) == len(expected), "actual TAP result denominator differs")
        for actual, wanted in zip(lines, expected):
            if wanted is None or wanted is False:
                prefix = "  duration_ms: " if wanted is None else "# duration_ms "
                require(actual.startswith(prefix), "native TAP duration shape differs")
                duration = float(actual[len(prefix):])
                require(math.isfinite(duration) and duration >= 0, "native TAP duration invalid")
            else:
                require(actual == wanted, "native TAP plan/result mismatch")
    return mapped


def fixture(root, control):
    base = root / FIXTURES / "clean"
    files = {p.name: source(root, p.relative_to(root).as_posix()).read_text() for p in base.iterdir()}
    if control.startswith("positive-"):
        ext = control.removeprefix("positive-")
        require(ext in EXTENSIONS, "unknown planted extension")
        bad = "const bad: number = 'wrong';\n" if ext in ("ts", "cts", "mts", "tsx") else "/** @type {number} */ const bad = 'wrong';\n"
        files["answer_" + ext + "." + ext] = "debugger;\n" + bad + files["answer_" + ext + "." + ext]
    elif control == "build-failure":
        files["tsconfig.build.json"] = "{ invalid build configuration\n"
    elif control == "test-failure":
        files["test.mjs"] = files["test.mjs"].replace("(),42)", "(),43)")
    elif control in ("build-noop", "test-noop"):
        manifest = parsed(files["package.json"])
        manifest["scripts"]["build" if control == "build-noop" else "test"] = "node -e 'process.exit(0)'"
        files["package.json"] = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
    elif control == "test-empty":
        files["test.mjs"] = files["test.mjs"].split("{\n  const loaded", 1)[0]
    elif control == "test-unmet-plan":
        files["test.mjs"] = files["test.mjs"].replace("    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);\n", "", 1)
    elif control in ("missing-manager", "manager-mismatch"):
        manifest = parsed(files["package.json"])
        if control == "missing-manager":
            manifest.pop("packageManager")
        else:
            manifest["packageManager"] = "pnpm@11.23.0"
        files["package.json"] = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
    elif control == "malformed":
        files["tsconfig.json"] = "{ invalid configuration\n"
    elif control == "scope-omission":
        value = parsed(files["tsconfig.json"])
        value["exclude"] = ["answer_tsx.tsx"]
        files["tsconfig.json"] = encoded(value).decode()
        # Rust serialization preserves insertion order from serde_json's map;
        # compare parsed tsconfig below, while every actual byte is still bound.
        files["eslint.config.mjs"] += "\n// Source fixture mutation: omit selected TSX scope.\n"
        files["eslint.config.mjs"] = files["eslint.config.mjs"].replace("export default [", "export default [{ignores:['answer_tsx.tsx']},")
    return files


GENERATED_INSTALL_FILES = {
    "node_modules/.bin/acorn": "node_modules/acorn/bin/acorn",
    "node_modules/.bin/js-yaml": "node_modules/js-yaml/bin/js-yaml.js",
    "node_modules/.bin/node-which": "node_modules/which/bin/node-which",
    "node_modules/.bin/pn": "node_modules/pnpm/bin/pnpm.mjs",
    "node_modules/.bin/pnpx": "node_modules/pnpm/bin/pnpx.mjs",
    "node_modules/.bin/pnx": "node_modules/pnpm/bin/pnpx.mjs",
    "node_modules/.bin/semver": "node_modules/semver/bin/semver.js",
    "node_modules/.bin/tsserver": "node_modules/typescript/bin/tsserver",
    "node_modules/.package-map.json": None,
    "node_modules/.pnpm-workspace-state-v1.json": None,
}


# Exact static prefix from enrolled pnpm 11.24.0 / @zkochan/cmd-shim 9.0.7.
# Archive SHA256: d1eab2433172661cc36a18ec85fce93f771db1962717329cc01ec9c2824ca24f.
PINNED_SHIM_PREFIX = '#!/bin/sh\n# Resolve $0 through symlinks so basedir is the shim\'s real directory.\n# Cap hops at the kernel\'s ELOOP limit so a cycle cannot hang the shim.\nlink="$0"\nhops=0\nwhile [ -L "$link" ] && [ "$hops" -lt 40 ]; do\n  hops=$((hops+1))\n  target=$(readlink "$link")\n  case "$target" in\n    /*) link="$target" ;;\n    *)  link="$(dirname "$link")/$target" ;;\n  esac\ndone\nbasedir=$(dirname "$(echo "$link" | sed -e \'s,\\\\,/,g\')")\nbasedir_win="$basedir"\nexe=""\nmsys=""\n\ncase `uname -a` in\n  *CYGWIN*|*MINGW*|*MSYS*)\n    if command -v cygpath > /dev/null 2>&1; then\n      basedir_win=`cygpath -w "$basedir"`\n    fi\n    exe=".exe"\n    msys="true"\n  ;;\n  *WSL2*)\n    if command -v wslpath > /dev/null 2>&1; then\n      basedir_win="$(wslpath -w "$basedir" 2> /dev/null)"\n      if [ $? -ne 0 ] || [ -z "$basedir_win" ]; then\n        basedir_win="$basedir"\n      else\n        exe=".exe"\n      fi\n    fi\n  ;;\nesac\n\n'


def pinned_shim(cwd, target):
    rel = "../" + target.removeprefix("node_modules/")
    body = ('if [ -n "$exe" ] && [ -x "$basedir/node.exe" ]; then\n'
            '  exec "$basedir/node.exe"  "$basedir_win/' + rel + '" "$@"\n'
            'elif [ -x "$basedir/node" ]; then\n'
            '  exec "$basedir/node"  "$basedir/' + rel + '" "$@"\n'
            'elif command -v node >/dev/null 2>&1; then\n'
            '  exec node  "$basedir/' + rel + '" "$@"\n'
            'elif [ -n "$exe" ] && command -v node.exe >/dev/null 2>&1; then\n'
            '  exec node.exe  "$basedir_win/' + rel + '" "$@"\n'
            'else\n  exec node  "$basedir/' + rel + '" "$@"\nfi\n'
            '# cmd-shim-target=' + str(cwd / target) + '\n')
    return (PINNED_SHIM_PREFIX + body).encode()


def raw_descriptor(value, reason):
    require(set(value) == {"digest", "bytes", "rawBytes"} or set(value) == {"digest", "bytes", "executable", "rawBytes"}, reason + " fields differ")
    raw = value["rawBytes"]
    require(isinstance(raw, list) and all(type(n) is int and 0 <= n <= 255 for n in raw), reason + " bytes malformed")
    data = bytes(raw)
    require(len(data) == value["bytes"] and digest(data) == value["digest"], reason + " bytes/hash differ")
    return data


def validate_preparation(case, enrollment, root, expected_files, control):
    prep = case.get("enrollmentPreparation")
    require(isinstance(prep, dict) and set(prep) == {"install", "enrolledRuntime", "postInstallRuntime", "generatedFiles", "lockfile"}, "genuine install preparation missing/incomplete")
    install = prep["install"]
    require(set(install) == {"schema", "argv", "cwd", "nodeDigest", "pnpmDigest", "exitCode", "success", "stdout", "stderr", "environmentCleared", "environment", "configInputsBefore", "configInputsAfter"}
            and install["schema"] == "legion-javascript-pnpm-install/1", "install receipt schema differs")
    cwd = absolute(case["policyDefinition"]["cwd"])
    node = absolute(enrollment["node"]["path"])
    pnpm = cwd / "node_modules/pnpm/bin/pnpm.mjs"
    scratch = absolute(case["policyDefinition"]["profile"]["path"]).parent.parent
    config_root = scratch.parent.parent / "preparations" / (case["caseId"] + "-config")
    require(not config_root.is_relative_to(cwd), "install config escaped external preparation scope")
    environment = {"PATH": str(node.parent) + ":/usr/bin:/bin", "CI": "true",
        "PNPM_CONFIG_IGNORE_PNPMFILE": "true", "PNPM_CONFIG_ENABLE_GLOBAL_VIRTUAL_STORE": "false",
        "PNPM_CONFIG_EXTEND_NODE_PATH": "false", "NPM_CONFIG_WORKSPACE_DIR": str(cwd)}
    for key, path in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state"), ("XDG_DATA_HOME", "data"),
        ("TMPDIR", "tmp"), ("PNPM_CONFIG_USERCONFIG", "npmrc")):
        environment[key] = str(config_root / path)
    require(install["environmentCleared"] is True, "install inherited host configuration")
    same(install["environment"], environment, "install environment differs from isolated pinned inputs")
    configs = {}
    for path, data in (("npmrc", b""), ("config/pnpm/auth.ini", b""), ("config/pnpm/config.yaml", b"{}\n")):
        configs[path] = {"path": str(config_root / path), "digest": digest(data), "bytes": len(data), "rawBytes": list(data)}
    same(install["configInputsBefore"], configs, "install config bytes differ from empty isolated inputs")
    same(install["configInputsAfter"], configs, "install changed isolated config inputs")
    same(install["argv"], [str(node), str(pnpm), "install", "--offline", "--ignore-scripts", "--no-frozen-lockfile"], "baseline installer argv differs")
    require(install["cwd"] == str(cwd) and install["nodeDigest"] == enrollment["node"]["digest"]
            and install["pnpmDigest"] == enrollment["runtime"]["files"]["node_modules/pnpm/bin/pnpm.mjs"]["digest"]
            and install["exitCode"] == 0 and install["success"] is True, "pinned baseline install did not succeed")
    for key in ("stdout", "stderr"):
        raw_descriptor(install[key], "original install " + key)
    same(prep["enrolledRuntime"], enrollment["runtime"], "preinstall enrolled tree differs from verified enrollment")
    generated = prep["generatedFiles"]
    same(set(generated), set(GENERATED_INSTALL_FILES), "installer generated-file set differs")
    pin = parsed(read(source(root, INPUTS), 16 * 1024 * 1024))
    declared_bins = {}
    for package_id, package in pin["packages"].items():
        bins = package.get("bin", {})
        if isinstance(bins, str):
            bins = {package_id.rsplit("@", 1)[0].rsplit("/", 1)[-1]: bins}
        require(isinstance(bins, dict), "pinned package bin declaration malformed")
        name = package_id.rsplit("@", 1)[0]
        package_path = "node_modules/" + name
        for alias, target in bins.items():
            if alias in {"acorn", "js-yaml", "node-which", "pn", "pnpx", "pnx", "semver", "tsserver"}:
                declared_bins["node_modules/.bin/" + alias] = package_path + "/" + target.removeprefix("./")
    same({p: GENERATED_INSTALL_FILES[p] for p in GENERATED_INSTALL_FILES if GENERATED_INSTALL_FILES[p] is not None}, declared_bins, "generated shim set/targets differ from enrolled package bin declarations")
    generated_raw = {}
    for path, target in GENERATED_INSTALL_FILES.items():
        data = raw_descriptor(generated[path], "generated " + path)
        generated_raw[path] = data
        require(generated[path].get("executable") is (target is not None), "generated install file mode differs")
        if target is not None:
            require(data == pinned_shim(cwd, target),
                    "pnpm shim bytes differ from pinned cmd-shim body/target")
    package_map = parsed(generated_raw["node_modules/.package-map.json"])
    same(set(package_map), {"packages"}, "pnpm package map keys differ")
    same(package_map["packages"], {".": {"url": "../..", "dependencies": {parsed(expected_files["package.json"].encode())["name"]: "."}}}, "pnpm package map includes unexpected package/dependency")
    state = parsed(generated_raw["node_modules/.pnpm-workspace-state-v1.json"])
    # ignorePnpmfile skips main's hook loader; pnpmfile/configDependencies remain
    # undefined & JSON.stringify omits both fields in the pinned state writer.
    same(set(state), {"lastValidatedTimestamp", "projects", "settings", "filteredInstall"}, "pnpm workspace state keys differ")
    require(type(state["lastValidatedTimestamp"]) is int and state["lastValidatedTimestamp"] >= 0, "pnpm workspace timestamp malformed")
    manifest = parsed(expected_files["package.json"].encode())
    same(state["projects"], {str(cwd): {"name": manifest["name"], "version": manifest["version"]}}, "pnpm workspace projects differ")
    require(state["filteredInstall"] is False
            and isinstance(state["settings"], dict), "pnpm workspace state values differ")
    # Exact projection of isolated pinned config defaults through the state writer.
    default_settings = {"enableGlobalVirtualStore": False,
        "autoInstallPeers": True, "catalogs": {}, "dedupeDirectDeps": False,
        "dedupeInjectedDeps": True, "dedupePeerDependents": True, "dedupePeers": False,
        "dev": True, "excludeLinksFromLockfile": False, "hoistPattern": ["*"],
        "hoistWorkspacePackages": True,
        "injectWorkspacePackages": False, "linkWorkspacePackages": False,
        "minimumReleaseAge": 1440, "minimumReleaseAgeIgnoreMissingTime": True,
        "nodeLinker": "isolated", "optional": True, "peersSuffixMaxLength": 1000,
        "preferWorkspacePackages": False, "production": True, "publicHoistPattern": [],
        "workspacePackagePatterns": ["."]}
    same(state["settings"], default_settings, "pnpm workspace state differs from isolated pinned config projection")
    lock = raw_descriptor(prep["lockfile"], "generated lockfile")
    lock_text = lock.decode("utf-8")
    require(re.fullmatch(r"lockfileVersion: '9\.0'\n+settings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n+importers:\n+  \.: \{\}\n", lock_text),
            "pnpm lockfile differs from complete empty-importer writer grammar")
    expected_files["pnpm-lock.yaml"] = lock_text
    original = prep["enrolledRuntime"]
    post = prep["postInstallRuntime"]
    same(post["links"], original["links"], "install changed enrolled links")
    same(post["directories"], original["directories"], "install changed enrolled directories")
    require(set(post["files"]) == set(original["files"]) | (set(GENERATED_INSTALL_FILES) - {"pnpm-lock.yaml"}), "install file delta differs")
    for path, value in original["files"].items():
        same(post["files"][path], value, "install changed enrolled file: " + path)
    for path, value in generated.items():
        if path.startswith("node_modules/"):
            same(post["files"][path], {k: value[k] for k in ("digest", "bytes", "executable")}, "installed runtime descriptor differs: " + path)
    expected_baseline = parsed(encoded(post))
    if control == "missing-tool":
        expected_baseline["links"].pop("node_modules/.bin/eslint")
    same(case["localRuntimeBefore"], expected_baseline, "post-install execution baseline differs")


def stream(record, raw, root):
    if record is None:
        require(raw is None, "unrecorded stream data")
        return b""
    require(set(record) == {"path", "digest", "bytes", "immutable"} and record["immutable"] is True, "SDK stream not immutable")
    rel = relative(record["path"])
    data = raw["rawBytes"]
    require(isinstance(data, list) and all(type(n) is int and 0 <= n <= 255 for n in data), "raw byte array malformed")
    value = bytes(data)
    require(len(value) <= 33554432 and len(value) == record["bytes"] == raw["bytes"]
            and digest(value) == record["digest"] == raw["digest"] and raw["immutable"] is True
            and raw["path"] == record["path"], "original SDK stream differs")
    require(absolute(raw["absolutePath"]) == root / "artifacts" / rel, "SDK artifact escaped retained scratch")
    return value


def suffix(task):
    return {"type": ["--noEmit", "-p", "tsconfig.json", "--pretty", "false", "--listFiles"],
            "lint": ["--no-cache", "--format", "json", "--no-error-on-unmatched-pattern", "."],
            "build": ["run", "build"], "test": ["run", "test"]}[task]


def expected_environment(policy):
    scratch = absolute(policy["profile"]["path"]).parent.parent
    cwd = absolute(policy["cwd"])
    node = absolute(policy["node"]["path"])
    env = {"PATH": ":".join(map(str, (cwd / "node_modules/.bin", node.parent, PurePosixPath("/usr/bin"), PurePosixPath("/bin"))))}
    for name, path in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"), ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"), ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"), ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"), ("GOCACHE", "cache/go-build"), ("HOME", "cache/javascript-home"), ("USERPROFILE", "cache/javascript-home"), ("XDG_CONFIG_HOME", "cache/javascript-home/.config"), ("APPDATA", "cache/javascript-home/AppData/Roaming"), ("LEGION_AUDIT_JS_OUTPUT", "cache/javascript-build")):
        env[name] = str(scratch / path)
    env.update({"PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1", "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never", "CI": "true", "COREPACK_ENABLE_NETWORK": "0"})
    allowed = sorted(set(env) | {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"})
    return env, allowed


def request(policy, req, task, sandbox=True):
    require(task in TASKS, "unlisted task")
    root = absolute(policy["cwd"])
    tool = root / "node_modules/.bin" / {"type": "tsc", "lint": "eslint", "build": "pnpm", "test": "pnpm"}[task]
    prefix = ["-f", policy["profile"]["path"], "--", str(tool)]
    require(req["schemaVersion"] == 1 and req["providerId"] == PROVIDER and req["planId"] == policy["planDigest"]
            and req["policyId"] == "audit" and req["taskId"] == task and req["cwd"] == str(root)
            and req["origin"] == "TargetProject" and req["shell"] is False, "SDK request scope differs")
    require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"]), "request identity malformed")
    same(req["args"], prefix + suffix(task), "actual tool argv differs")
    same(req["versionArgs"], prefix + ["--version"], "real tool version probe differs")
    require(req["executable"] == policy["wrapper"]["path"] and req["expectedDigest"] == policy["wrapper"]["digest"], "wrapper identity differs")
    require(req["skipVersionProbe"] is False and req["versionRequirement"] is None and req["requiresNetworkSandbox"] is True, "tool sealing/sandbox loosened")
    same(req["environment"], policy["environment"], "request environment differs")
    same(req["environmentAllowlist"], policy["environmentAllowlist"], "request inherited environment differs")
    require(not any(k in req["environment"] or k in req["environmentAllowlist"] for k in ("NODE_OPTIONS", "NODE_PATH", "PNPM_HOME")), "ambient Node module/config injection")
    require(req["sensitiveArgumentIndexes"] == req["sensitiveEnvironmentNames"] == [] and req["timeoutMs"] == 120000
            and req["stdoutLimit"] == req["stderrLimit"] == 33554432, "SDK bounds differ")
    same(req["acceptedExitCodes"], [0, 1, 2] if task == "type" else [0, 1] if task == "lint" else [0], "exit contract loosened")
    same(req["sandbox"], {"id": policy["profile"]["receiptId"], "network": True, "filesystemScope": str(root)} if sandbox else None, "authenticated sandbox differs")


def sdk(row, policy, expected_state=None, expected_allowed=True, sandbox=True):
    require(set(row) == {"request", "executionReceipt", "stdout", "stderr"}, "SDK row fields differ")
    req, receipt = row["request"], row["executionReceipt"]
    require(set(receipt) == RECEIPT_FIELDS, "original receipt incomplete")
    task = req["taskId"]
    request(policy, req, task, sandbox)
    require(receipt["requestId"] == req["requestId"] and receipt["planId"] == req["planId"]
            and receipt["providerId"] == PROVIDER and receipt["policyId"] == "audit" and receipt["taskId"] == task,
            "SDK receipt request binding differs")
    decision = receipt["policy"]
    require(decision["allowed"] is expected_allowed and decision["version"] == 1, "actual admission outcome differs")
    if decision["id"] == POLICY:
        require(decision["digest"] == digest(encoded(policy)), "fixture authorizer definition differs")
    else:
        require(not expected_allowed and decision["id"] == "audit-native-owner-admission-v1", "unrecognized policy owner")
    if expected_state:
        require(receipt["state"] == expected_state, "actual SDK state differs")
    scratch = absolute(policy["profile"]["path"]).parent.parent
    stdout = stream(receipt["stdout"], row["stdout"], scratch)
    stderr = stream(receipt["stderr"], row["stderr"], scratch)
    started = receipt["processTree"]["started"]
    require(started is (expected_allowed and sandbox), "refused process started or actual run absent")
    if started:
        require(receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True, "process tree not reaped")
        version = receipt["executable"]["version"]
        require(version["qualified"] is True and version["skippedByPolicy"] is False and version["exitCode"] == 0, "real version probe not qualified")
        same(version["args"], req["versionArgs"], "executed version args differ")
        require(version["output"].strip() == {"type": "Version 5.9.3", "lint": "v9.39.1", "build": "11.24.0", "test": "11.24.0"}[task], "observed native version differs")
        require(receipt["sandbox"]["required"] is True and receipt["sandbox"]["receiptId"] == policy["profile"]["receiptId"] and receipt["sandbox"]["networkEnabled"] is True, "actual sandbox missing/network permitted")
        same(receipt["command"]["args"], req["args"], "executed argv differs")
        require(receipt["command"]["executable"] == req["executable"], "executed wrapper differs")
        require(receipt["executable"]["digest"] == policy["wrapper"]["digest"], "executed wrapper bytes differ")
        require(receipt["state"] in ("completed", "failed") and receipt["complete"] is (receipt["state"] == "completed"), "actual process receipt incomplete")
    else:
        require(receipt["complete"] is False, "refusal complete claim")
    return stdout.decode("utf-8"), stderr.decode("utf-8")


def validate_record(root, row, enrollment=None, live=False):
    require(row["schema"] == "legion-javascript-sdk-accuracy/1" and row["kind"] == "javascript-sdk-known-answer"
            and row["provider"] == PROVIDER and row["productionQualification"] is False
            and row["qualificationEligible"] is True and row["claimScope"] == FAMILY_SCOPE
            and row["executionPath"] == "native-sdk-frozen-plan-self-sourced-code"
            and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "record identity/scope differs")
    value = dict(row)
    claimed = value.pop("qualificationDigest")
    require(claimed == digest(encoded(value)), "qualification digest differs")
    spec = next(p for p in parsed(read(source(root, "src/registry/providers.json"), 4 * 1024 * 1024))["providers"] if p["id"] == PROVIDER)
    spec.pop("benchmark", None)
    same(row["binding"]["providerSpec"], spec, "original provider contract differs")
    require(row["binding"]["providerSpecDigest"] == digest(encoded(spec)), "provider source digest differs")
    same(row["requiredContract"], CONTRACT, "original JS/TS config narrowed")
    same(row["executedScope"], list(TASKS), "required tool omitted")
    sources = source_files(root)
    same(row["binding"]["sources"], sources, "complete source closure differs")
    require(row["binding"]["sourcesDigest"] == digest(encoded(sources)) and row["binding"]["fixture"] == HARNESS, "source closure digest differs")
    require(enrollment is not None, "original official enrollment required")
    helper = runpy.run_path(str(source(root, HELPER)))
    helper["verify_enrollment"](root, enrollment, live=live)
    require([c["control"] for c in row["cases"]] == list(CONTROLS), "control denominator/order differs")
    corpus = {}
    for case in row["cases"]:
        control = case["control"]
        require(case["provider"] == PROVIDER and case["caseId"] == "javascript-" + control
                and case["matched"] is True and case["productionQualification"] is False
                and case["qualificationEligible"] is False, "case identity/claim differs")
        expected_files = fixture(root, control)
        validate_preparation(case, enrollment, root, expected_files, control)
        actual_files = dict(case["fixtureFiles"])
        if control == "scope-omission":
            same(parsed(actual_files["tsconfig.json"]), parsed(expected_files["tsconfig.json"]), "scope config mutation differs")
            expected_files["tsconfig.json"] = actual_files["tsconfig.json"]
        same(actual_files, expected_files, "actual fixture source differs")
        expected_sources = {p: digest(v.encode()) for p, v in actual_files.items()}
        same(case["sourceBefore"], expected_sources, "frozen fixture source hashes differ")
        corpus.update({case["caseId"] + "/" + p: d for p, d in expected_sources.items()})
        after = dict(expected_sources)
        if control == "source-tamper":
            after["answer_js.js"] = digest((actual_files["answer_js.js"] + "\n// changed after frozen inventory\n").encode())
        same(case["sourceAfter"], after, "unexpected source writes")
        require(case["inventory"]["entries"] and len(case["inventory"]["entries"]) == len(expected_files), "frozen inventory narrowed/expanded")
        same({e["path"]: e["digest"] for e in case["inventory"]["entries"]}, expected_sources, "inventory source closure differs")
        inventory = case["inventory"]
        entries = inventory["entries"]
        require([e["path"] for e in entries] == sorted(expected_files), "frozen inventory order differs")
        require(inventory["schemaVersion"] == 1 and inventory["repositoryId"] == case["caseId"]
                and inventory["generation"] == "filesystem:" + digest(encoded(entries))
                and inventory["digest"] == digest(encoded([1, case["caseId"], inventory["generation"], entries])), "inventory identity differs")
        frozen = case["frozenProvider"]
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", case["planDigest"])
                and frozen["id"] == PROVIDER and frozen["version"] == spec["providerVersion"]
                and frozen["configuration"]["denominatorCount"] == len(entries)
                and frozen["configuration"]["denominatorDigest"] == digest(encoded([inventory["digest"], spec["selector"], entries])),
                "original frozen provider denominator differs")
        policy = case["policyDefinition"]
        require(set(policy) == {"id", "version", "scope", "provider", "planDigest", "cwd", "node", "runtime", "wrapper", "profile", "environment", "environmentAllowlist", "absentSandboxControl", "commands", "timeoutMs", "stdoutLimit", "stderrLimit"}
                and policy["version"] == 1 and policy["scope"] == "exact source-owned JS/TS SDK fixtures; no production owner admission"
                and policy["commands"] == [{"task": task, "args": suffix(task)} for task in TASKS]
                and policy["absentSandboxControl"] is (control == "absent-sandbox")
                and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 33554432,
                "exact fixture policy contract differs")
        require(policy["id"] == POLICY and policy["provider"] == PROVIDER and policy["planDigest"] == case["planDigest"]
                and policy["node"]["path"] == enrollment["node"]["path"] and policy["node"]["digest"] == enrollment["node"]["digest"], "actual policy/Node identity differs")
        cwd = absolute(policy["cwd"])
        exact_env, exact_allowlist = expected_environment(policy)
        same(policy["environment"], exact_env, "policy environment exceeds frozen source contract")
        same(policy["environmentAllowlist"], exact_allowlist, "policy inheritance exceeds frozen source contract")
        require(policy["wrapper"]["path"] == "/usr/bin/sandbox-exec", "unrecognized native sandbox wrapper")
        baseline = parsed(encoded(case["enrollmentPreparation"]["postInstallRuntime"]))
        if control == "missing-tool":
            baseline["links"].pop("node_modules/.bin/eslint")
        same(policy["runtime"], baseline, "fixture admission closure differs")
        after_runtime = parsed(encoded(baseline))
        if control == "tool-tamper":
            # The original mutated bytes are retained in the negative case;
            # a fixed source change must explain exact post-mutation descriptor.
            changed = "node_modules/eslint/bin/eslint.js"
            require(set(case["localRuntimeAfter"]["files"]) == set(baseline["files"]), "tamper changed file denominator")
            actual = case["localRuntimeAfter"]["files"][changed]
            raw = bytes(case["toolTamperBytes"])
            suffix = b"\n// changed after official enrollment\n"
            require(raw.endswith(suffix) and digest(raw[:-len(suffix)]) == baseline["files"][changed]["digest"]
                    and len(raw) == actual["bytes"] and digest(raw) == actual["digest"]
                    and actual["bytes"] == baseline["files"][changed]["bytes"] + len(suffix), "tool tamper bytes differ")
            after_runtime["files"][changed] = actual
        same(case["localRuntimeAfter"], after_runtime, "unexpected package writes")
        home = str(absolute(policy["profile"]["path"]).parent.parent / "cache/javascript-home")
        require(policy["environment"]["HOME"] == policy["environment"]["USERPROFILE"] == home
                and policy["environment"]["XDG_CONFIG_HOME"] == home + "/.config"
                and policy["environment"]["APPDATA"] == home + "/AppData/Roaming"
                and policy["environment"]["CI"] == "true" and policy["environment"]["COREPACK_ENABLE_NETWORK"] == "0", "isolated script config differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        profile = '(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "' + escaped + '"))\n'
        require(policy["profile"]["text"] == profile and policy["profile"]["receiptId"] == "sandbox:macos:" + digest(profile.encode())[7:], "sandbox profile semantics differ")
        executions = case["sdkExecutions"]
        expected_tasks = ["type"] if control == "absent-sandbox" else [] if control == "source-tamper" else ["type", "build", "test"] if control == "missing-tool" else ["type", "lint"] if control in ("missing-manager", "manager-mismatch") else list(TASKS)
        require([e["request"]["taskId"] for e in executions] == expected_tasks, "actual required SDK executions differ")
        complete = control == "nonempty-clean" or control.startswith("positive-")
        result = case["nativeResult"]
        if control == "absent-sandbox":
            require(result is None, "SDK boundary control falsely labeled provider execution")
        else:
            require(result["provider"] == PROVIDER and result["complete"] is complete
                    and bool(result["coverage_gaps"]) is not complete, "provider complete/gap outcome differs")
            coverage = result["coverage"]
            require(coverage["expected"] == len(expected_files) and 0 <= coverage["examined"] <= len(expected_files) and (not complete or coverage["examined"] == len(expected_files)), "frozen coverage denominator changed")
        observed = {}
        for execution in executions:
            task = execution["request"]["taskId"]
            refused = control in ("rejected-admission", "tool-tamper")
            expected_state = "sandbox_missing" if control == "absent-sandbox" else "unauthorized_effect" if refused else "failed" if (control in ("build-failure", "malformed") and task == "build") or (control in ("test-failure", "test-unmet-plan") and task == "test") or (control in ("build-noop", "build-failure", "malformed", "scope-omission") and task == "test") else "completed"
            observed[task] = sdk(execution, policy, expected_state=expected_state, expected_allowed=not refused, sandbox=control != "absent-sandbox")
        expected_decisions = [] if control == "rejected-admission" else [
            {"requestId": e["request"]["requestId"], "taskId": e["request"]["taskId"],
             "allowed": control != "tool-tamper", "request": e["request"]} for e in executions]
        same(case["policyDecisions"], expected_decisions, "actual authorizer decisions differ from SDK execution requests")
        if control in ("build-noop", "test-noop", "test-empty", "test-unmet-plan"):
            task = "build" if control == "build-noop" else "test"
            row_execution = next(e for e in executions if e["request"]["taskId"] == task)
            require(not result["complete"] and result["coverage_gaps"], "substance-negative control falsely complete")
            if control != "test-unmet-plan":
                require(row_execution["executionReceipt"]["state"] == "completed" and row_execution["executionReceipt"]["exitCode"] == 0, "noop/empty control did not genuinely exit zero")
            else:
                require("plan expected 1 assertions but received 0" in observed["test"][0], "genuine Node missing-plan enforcement absent")
        if control == "scope-omission":
            require("source-scope-incomplete" in str(result["coverage_gaps"]), "scope omission was credited clean")
        if control == "missing-manager":
            require("package-manager-unproven" in str(result["coverage_gaps"]), "absent manager was credited clean")
        if control == "manager-mismatch":
            require("pnpm-declared-version-mismatch" in str(result["coverage_gaps"]), "mismatched manager was credited clean")
        if control == "source-tamper":
            require("frozen-source-changed" in str(result["coverage_gaps"]), "source drift was credited clean")
        if complete:
            emitted = case["emittedModules"]
            expected_outputs = {"answer_" + e + "." + {"ts":"js", "cts":"cjs", "mts":"mjs", "jsx":"js", "tsx":"js"}.get(e,e) for e in EXTENSIONS} | {"test.mjs", "eslint.config.mjs"}
            require(set(emitted) == expected_outputs | {p + ".map" for p in expected_outputs}, "emitted variant/source-map denominator differs")
            for descriptor in emitted.values():
                data = bytes(descriptor["rawBytes"])
                require(data and len(data) == descriptor["bytes"] and digest(data) == descriptor["digest"], "actual emitted module bytes differ")
            selected = {p for p in expected_files if p.rsplit(".", 1)[-1] in EXTENSIONS}
            allowed = set(expected_files) | set(enrollment["runtime"]["files"]) | set(enrollment["runtime"]["links"])
            typed = strict_tsc(observed["type"][0], cwd, allowed, next(e["executionReceipt"]["exitCode"] for e in executions if e["request"]["taskId"] == "type"))
            require(selected <= typed, "actual TypeScript scope omitted selected sources")
            lint = parsed(observed["lint"][0])
            require(isinstance(lint, list) and {r["filePath"] for r in lint} == {str(cwd / p) for p in selected}, "actual ESLint file scope differs")
            errors = 0
            require(len(lint) == len({r["filePath"] for r in lint}), "duplicate ESLint scope row")
            for lint_row in lint:
                require(isinstance(lint_row["messages"], list), "ESLint messages absent")
                counts = {1: 0, 2: 0}
                for message in lint_row["messages"]:
                    require(type(message["severity"]) is int and message["severity"] in counts
                            and isinstance(message["message"], str) and message["message"]
                            and type(message["line"]) is int and message["line"] > 0,
                            "malformed original ESLint diagnostic")
                    require((isinstance(message["ruleId"], str) and message["ruleId"])
                            or (message["ruleId"] is None and message.get("fatal") is True), "ESLint rule absent")
                    counts[message["severity"]] += 1
                require(lint_row["errorCount"] == counts[2] and lint_row["warningCount"] == counts[1], "ESLint count mismatch")
                errors += counts[2]
            lint_exit = next(e["executionReceipt"]["exitCode"] for e in executions if e["request"]["taskId"] == "lint")
            require((lint_exit == 0 and errors == 0) or (lint_exit == 1 and errors > 0), "ESLint exit/count mismatch")
            evidence = result["details"]["findingEvidence"]
            if control.startswith("positive-"):
                ext = control.removeprefix("positive-")
                require(re.search(r"answer_" + ext + r"\." + ext + r"\(2,\d+\): error TS2322:", observed["type"][0]), "actual planted TypeScript diagnostic missing")
                require(any(r["filePath"] == str(cwd / ("answer_" + ext + "." + ext)) and any(m["ruleId"] == "no-debugger" and m["line"] == 1 and m["severity"] == 2 for m in r["messages"]) for r in lint), "actual planted ESLint diagnostic missing")
                for rule, line in (("eslint:no-debugger", 1), ("tsc:TS2322", 2)):
                    require(any(f["ruleId"] == rule and f["path"] == "answer_" + ext + "." + ext and f["line"] == line for f in evidence.values()), "projected native finding missing/mislocated")
            else:
                require(result["findings"] == [] and evidence == {}, "nonempty-clean fixture produced findings")
            receipts = result["details"]["nativeProducer"]["toolReceipts"]
            require([r["tool"] for r in receipts] == list(TASKS), "native producer receipt accounting differs")
            for receipt, execution in zip(receipts, executions):
                same(receipt["sdkReceipt"], execution["executionReceipt"], "projected receipt differs from original SDK")
                snapshots = receipt["nativeInputSnapshots"]
                require(snapshots["unchanged"] is True and snapshots["afterError"] is None, "runtime/source closure drift credited clean")
                same(snapshots["before"], snapshots["after"], "before/after closure differs")
                require(snapshots["before"]["schema"] == "legion-javascript-input-snapshot/1", "snapshot schema differs")
                same(snapshots["before"]["sourceFiles"], expected_sources, "production frozen source closure differs")
                source_context = {"schema": "legion-javascript-source-context/1", "cwd": "", "files": dict(sorted(expected_sources.items())), "selected": sorted(selected)}
                context_digest = digest(json.dumps(source_context, ensure_ascii=False, separators=(",", ":")).encode())
                require(receipt["sourceDigest"] == snapshots["before"]["sourceContextDigest"] == context_digest, "source context/manifest/script binding differs")
                local = snapshots["before"]["localPackages"]
                require(local["root"] == str(cwd / "node_modules"), "local package root differs")
                expected_local_files = {p.removeprefix("node_modules/"): {k: v[k] for k in ("digest", "bytes")} for p, v in enrollment["runtime"]["files"].items()}
                expected_local_links = {p.removeprefix("node_modules/"): v for p, v in enrollment["runtime"]["links"].items()}
                same(local["files"], expected_local_files, "production package source closure differs")
                same(local["links"], expected_local_links, "production package aliases differ")
                expected_local_directories = sorted(p.removeprefix("node_modules/") if p != "node_modules" else "" for p in enrollment["runtime"]["directories"])
                same(local["directories"], expected_local_directories, "production package directory closure differs")
                require(local["nodes"] == len(expected_local_files) + len(expected_local_links) + len(expected_local_directories)
                        and local["bytes"] == sum(v["bytes"] for v in expected_local_files.values()), "production package node/byte accounting differs")
                task = receipt["tool"]
                output = absolute(policy["environment"]["LEGION_AUDIT_JS_OUTPUT"])
                if task in ("build", "test"):
                    operation_replay(task, receipt["nativeOperationObservation"], observed[task], emitted, expected_files, cwd, output)
                if task == "test":
                    compiled = snapshots["before"]["compiledInputs"]
                    require(compiled["root"] == str(output) and compiled["links"] == {} and compiled["directories"] == [""], "test input output-tree identity differs")
                    same(compiled["files"], {p:{k:v[k] for k in ("digest", "bytes")} for p,v in emitted.items()}, "test did not seal actual compiled modules/maps")
                    require(compiled["nodes"] == len(emitted) + 1 and compiled["bytes"] == sum(v["bytes"] for v in emitted.values()), "compiled input bounds accounting differs")
                else:
                    require(snapshots["before"]["compiledInputs"] is None, "non-test snapshot incorrectly seals build output")
                if receipt["tool"] in ("build", "test"):
                    require(snapshots["before"]["packageManagerVersion"] == "11.24.0", "frozen package manager version differs")
                    manager = snapshots["before"]["projectManagerPackage"]
                    expected_manager = {p.removeprefix("pnpm/"): v for p, v in expected_local_files.items() if p.startswith("pnpm/")}
                    same(manager["files"], expected_manager, "pnpm runtime closure differs")
                    require(manager["root"] == str(cwd / "node_modules/pnpm") and manager["links"] == {}, "pnpm runtime aliases differ")
                require(snapshots["before"]["node"]["digest"] == enrollment["node"]["digest"], "production Node differs")
        if control == "nonempty-clean":
            mutations = case["requestMutationControls"]
            require([m["mutation"] for m in mutations] == ["argv", "cwd", "environment", "task"], "request mutation denominator differs")
            for mutation in mutations:
                original = parsed(encoded(executions[0]["request"]))
                kind = mutation["mutation"]
                original["requestId"] = "legion-audit/" + digest((case["caseId"] + ":" + kind).encode())[7:]
                if kind == "argv":
                    original["args"].append("--unexpected")
                elif kind == "cwd":
                    original["cwd"] = str(cwd.parent.parent)
                elif kind == "environment":
                    original["environment"]["NODE_OPTIONS"] = "--inspect"
                    original["environmentAllowlist"] = sorted(set(original["environmentAllowlist"]) | {"NODE_OPTIONS"})
                else:
                    original["taskId"] = "unlisted"
                same(mutation["execution"]["request"], original, "actual SDK request tamper differs")
                require(mutation["matched"] is True, "request tamper not rejected")
                receipt = mutation["execution"]["executionReceipt"]
                require(set(receipt) == RECEIPT_FIELDS and receipt["state"] == "unauthorized_effect"
                        and receipt["complete"] is False and receipt["policy"]["allowed"] is False
                        and receipt["processTree"]["started"] is False and receipt["policy"]["id"] == POLICY
                        and receipt["policy"]["digest"] == digest(encoded(policy))
                        and receipt["requestId"] == original["requestId"] and receipt["providerId"] == PROVIDER
                        and receipt["planId"] == case["planDigest"] and receipt["taskId"] == original["taskId"]
                        and receipt["stdout"] is None and receipt["stderr"] is None
                        and mutation["execution"]["stdout"] is None and mutation["execution"]["stderr"] is None,
                        "real SDK mutation refusal missing")
    same(row["binding"]["fixtureSources"], corpus, "fixture corpus denominator differs")
    require(row["binding"]["fixtureSourcesDigest"] == digest(encoded(corpus)), "fixture corpus digest differs")
    same(row["metrics"], {"cases": len(CONTROLS), "matched": len(CONTROLS), "mismatched": 0, "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}, "accuracy counters differ")
    return {"provider": PROVIDER, "qualificationDigest": claimed, "qualificationEligible": True, "productionQualification": False, "claimScope": FAMILY_SCOPE}


def artifact_locator(row, raw):
    return {"provider": PROVIDER, "file": "code_javascript.json", "digest": digest(raw), "bytes": len(raw),
            "qualificationDigest": row["qualificationDigest"], "qualificationEligible": True, "productionQualification": False}


def validate_retained(root, row, paths, live=False):
    require(set(paths) == {"enrollment", "childExecution", "childStdout", "childStderr", "providerRecord"}, "retained family files differ")
    original = read(paths["providerRecord"])
    same(parsed(original), row, "indexed row differs from original child artifact")
    enrollment_bytes = read(paths["enrollment"], 4 * 1024 * 1024)
    require(row["enrollment"] == {"file": "enrollment.json", "digest": digest(enrollment_bytes), "bytes": len(enrollment_bytes)}, "original enrollment bytes differ")
    child = parsed(read(paths["childExecution"], 1024 * 1024))
    require(child["schema"] == "legion-javascript-sdk-child/1" and child["productionQualification"] is False, "child provenance differs")
    same(child["status"], {"success": True, "exitCode": 0, "signal": None}, "actual native child failed")
    stdout = b""
    for name, path in (("stdout", paths["childStdout"]), ("stderr", paths["childStderr"])):
        actual = Path(path)
        require(actual.is_file() and not actual.is_symlink(), "child raw stream missing/unsafe")
        data = read(actual, 64 * 1024 * 1024)
        same(child[name], {"file": "child." + name + ".log", "digest": digest(data), "bytes": len(data)}, "actual child stream differs")
        if name == "stdout":
            stdout = data
    marker = b"JAVASCRIPT_SDK_ACCURACY_ARTIFACT "
    locators = [parsed(line.split(marker, 1)[1]) for line in stdout.splitlines() if marker in line]
    same(locators, [{"provider": PROVIDER, "file": "code_javascript.json", "digest": digest(original), "bytes": len(original), "qualificationDigest": row["qualificationDigest"], "qualificationEligible": True, "productionQualification": False}], "actual child artifact emission differs")
    require(re.findall(rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", stdout) == [(b"1", b"0", b"0")]
            and len(re.findall(rb"\btest real_javascript_sdk_accuracy \.\.\.", stdout)) == 1, "native child did not execute exactly once")
    return validate_record(root, row, enrollment=parsed(enrollment_bytes), live=live)


def validate_records(root, receipts, live=True):
    receipts = Path(receipts)
    paths = {"enrollment": receipts / "enrollment.json", "childExecution": receipts / "child-execution.json", "childStdout": receipts / "child.stdout.log", "childStderr": receipts / "child.stderr.log", "providerRecord": receipts / "code_javascript.json"}
    return validate_retained(Path(root), parsed(read(paths["providerRecord"])), paths, live=live)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    result = validate_records(args.root.resolve(), args.receipts, live=not args.offline)
    print("JAVASCRIPT_SDK_ACCURACY_SUMMARY " + encoded(result).decode())


if __name__ == "__main__":
    main()
