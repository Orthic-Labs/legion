#!/usr/bin/env python3
"""Managed-CI Python SDK tools: official wheels, observed managed runtime.

No project is installed or executed. Only provisioning uses network; every tool
wheel is pinned. Runtime provenance is authenticated managed-runner observation,
not authentication against an official CPython binary archive. Importable
verify_enrollment() only replays retained source/input bindings & filesystem bytes.
"""
import argparse
import email.parser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import stat
import subprocess
import sys
import sysconfig
import zipfile

SCHEMA = "legion-python-sdk-enrollment/1"
SELF = "scripts/ci/audit-python-sdk-bootstrap.py"
CAPTURE = "scripts/ci/provision-python-qualification-tools.py"
REPLAY = "scripts/ci/audit-pip-audit-provider-accuracy.py"
LOCK = "scripts/ci/python-tool-locks/code-python-sdk-macos-arm64-cp314.json"
REQUIREMENTS = LOCK.removesuffix(".json") + ".txt"
ROOTS = {"pip": "26.2.1", "ruff": "0.17.1", "mypy": "2.4.0", "pytest": "9.1.1", "build": "1.6.1", "hatchling": "1.32.4"}
TARGET = {"implementation": "cpython", "pythonFullVersion": "3.14.7", "abi": "cp314", "platform": "darwin", "machine": "arm64", "minimumMacOS": "15.0"}
HEADER = "# Official PyPI binary wheels only. No index, source distribution, or dependency build.\n"
PROVENANCE = "observed authenticated managed macOS CI CPython runtime; no official interpreter archive authentication"
PIP_CODE = "import sys; sys.path.insert(0, sys.argv.pop(1)); from pip._internal.cli.main import main; sys.exit(main())"


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return "sha256:" + h.hexdigest()


def parse(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON constant"))


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "object fields differ")


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n\t"), "unsafe absolute path")
    p = PurePosixPath(value)
    require(p.is_absolute() and str(p) == value and ".." not in p.parts and not value.startswith("//"), "noncanonical absolute path")
    return p


def inside(path, root):
    return path == root or root in path.parents


def source(root, relative):
    p = root
    for part in PurePosixPath(relative).parts:
        p = p / part
        require(not p.is_symlink(), "source symlink")
    require(p.is_file(), "missing source input: " + relative)
    return p


def load_inputs(repository):
    repository = Path(repository).resolve(strict=True)
    lock = parse(source(repository, LOCK).read_bytes())
    keys(lock, ("schema", "target", "roots", "resolver", "wheels"))
    require(lock["schema"] == "legion-python-sdk-wheel-lock/1" and lock["target"] == TARGET and lock["roots"] == ROOTS, "lock target/roots differ")
    wheels = lock["wheels"]
    require(isinstance(wheels, list) and len(wheels) == 18 and [w["name"] for w in wheels] == sorted({w["name"] for w in wheels}), "wheel closure count/order differs")
    require(lock["resolver"] == {"basis": "official exact PyPI JSON + actual hash-verified wheel METADATA; full active Requires-Dist closure for no extras; offline hash-required pip rechecks all dependencies in CI", "environment": {"extra": "", "os_name": "posix", "platform_machine": "arm64", "platform_python_implementation": "CPython", "python_full_version": "3.14.7", "python_version": "3.14", "sys_platform": "darwin"}}, "resolver target differs")
    for wheel in wheels:
        keys(wheel, ("name", "version", "filename", "url", "sha256", "size", "metadataUrl", "metadataSha256", "wheelMetadataSha256", "requiresPython", "requiresDist", "requestedExtras"))
        require(re.fullmatch(r"[0-9a-f]{64}", wheel["metadataSha256"]) is not None and re.fullmatch(r"[0-9a-f]{64}", wheel["wheelMetadataSha256"]) is not None, "metadata pins malformed")
        require((wheel["requiresPython"] is None or isinstance(wheel["requiresPython"], str)) and isinstance(wheel["requiresDist"], list) and all(isinstance(item, str) for item in wheel["requiresDist"]), "dependency metadata malformed")
        require(re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", wheel["filename"]) is not None and wheel["url"].startswith("https://files.pythonhosted.org/packages/") and wheel["url"].endswith("/" + wheel["filename"]), "official wheel URL/name differs")
        require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", wheel["name"]) and re.fullmatch(r"[0-9a-f]{64}", wheel["sha256"]), "wheel identity malformed")
        require(type(wheel["size"]) is int and 0 < wheel["size"] <= 40 * 1024 * 1024 and wheel["requestedExtras"] == [], "wheel size/extras differ")
        require(wheel["metadataUrl"] == "https://pypi.org/pypi/" + wheel["name"] + "/" + wheel["version"] + "/json", "nonofficial metadata input")
    require({w["name"]: w["version"] for w in wheels if w["name"] in ROOTS} == ROOTS, "root wheel versions differ")
    text = HEADER + "".join(w["name"] + "==" + w["version"] + " --hash=sha256:" + w["sha256"] + "\n" for w in wheels)
    require(source(repository, REQUIREMENTS).read_text() == text, "requirements differ from exact wheel set")
    return lock, {rel: {"path": str(source(repository, rel)), "digest": file_digest(source(repository, rel))} for rel in (SELF, CAPTURE, REPLAY, LOCK, REQUIREMENTS)}


def native_graph(value, runtime, live):
    keys(value, ("inspector", "systemExemptions", "images", "digest"))
    require(value["digest"] == digest(canonical({k: v for k, v in value.items() if k != "digest"})), "native graph digest differs")
    keys(value["inspector"], ("path", "digest"))
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value["inspector"]["digest"]) is not None, "inspector digest absent")
    require(value["systemExemptions"] == ["/usr/lib", "/System/Library"] and value["inspector"]["path"] == "/usr/bin/otool", "native inspection boundary differs")
    if live:
        require(file_digest(value["inspector"]["path"]) == value["inspector"]["digest"], "native inspector changed")
    require(isinstance(value["images"], list) and value["images"], "native graph absent")
    for image in value["images"]:
        keys(image, ("path", "executable", "rpathStack", "dependencies"))
        require(isinstance(image["rpathStack"], list) and all(isinstance(path, str) and path.startswith("/") for path in image["rpathStack"]), "native rpath context differs")
        for field in ("path", "executable"):
            require(str(absolute(image[field])).lstrip("/") in runtime["files"], "native image outside captured bytes")
        for dependency in image["dependencies"]:
            keys(dependency, ("command", "requested", "resolved", "systemExempt"))
            require(dependency["command"] in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_DYLINKER") and isinstance(dependency["requested"], str) and dependency["requested"], "native load command differs")
            target = absolute(dependency["resolved"])
            system = any(inside(target, PurePosixPath(root)) for root in value["systemExemptions"])
            require(type(dependency["systemExempt"]) is bool and dependency["systemExempt"] is system, "native dependency exemption differs")
            if not system:
                require(str(target) in runtime["roots"] and str(target).lstrip("/") in runtime["files"], "native dependency bytes missing")


def verify_enrollment(repository_root, enrollment, live=False):
    """Pure replay; no command, install, network, or tool-version probe."""
    require(type(live) is bool, "invalid live flag")
    repository = Path(repository_root).resolve(strict=True)
    if isinstance(enrollment, (str, Path)):
        enrollment = parse(Path(enrollment).read_bytes())
    keys(enrollment, ("schema", "qualificationEligible", "provenance", "target", "host", "repositoryRoot", "inputs", "environment", "interpreter", "runtime", "nativeDiscovery", "managedRuntime", "tools", "distributions", "wheels", "processes"))
    lock, inputs = load_inputs(repository)
    require(enrollment["schema"] == SCHEMA and enrollment["qualificationEligible"] is False and enrollment["provenance"] == PROVENANCE and enrollment["target"] == TARGET, "enrollment claim/target differs")
    original_repository = absolute(enrollment["repositoryRoot"])
    retained_inputs = enrollment["inputs"]
    require(isinstance(retained_inputs, dict) and set(retained_inputs) == set(inputs), "enrollment source inputs differ")
    for relative, expected in inputs.items():
        require(retained_inputs[relative] == {"path": str(original_repository / relative), "digest": expected["digest"]}, "enrollment source digest/path differs")
    if live:
        require(str(original_repository) == str(repository), "actual source repository changed")
    host = enrollment["host"]
    keys(host, ("platform", "machine", "implementation", "osVersion", "runnerOS"))
    require(host["platform"] == "darwin" and host["machine"] == "arm64" and host["implementation"] == "cpython" and host["runnerOS"] == "macOS"
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", host["osVersion"]) is not None and int(host["osVersion"].split(".")[0]) >= 15, "observed host platform differs")
    if live:
        require(host["platform"] == sys.platform and host["machine"] == platform.machine() and host["implementation"] == sys.implementation.name and host["osVersion"] == platform.mac_ver()[0], "actual host platform changed")
    replay = runpy.run_path(str(source(repository, REPLAY)))["runtime_closure"]
    runtime = enrollment["runtime"]
    replay(runtime, live)
    interpreter = enrollment["interpreter"]
    keys(interpreter, ("path", "digest", "version", "sysVersion", "basePrefix", "stdlibRoot", "soabi", "cacheTag"))
    if live:
        require(platform.python_version() == interpreter["version"] and sys.implementation.cache_tag == interpreter["cacheTag"] and sysconfig.get_config_var("SOABI") == interpreter["soabi"], "live CPython ABI/version changed")
    require(isinstance(interpreter["sysVersion"], str) and interpreter["sysVersion"].startswith("3.14.7 "), "observed full CPython version absent")
    require(interpreter["version"] == "3.14.7" and interpreter["cacheTag"] == "cpython-314" and interpreter["soabi"].startswith("cpython-314-"), "actual managed CPython identity differs")
    stdlib = absolute(interpreter["stdlibRoot"])
    require(inside(stdlib, absolute(interpreter["basePrefix"])) and runtime["exclusions"] == [str(stdlib / "site-packages")], "runtime exclusions expanded")
    require(runtime["files"].get(str(absolute(interpreter["path"])).lstrip("/")) == interpreter["digest"], "managed interpreter bytes absent")
    managed = enrollment["managedRuntime"]
    keys(managed, ("snapshot", "beforeDigest", "afterDigest", "nativeDiscovery"))
    replay(managed["snapshot"], live)
    require(managed["snapshot"]["digest"] == managed["beforeDigest"] == managed["afterDigest"], "managed runtime changed during provisioning")
    require(managed["snapshot"]["exclusions"] == runtime["exclusions"], "managed exclusions differ")
    for name, sha in managed["snapshot"]["files"].items():
        require(runtime["files"].get(name) == sha, "pre-provision managed input missing/changed")
    native_graph(managed["nativeDiscovery"], managed["snapshot"], live)
    native_graph(enrollment["nativeDiscovery"], runtime, live)
    tools = enrollment["tools"]
    keys(tools, ("python3", "ruff", "mypy", "pytest", "build", "hatchling"))
    python = tools["python3"]
    keys(python, ("path", "digest", "version"))
    python_path = absolute(python["path"])
    venv = python_path.parent.parent
    require(python_path.name == "python3" and python_path.parent.name == "bin" and str(venv) in runtime["roots"] and not inside(venv, original_repository), "isolated venv boundary differs")
    require(python["version"] == "3.14.7" and runtime["files"].get(str(python_path).lstrip("/")) == python["digest"], "actual SDK Python bytes absent")
    require(str(stdlib) in runtime["roots"] and interpreter["path"] in runtime["roots"], "managed interpreter/stdlib roots absent")
    for name in ("ruff", "mypy", "pytest"):
        item = tools[name]
        keys(item, ("path", "digest", "version", "distribution"))
        path = absolute(item["path"])
        require(path == venv / "bin" / name and item["version"] == ROOTS[name] and item["distribution"] == name and runtime["files"].get(str(path).lstrip("/")) == item["digest"], "actual SDK launcher bytes/version differ")
    for name, module in (("build", "build"), ("hatchling", "hatchling.build")):
        require(tools[name] == {"module": module, "version": ROOTS[name], "distribution": name}, "installed build/backend identity differs")
    distributions = enrollment["distributions"]
    require(set(distributions) == {w["name"] for w in lock["wheels"]}, "installed distribution closure differs")
    for wheel in lock["wheels"]:
        item = distributions[wheel["name"]]
        keys(item, ("version", "metadataPath", "metadataDigest"))
        path = absolute(item["metadataPath"])
        require(inside(path, venv) and path.name == "METADATA" and item["version"] == wheel["version"] and item["metadataDigest"] == "sha256:" + wheel["wheelMetadataSha256"] and runtime["files"].get(str(path).lstrip("/")) == item["metadataDigest"], "installed metadata differs from exact official wheel")
    require(isinstance(enrollment["wheels"], list) and len(enrollment["wheels"]) == len(lock["wheels"]), "original wheel evidence incomplete")
    for item, wheel in zip(enrollment["wheels"], lock["wheels"]):
        require(item == {"filename": wheel["filename"], "path": str(venv.parent / "wheels" / wheel["filename"]), "digest": "sha256:" + wheel["sha256"], "bytes": wheel["size"]}, "original wheel descriptor differs")
        if live:
            path = Path(item["path"])
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == item["bytes"] and file_digest(path) == item["digest"], "original wheel bytes changed")
    processes = enrollment["processes"]
    require(len(processes) == 2, "bootstrap process count differs")
    commands = [[interpreter["path"], "-I", "-S", "-B", "-m", "venv", "--without-pip", "--copies", str(venv)],
                [interpreter["path"], "-I", "-S", "-B", "-c", PIP_CODE, str(venv.parent / "bootstrap-pip"), "--python", str(python_path), "--isolated", "--disable-pip-version-check", "--no-input", "install", "--no-index", "--find-links", str(venv.parent / "wheels"), "--only-binary=:all:", "--require-hashes", "--no-compile", "--no-cache-dir", "-r", retained_inputs[REQUIREMENTS]["path"]]]
    expected_process_environment = {"PATH": "/usr/bin:/bin", "HOME": str(venv.parent), "TMPDIR": str(venv.parent / "tmp"), "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": "/dev/null"}
    for process, command in zip(processes, commands):
        keys(process, ("argv", "cwd", "environment", "exitCode", "stdout", "stderr", "stdoutDigest", "stderrDigest"))
        require(process["exitCode"] == 0 and process["stdoutDigest"] == digest(process["stdout"].encode()) and process["stderrDigest"] == digest(process["stderr"].encode()), "actual bootstrap process failed/unbound")
        require(process["argv"] == command and process["environment"] == expected_process_environment and process["cwd"] == str(venv.parent), "bootstrap command/environment escaped exact isolated contract")
    expected_env = {"LEGION_PYTHON_SDK_ENROLLMENT_JSON": str(venv.parent / "enrollment.json"), "LEGION_PYTHON_SDK_PYTHON": str(python_path), "LEGION_PYTHON_SDK_BIN_DIR": str(python_path.parent)}
    require(enrollment["environment"] == expected_env, "SDK enrollment exports differ")
    return {"lockDigest": inputs[LOCK]["digest"], "runtimeDigest": runtime["digest"], "managedRuntimeDigest": managed["snapshot"]["digest"], "wheelSetDigest": digest(canonical(enrollment["wheels"])), "pythonDigest": python["digest"]}


def wheel_metadata(path, wheel):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) <= 100000 and sum(m.file_size for m in members) <= 512 * 1024 * 1024, "wheel archive bounds")
        for member in members:
            p = PurePosixPath(member.filename)
            require(not p.is_absolute() and ".." not in p.parts and "\\" not in member.filename and not stat.S_ISLNK(member.external_attr >> 16), "unsafe wheel member")
        names = [m.filename for m in members if m.filename.endswith(".dist-info/METADATA")]
        require(len(names) == 1, "wheel metadata count")
        raw = archive.read(names[0])
        message = email.parser.BytesParser().parsebytes(raw)
        require(re.sub(r"[-_.]+", "-", message["Name"]).lower() == wheel["name"] and message["Version"] == wheel["version"] and digest(raw) == "sha256:" + wheel["wheelMetadataSha256"] and message.get_all("Requires-Dist", []) == wheel["requiresDist"] and message["Requires-Python"] == wheel["requiresPython"], "official wheel METADATA differs")
    return names[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "macOS", "managed macOS GitHub CI only")
    require(sys.platform == "darwin" and platform.machine() == "arm64" and sys.implementation.name == "cpython" and platform.python_version() == "3.14.7" and not sysconfig.get_config_var("Py_GIL_DISABLED"), "require actual managed arm64 CPython3.14.7 standard ABI")
    require(int(platform.mac_ver()[0].split(".")[0]) >= 15, "require managed macOS15+")
    repository = args.repository_root.resolve(strict=True)
    require(Path(__file__).resolve(strict=True) == source(repository, SELF), "bootstrap must be supplied source")
    lock, inputs = load_inputs(repository)
    capture = runpy.run_path(str(source(repository, CAPTURE)))
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = args.output_root.absolute()
    require(output == output.resolve() and inside(output, temporary) and output != temporary and not inside(output, repository) and not output.exists(), "fresh canonical private RUNNER_TEMP child outside project required")
    interpreter = Path(sys.executable).resolve(strict=True)
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    require(inside(stdlib, base_prefix), "managed stdlib outside prefix")
    roots = {str(interpreter), str(stdlib)}
    library = sysconfig.get_config_var("LDLIBRARY")
    for candidate in [base_prefix / "Python", Path(sysconfig.get_config_var("LIBDIR") or base_prefix) / (library or "__absent__")]:
        if candidate.is_file(): roots.add(str(candidate.resolve(strict=True)))
    for entry in sys.path:
        candidate = Path(entry)
        if candidate.is_file() and candidate.suffix == ".zip" and inside(candidate.resolve(strict=True), base_prefix): roots.add(str(candidate.resolve(strict=True)))
    exclusions = [str(stdlib / "site-packages")]
    initial_roots, initial_aliases, initial_absent, managed_native = capture["native_dependency_closure"](sorted(roots), exclusions, interpreter)
    managed_before = capture["snapshot"](initial_roots, exclusions, initial_aliases, initial_absent)
    output.mkdir(mode=0o700)
    wheelhouse = output / "wheels"; wheelhouse.mkdir(mode=0o700)
    for wheel in lock["wheels"]:
        path = capture["fetch"](wheel, wheelhouse)
        wheel_metadata(path, wheel)
        path.chmod(0o444)
    (output / "tmp").mkdir(mode=0o700)
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(output), "TMPDIR": str(output / "tmp"), "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": os.devnull}
    processes = []
    def run(argv):
        sequence = str(len(processes) + 1)
        try:
            result = subprocess.run(argv, env=environment, cwd=output, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        except subprocess.TimeoutExpired as error:
            (output / ("bootstrap-process-" + sequence + ".stdout.bin")).write_bytes(error.stdout or b"")
            (output / ("bootstrap-process-" + sequence + ".stderr.bin")).write_bytes(error.stderr or b"")
            raise
        (output / ("bootstrap-process-" + sequence + ".stdout.bin")).write_bytes(result.stdout)
        (output / ("bootstrap-process-" + sequence + ".stderr.bin")).write_bytes(result.stderr)
        require(len(result.stdout) <= 2 * 1024 * 1024 and len(result.stderr) <= 2 * 1024 * 1024, "bootstrap output bound")
        record = {"argv": argv, "cwd": str(output), "environment": environment, "exitCode": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode(), "stdoutDigest": digest(result.stdout), "stderrDigest": digest(result.stderr)}
        processes.append(record)
        (output / ("bootstrap-process-" + str(len(processes)) + ".json")).write_bytes(canonical(record) + b"\n")
        require(result.returncode == 0, "bootstrap process failed; original diagnostics retained")
    venv = output / "venv"
    run([str(interpreter), "-I", "-S", "-B", "-m", "venv", "--without-pip", "--copies", str(venv)])
    pip = next(w for w in lock["wheels"] if w["name"] == "pip")
    bootstrap = output / "bootstrap-pip"; bootstrap.mkdir(mode=0o700)
    with zipfile.ZipFile(wheelhouse / pip["filename"]) as archive: archive.extractall(bootstrap)
    run([str(interpreter), "-I", "-S", "-B", "-c", PIP_CODE, str(bootstrap), "--python", str(venv / "bin/python3"), "--isolated", "--disable-pip-version-check", "--no-input", "install", "--no-index", "--find-links", str(wheelhouse), "--only-binary=:all:", "--require-hashes", "--no-compile", "--no-cache-dir", "-r", str(source(repository, REQUIREMENTS))])
    managed_after = capture["snapshot"](initial_roots, exclusions, managed_before["links"], managed_before["absent"])
    require(managed_before == managed_after, "managed runtime changed during tools provisioning")
    bound_roots, aliases, absent, native = capture["native_dependency_closure"](sorted(roots | {str(venv)}), exclusions, venv / "bin/python3")
    runtime = capture["snapshot"](bound_roots, exclusions, aliases, absent)
    distributions = {}
    for path in sorted((venv / "lib/python3.14/site-packages").glob("*.dist-info/METADATA")):
        message = email.parser.BytesParser().parsebytes(path.read_bytes())
        name = re.sub(r"[-_.]+", "-", message["Name"]).lower()
        require(name not in distributions, "duplicate installed distribution")
        distributions[name] = {"version": message["Version"], "metadataPath": str(path), "metadataDigest": file_digest(path)}
    tools = {"python3": {"path": str(venv / "bin/python3"), "digest": file_digest(venv / "bin/python3"), "version": platform.python_version()}}
    for name in ("ruff", "mypy", "pytest"):
        path = venv / "bin" / name
        require(path.is_file() and not path.is_symlink(), "missing regular tool launcher")
        tools[name] = {"path": str(path), "digest": file_digest(path), "version": ROOTS[name], "distribution": name}
    tools.update({name: {"module": module, "version": ROOTS[name], "distribution": name} for name, module in (("build", "build"), ("hatchling", "hatchling.build"))})
    enrollment = {"schema": SCHEMA, "qualificationEligible": False, "provenance": PROVENANCE, "target": TARGET, "host": {"platform": sys.platform, "machine": platform.machine(), "implementation": sys.implementation.name, "osVersion": platform.mac_ver()[0], "runnerOS": os.environ["RUNNER_OS"]}, "repositoryRoot": str(repository), "inputs": inputs,
        "interpreter": {"path": str(interpreter), "digest": file_digest(interpreter), "version": platform.python_version(), "sysVersion": sys.version, "basePrefix": str(base_prefix), "stdlibRoot": str(stdlib), "soabi": sysconfig.get_config_var("SOABI"), "cacheTag": sys.implementation.cache_tag},
        "runtime": runtime, "nativeDiscovery": native, "managedRuntime": {"snapshot": managed_before, "beforeDigest": managed_before["digest"], "afterDigest": managed_after["digest"], "nativeDiscovery": managed_native}, "tools": tools, "distributions": distributions,
        "wheels": [{"filename": w["filename"], "path": str(wheelhouse / w["filename"]), "digest": "sha256:" + w["sha256"], "bytes": w["size"]} for w in lock["wheels"]], "processes": processes,
        "environment": {"LEGION_PYTHON_SDK_ENROLLMENT_JSON": str(output / "enrollment.json"), "LEGION_PYTHON_SDK_PYTHON": str(venv / "bin/python3"), "LEGION_PYTHON_SDK_BIN_DIR": str(venv / "bin")}}
    verify_enrollment(repository, enrollment, live=True)
    path = output / "enrollment.json"; path.write_bytes(canonical(enrollment) + b"\n")
    require(capture["snapshot"](bound_roots, exclusions, runtime["links"], runtime["absent"]) == runtime, "runtime changed while enrollment retained")
    print("PYTHON_SDK_ENROLLMENT " + canonical({"path": str(path), "digest": file_digest(path), "runtimeDigest": runtime["digest"], "wheelBytes": sum(w["size"] for w in lock["wheels"])}).decode())


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print("python-sdk-provisioning-failed: " + str(error), file=sys.stderr)
        sys.exit(1)
