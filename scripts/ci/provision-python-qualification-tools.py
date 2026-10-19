#!/usr/bin/env python3
"""CI-only binary-wheel provisioning; never resolves, builds, or touches a project.

The reviewed locks target the managed macOS 15 arm64 CPython 3.14 runner.
Enrollment describes observed bytes, not an interpreter provenance/freshness claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
import urllib.parse
import urllib.request
import zipfile

SCHEMA = "legion-python-tool-enrollment/1"
VERSIONS = {"pip-audit": "2.10.0", "semgrep": "1.141.0"}
LOCK_HEADER = "# Official PyPI binary wheels only. No index, source distribution, or dependency build.\n"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def within(path, root):
    return path == root or root in path.parents


def resolve_link_chain(path, observed, allow_missing=False):
    """Resolve components & seal every link hop, including parent aliases."""
    require(path.is_absolute(), "absolute runtime path required")
    current = Path("/")
    pending = list(path.parts[1:])
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            require(allow_missing, "missing runtime path: " + str(current))
            return Path(os.path.normpath(str(current.joinpath(*pending))))
        if stat.S_ISLNK(mode):
            hops += 1
            require(hops <= 40, "runtime link cycle/depth exceeded")
            raw = os.readlink(current)
            key = current.relative_to("/").as_posix()
            require(key not in observed or observed[key] == raw, "runtime link changed during capture")
            observed[key] = raw
            target = Path(raw)
            if target.is_absolute():
                current = Path("/")
                pending = list(target.parts[1:]) + pending
            else:
                current = current.parent
                pending = list(target.parts) + pending
    return current


def snapshot(roots, exclusions, sealed_links=None, absent=None):
    """Complete files, every link hop, & absent native search candidates."""
    files, links = {}, {}
    declared = [Path(p) for p in roots]
    omitted = [Path(p) for p in exclusions]
    sealed_links = {} if sealed_links is None else sealed_links
    absent = [] if absent is None else absent
    require(absent == sorted(set(absent)), "noncanonical absent-path list")

    def visit(path):
        if any(within(path, p) for p in omitted):
            return
        mode = path.lstat().st_mode
        key = path.relative_to("/").as_posix()
        if stat.S_ISLNK(mode):
            target = resolve_link_chain(path, links)
            require(any(within(target, root) for root in declared), "runtime symlink escapes bound runtime: " + str(path))
            require(not any(within(target, p) for p in omitted), "runtime symlink enters excluded global packages: " + str(path))
        elif stat.S_ISREG(mode):
            files[key] = digest_file(path)
        elif stat.S_ISDIR(mode):
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            raise ValueError("unsupported runtime entry: " + str(path))

    for root in declared:
        require(root.is_absolute() and resolve_link_chain(root, links) == root, "runtime root must be canonical: " + str(root))
        visit(root)
    # Native load commands can name aliases outside canonical runtime roots.
    # Seal these nodes too; no intermediate directory alias remains unobserved.
    for key, raw in sealed_links.items():
        path = Path("/") / key
        require(path.is_symlink() and os.readlink(path) == raw, "sealed runtime alias changed: " + str(path))
        target = resolve_link_chain(path, links)
        require(any(within(target, root) for root in declared) or (target.is_dir() and any(within(Path("/") / name, target) for name in files)), "runtime alias target has no bound descendant: " + str(path))
    for name in absent:
        path = Path(name)
        require(path.is_absolute() and not os.path.lexists(path), "native search candidate appeared: " + name)
        resolve_link_chain(path, links, allow_missing=True)
    # A caller replays this function with the full returned map. Exact equality
    # then detects a new, removed, or retargeted intermediate hop.
    for key, raw in sealed_links.items():
        require(links.get(key) == raw, "sealed alias omitted")
    value = {"absent": absent, "files": dict(sorted(files.items())), "links": dict(sorted(links.items())), "roots": roots}
    return dict(value, digest=digest_bytes(canonical(value)), root="/", exclusions=exclusions)


MACHO_MAGICS = {bytes.fromhex(x) for x in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}
SYSTEM_LIBRARY_ROOTS = (Path("/usr/lib"), Path("/System/Library"))


def is_arm64_macho(path):
    with path.open("rb") as stream:
        header = stream.read(4096)
    if len(header) < 12 or header[:4] not in MACHO_MAGICS:
        return False
    magic = header[:4].hex()
    endian = ">" if magic in ("feedface", "feedfacf", "cafebabe", "cafebabf") else "<"
    if magic in ("cafebabe", "bebafeca", "cafebabf", "bfbafeca"):
        count = struct.unpack(endian + "I", header[4:8])[0]
        width = 32 if magic in ("cafebabf", "bfbafeca") else 20
        if not 1 <= count <= 64:
            return False
        if len(header) < 8 + count * width:
            return False
        return any(struct.unpack(endian + "I", header[8 + index * width:12 + index * width])[0] == 0x0100000C for index in range(count))
    return struct.unpack(endian + "I", header[4:8])[0] == 0x0100000C


def native_dependency_closure(initial_roots, exclusions, python_executable):
    """Use system otool in CI; resolve all non-system load commands recursively.

    Unsupported or ambiguous loader resolution fails closed. No scanner/native
    image is executed. Exempt only dyld's system-owned library locations.
    """
    inspector = Path("/usr/bin/otool")
    require(inspector.is_file() and not inspector.is_symlink(), "missing system otool")
    roots, aliases, absent = set(initial_roots), {}, set()
    images, cache = [], {}
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}

    def system(path):
        return any(within(Path(os.path.normpath(str(path))), root) for root in SYSTEM_LIBRARY_ROOTS)

    def inspect(path):
        if path in cache:
            return cache[path]
        header = subprocess.run([str(inspector), "-arch", "arm64", "-hv", str(path)], check=True, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30).stdout
        require(re.search(r"\b(?:EXECUTE|DYLIB|BUNDLE)\b", header) is not None, "unsupported Mach-O file type: " + str(path))
        executable = re.search(r"\bEXECUTE\b", header) is not None
        output = subprocess.run([str(inspector), "-arch", "arm64", "-l", str(path)], check=True, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30).stdout
        loads, rpaths, command = [], [], None
        for line in output.splitlines():
            match = re.fullmatch(r"\s*cmd (LC_\S+)\s*", line)
            if match:
                command = match.group(1)
                require(command not in ("LC_DYLD_ENVIRONMENT", "LC_LOADFVMLIB", "LC_PREBOUND_DYLIB"), "unsupported embedded/legacy dyld command")
            match = re.fullmatch(r"\s*(?:name|path) (.+) \(offset \d+\)\s*", line)
            if not match:
                continue
            if command == "LC_RPATH":
                rpaths.append(match.group(1))
            elif command in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_DYLINKER"):
                loads.append((command, match.group(1)))
        cache[path] = (executable, loads, rpaths)
        return cache[path]

    def expand(value, loader, executable):
        if value == "@loader_path" or value.startswith("@loader_path/"):
            return loader.parent / value[len("@loader_path/"):] if value != "@loader_path" else loader.parent
        if value == "@executable_path" or value.startswith("@executable_path/"):
            return executable.parent / value[len("@executable_path/"):] if value != "@executable_path" else executable.parent
        require(value.startswith("/"), "unsupported native loader path: " + value)
        return Path(value)

    initial = snapshot(sorted(roots), exclusions)
    seeds = []
    for name in initial["files"]:
        path = Path("/") / name
        if is_arm64_macho(path):
            seeds.append(path)
    aliases.update(initial["links"])
    python_executable = resolve_link_chain(python_executable, aliases)
    require(python_executable in seeds and inspect(python_executable)[0], "no isolated native Python executable observed")
    # Python extension modules use the isolated launcher interpreter context;
    # bundled executable images (e.g. semgrep-core) use their own context.
    python_rpaths = tuple(str(expand(value, python_executable, python_executable)) for value in inspect(python_executable)[2])
    queue = [(path, path if inspect(path)[0] else python_executable, () if inspect(path)[0] else python_rpaths) for path in seeds]
    seen, choices = set(), {}
    while queue:
        loader, executable, inherited = queue.pop(0)
        context = (str(loader), str(executable), inherited)
        if context in seen:
            continue
        seen.add(context)
        require(len(seen) <= 8192, "native dependency context limit exceeded")
        _, loads, raw_rpaths = inspect(loader)
        local = tuple(str(expand(value, loader, executable)) for value in raw_rpaths)
        stack = tuple(dict.fromkeys(local + inherited))
        resolved_loads = []
        for command, requested in loads:
            if requested.startswith("@rpath/"):
                candidates = [Path(root) / requested[len("@rpath/"):] for root in stack]
                require(candidates, "unresolved @rpath load: " + requested)
            else:
                candidates = [expand(requested, loader, executable)]
            matches = {}
            for candidate in candidates:
                normalized = Path(os.path.normpath(str(candidate)))
                if system(normalized):
                    matches[str(normalized)] = (normalized, True)
                elif os.path.lexists(candidate):
                    resolved = resolve_link_chain(candidate, aliases)
                    require(resolved.is_file(), "native dependency is not a regular file")
                    matches[str(resolved)] = (resolved, False)
                else:
                    resolve_link_chain(candidate, aliases, allow_missing=True)
                    absent.add(str(candidate))
            require(len(matches) == 1, "missing or ambiguous native dependency: " + requested + " from " + str(loader))
            resolved, exempt = next(iter(matches.values()))
            key = (str(loader), requested)
            require(key not in choices or choices[key] == str(resolved), "native load differs by executable/rpath context")
            choices[key] = str(resolved)
            resolved_loads.append({"command": command, "requested": requested, "resolved": str(resolved), "systemExempt": exempt})
            if not exempt:
                roots.add(str(resolved))
                require(is_arm64_macho(resolved), "non-arm64-Mach-O native dependency")
                queue.append((resolved, executable, stack))
        images.append({"path": str(loader), "executable": str(executable), "rpathStack": list(stack), "dependencies": resolved_loads})
    # A candidate found in another context cannot also be claimed absent.
    absent = sorted(path for path in absent if not os.path.lexists(path))
    metadata = {"inspector": {"path": str(inspector), "digest": digest_file(inspector)}, "systemExemptions": [str(path) for path in SYSTEM_LIBRARY_ROOTS], "images": sorted(images, key=lambda row: (row["path"], row["executable"], row["rpathStack"]))}
    metadata["digest"] = digest_bytes(canonical(metadata))
    return sorted(roots), aliases, absent, metadata


def fetch(wheel, directory):
    name = wheel["filename"]
    require(re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", name) is not None, "non-wheel filename")
    parsed = urllib.parse.urlparse(wheel["url"])
    require(parsed.scheme == "https" and parsed.hostname == "files.pythonhosted.org" and not parsed.query and not parsed.fragment, "nonofficial wheel URL")
    require(re.fullmatch(r"[0-9a-f]{64}", wheel["sha256"]) is not None, "invalid wheel pin")
    path = directory / name
    # Wheel bytes are verified before either zipimport or pip can inspect them.
    with urllib.request.urlopen(wheel["url"], timeout=120) as response, path.open("xb") as stream:
        require(urllib.parse.urlparse(response.url).hostname == "files.pythonhosted.org", "wheel redirect escaped official host")
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(total <= wheel["size"], "oversized wheel download")
            stream.write(chunk)
    require(total == wheel["size"] and digest_file(path) == "sha256:" + wheel["sha256"], "wheel digest/length mismatch: " + name)
    return path


def run(arguments, env, cwd):
    subprocess.run(arguments, check=True, env=env, cwd=cwd, stdin=subprocess.DEVNULL, timeout=600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, choices=sorted(VERSIONS))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "macOS", "provisioning is managed macOS CI only")
    require(sys.platform == "darwin" and platform.machine() == "arm64" and sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14), "unsupported-python-tool-target: require existing arm64 CPython 3.14")
    require(tuple(map(int, platform.mac_ver()[0].split(".")[:1])) >= (15,), "unsupported-python-tool-target: require macOS >=15")
    repository = args.repository_root.resolve(strict=True)
    helper = Path(__file__).resolve(strict=True)
    require(helper == repository / "scripts/ci/provision-python-qualification-tools.py", "helper must come from supplied repository")
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    requested = args.output_root.absolute()
    require(requested == requested.resolve() and within(requested, temporary) and not within(requested, repository) and requested != temporary, "output must be canonical private RUNNER_TEMP child outside project")
    require(not requested.exists(), "refusing existing provisioning output")
    lock_path = repository / "scripts/ci/python-tool-locks" / (args.tool + "-macos-arm64-cp314.json")
    requirements_path = lock_path.with_suffix(".txt")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    require(lock["schema"] == "legion-python-tool-lock/1" and lock["tool"] == {"name": args.tool, "version": VERSIONS[args.tool]}, "tool lock mismatch")
    require(lock["target"] == {"implementation": "cpython", "machine": "arm64", "minimumMacOS": "15.0", "platform": "darwin", "python": "3.14"}, "lock target mismatch")
    wheels = lock["wheels"]
    require(wheels and len({w["name"] for w in wheels}) == len(wheels), "duplicate/empty wheel closure")
    expected_requirements = LOCK_HEADER + "".join(w["name"] + "==" + w["version"] + " --hash=sha256:" + w["sha256"] + "\n" for w in wheels)
    require(requirements_path.read_text(encoding="utf-8") == expected_requirements, "requirements do not equal pinned wheel closure")
    bootstrap = next(w for w in wheels if w["name"] == "pip")
    require(bootstrap["version"] == "26.2.1", "unpinned pip bootstrap")
    tool = next(w for w in wheels if w["name"] == args.tool)
    require(tool["version"] == VERSIONS[args.tool], "unpinned tool")
    requested.mkdir(parents=True, mode=0o700)
    wheelhouse = requested / "wheels"
    wheelhouse.mkdir(mode=0o700)
    for wheel in wheels:
        fetch(wheel, wheelhouse)
    environment = {"PATH": os.environ["PATH"], "HOME": str(requested), "TMPDIR": str(requested / "tmp"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": os.devnull, "LANG": "en_US.UTF-8"}
    (requested / "tmp").mkdir(mode=0o700)
    interpreter = Path(sys.executable).resolve(strict=True)
    interpreter_digest = digest_file(interpreter)
    venv = requested / "venv"
    run([str(interpreter), "-I", "-S", "-B", "-m", "venv", "--without-pip", "--copies", str(venv)], environment, requested)
    # Bootstrap only reviewed pip wheel. --python targets the empty venv; pip's
    # resolver checks all active dependency metadata against this offline set.
    bootstrap_root = requested / "bootstrap-pip"
    bootstrap_root.mkdir(mode=0o700)
    with zipfile.ZipFile(wheelhouse / bootstrap["filename"]) as archive:
        for member in archive.infolist():
            relative = Path(member.filename)
            require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in member.filename, "unsafe bootstrap wheel path")
            require(not stat.S_ISLNK(member.external_attr >> 16), "bootstrap wheel symlink forbidden")
        archive.extractall(bootstrap_root)
    bootstrap_code = "import sys; sys.path.insert(0, sys.argv.pop(1)); from pip._internal.cli.main import main; sys.exit(main())"
    run([str(interpreter), "-I", "-S", "-B", "-c", bootstrap_code, str(bootstrap_root), "--python", str(venv / "bin/python3"), "--isolated", "--disable-pip-version-check", "--no-input", "install", "--no-index", "--find-links", str(wheelhouse), "--only-binary=:all:", "--require-hashes", "--no-compile", "--no-cache-dir", "-r", str(requirements_path)], environment, requested)
    launcher = venv / "bin" / args.tool
    require(launcher.is_file() and not launcher.is_symlink(), "launcher must be regular installed file")
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    require(within(stdlib, base_prefix), "stdlib outside interpreter prefix")
    roots = {venv.as_posix(), stdlib.as_posix(), interpreter.as_posix()}
    # CPython framework binary or non-framework libpython, when present.
    library = sysconfig.get_config_var("LDLIBRARY")
    for candidate in [base_prefix / "Python", Path(sysconfig.get_config_var("LIBDIR") or base_prefix) / (library or "__absent__")]:
        if candidate.is_file():
            roots.add(candidate.resolve(strict=True).as_posix())
    for entry in sys.path:
        candidate = Path(entry)
        if candidate.is_file() and candidate.suffix == ".zip" and within(candidate.resolve(strict=True), base_prefix):
            roots.add(candidate.resolve(strict=True).as_posix())
    exclusions = [(stdlib / "site-packages").as_posix()]
    bound_roots, aliases, absent, native = native_dependency_closure(sorted(roots), exclusions, venv / "bin/python3")
    runtime = snapshot(bound_roots, exclusions, aliases, absent)
    require(digest_file(interpreter) == interpreter_digest, "managed interpreter changed during provisioning")
    enrollment = {"schema": SCHEMA, "tool": {"name": args.tool, "version": VERSIONS[args.tool], "wheelSha256": "sha256:" + tool["sha256"]}, "launcher": {"path": launcher.as_posix(), "digest": digest_file(launcher)}, "interpreter": {"path": interpreter.as_posix(), "digest": interpreter_digest, "version": platform.python_version(), "basePrefix": base_prefix.as_posix(), "stdlibRoot": stdlib.as_posix()}, "runtime": runtime, "nativeDiscovery": native, "lock": {"path": lock_path.as_posix(), "digest": digest_file(lock_path)}, "requirements": {"path": requirements_path.as_posix(), "digest": digest_file(requirements_path)}, "provisioner": {"path": helper.as_posix(), "digest": digest_file(helper)}, "wheels": [{"filename": w["filename"], "path": (wheelhouse / w["filename"]).as_posix(), "digest": "sha256:" + w["sha256"]} for w in wheels]}
    output = requested / "enrollment.json"
    output.write_bytes(json.dumps(enrollment, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n")
    require(snapshot(bound_roots, exclusions, runtime["links"], runtime["absent"]) == runtime, "runtime changed while enrollment was written")
    print("PYTHON_TOOL_ENROLLMENT " + canonical({"tool": args.tool, "path": output.as_posix(), "digest": digest_file(output), "runtimeDigest": runtime["digest"]}).decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print("python-tool-provisioning-failed: " + str(error), file=sys.stderr)
        sys.exit(1)
