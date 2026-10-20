#!/usr/bin/env python3
"""CI-only data provisioning. Pins Rust fixture inputs & discovers native linker dependencies in managed CI only."""
import argparse
import hashlib
import io
import json
import os
import platform
import runpy
import subprocess
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def tree(root):
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("input symlink")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = digest(path.read_bytes())
        elif not path.is_dir():
            raise ValueError("nonregular input")
    return files



def native_linker(repository, root):
    # These are CI host discovery commands, never target-project commands.
    # Fixed arm64 fixture scope; no implicit PATH/toolchain fallback.
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported native linker enrollment platform")
    helper = repository / "scripts/ci/provision-python-qualification-tools.py"
    api = runpy.run_path(str(helper))
    aliases, probes = {}, []
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    def probe(args):
        result = subprocess.run(args, env=environment, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        probes.append({"args": args, "cwd": str(root), "environment": environment, "exitCode": result.returncode,
                       "stdout": {"rawBytes": list(result.stdout), "digest": digest(result.stdout)},
                       "stderr": {"rawBytes": list(result.stderr), "digest": digest(result.stderr)}})
        if result.returncode or len(result.stdout) + len(result.stderr) > 1024 * 1024:
            raise ValueError("native discovery failed or exceeded bound")
        return result.stdout.decode("utf-8").strip()
    xcrun = Path("/usr/bin/xcrun")
    if xcrun.is_symlink() or not xcrun.is_file():
        raise ValueError("fixed native discovery executable unavailable")
    tools = {}
    for name in ("clang", "ld", "ar", "ranlib", "dsymutil"):
        selected = probe([str(xcrun), "--find", name])
        if not Path(selected).is_absolute():
            raise ValueError("nonabsolute native tool selection")
        resolved = api["resolve_link_chain"](Path(selected), aliases)
        tools[name] = {"selectedPath": selected, "path": str(resolved), "digest": digest(resolved.read_bytes())}
    sdk = Path(probe([str(xcrun), "--show-sdk-path"]))
    sdk = api["resolve_link_chain"](sdk, aliases)
    clang = tools["clang"]["path"]
    resource = Path(probe([clang, "-print-resource-dir"]))
    resource = api["resolve_link_chain"](resource, aliases)
    probe([clang, "--version"])
    probe([clang, "-print-search-dirs"])
    # Driver-only trace: -### does not compile, link, or execute any project code.
    probe([clang, "-###", "-isysroot", str(sdk), "-fuse-ld=" + tools["ld"]["path"], "-Wl,-Z", "-L" + str(sdk / "usr/lib"),
           "-F" + str(sdk / "System/Library/Frameworks"), "-L" + str(resource / "lib/darwin"), "-x", "c", "/dev/null", "-o", str(root / "never-created-link-probe")])
    trace_bytes = bytes(probes[-1]["stderr"]["rawBytes"])
    if tools["ld"]["path"].encode() not in trace_bytes or str(sdk).encode() not in trace_bytes:
        raise ValueError("driver trace does not prove selected linker/SDK")
    search_roots = [sdk / "usr/lib", sdk / "System/Library/Frameworks", resource / "lib/darwin"]
    search_inputs, seeds = {}, [Path(tool["path"]) for tool in tools.values()] + [xcrun]
    loader_images = list(seeds)
    suffixes = (".tbd", ".a", ".dylib", ".o")
    # Bind every selectable library/stub in these fixed search roots, including
    # membership. Headers, docs, unrelated SDKs & whole Xcode trees are excluded.
    for search in search_roots:
        if not search.is_dir() or search.is_symlink():
            raise ValueError("native linker search root unavailable/aliased")
        files = {}
        visited = 0
        def visit(path, active):
            nonlocal visited
            visited += 1
            if visited > 200000:
                raise ValueError("linker search enumeration bound exceeded")
            target = path.resolve(strict=True)
            if not target.is_relative_to(sdk) and not target.is_relative_to(resource):
                raise ValueError("linker search escapes enrolled SDK/resource")
            if target.is_dir():
                if target in active:
                    raise ValueError("linker search directory cycle")
                for child in sorted(path.iterdir()):
                    if child.name in ("Headers", "PrivateHeaders", "Modules") or child.name.endswith(".swiftmodule"):
                        continue  # Rust-only fixture: no C/ObjC/Swift source/header compilation.
                    visit(child, active | {target})
            elif path.name.endswith(suffixes):
                resolved = api["resolve_link_chain"](path, aliases)
                if not resolved.is_file():
                    raise ValueError("nonregular linker input")
                files[path.relative_to(search).as_posix()] = digest(resolved.read_bytes())
                seeds.append(resolved)
        visit(search, set())
        search_inputs[str(search)] = files
    optional_absent = []
    for name in ("SDKSettings.json", "SDKSettings.plist"):
        path = sdk / name
        if path.exists():
            seeds.append(api["resolve_link_chain"](path, aliases))
        else:
            api["resolve_link_chain"](path, aliases, allow_missing=True)
            optional_absent.append(str(path))
    # Clang's LTO library may be loaded dynamically rather than through LC_LOAD_DYLIB.
    lto = Path(clang).parent.parent / "lib/libLTO.dylib"
    if lto.exists():
        resolved_lto = api["resolve_link_chain"](lto, aliases)
        seeds.append(resolved_lto)
        loader_images.append(resolved_lto)
    else:
        api["resolve_link_chain"](lto, aliases, allow_missing=True)
        optional_absent.append(str(lto))
    native_bin = root / "native-bin"
    native_bin.mkdir()
    for name, target in {**{name: item["path"] for name, item in tools.items()}, "cc": clang, "xcrun": str(xcrun)}.items():
        (native_bin / name).symlink_to(target)
    seeds.append(native_bin)
    loader_images.append(native_bin)
    seeds = sorted(set(seeds), key=str)
    if len(seeds) > 15000 or sum(path.stat().st_size for path in seeds if path.is_file()) > 1024 * 1024 * 1024:
        raise ValueError("native fixture closure bound exceeded")
    # Fixed pure-Rust fixtures have no native source, FFI, sanitizer or plugin
    # options. Search libraries/stubs are linker data, not executable seeds.
    # Every search input remains in seeds/searchInputs and the final snapshot;
    # tools, xcrun and explicit libLTO still get recursive dyld discovery.
    loader_images = sorted(set(loader_images), key=str)
    roots, loader_aliases, absent, discovery = api["native_dependency_closure"]([str(path) for path in loader_images], [], Path(clang))
    roots = sorted(set(roots) | {str(path) for path in seeds})
    absent = sorted(set(absent) | set(optional_absent))
    for key, value in loader_aliases.items():
        if key in aliases and aliases[key] != value:
            raise ValueError("native alias changed during discovery")
        aliases[key] = value
    runtime = api["snapshot"](roots, [], aliases, absent)
    return {"schema": "legion-rust-native-linker-enrollment/1", "target": "aarch64-apple-darwin",
            "bin": str(native_bin), "sdkRoot": str(sdk), "resourceRoot": str(resource), "tools": tools,
            "discoveryTool": {"path": str(xcrun), "digest": digest(xcrun.read_bytes())},
            "searchInputs": search_inputs, "probes": probes, "runtime": runtime, "nativeDiscovery": discovery,
            "scope": "Rust-only fixed fixture linker/SDK libraries; OS /usr/lib & /System/Library runtime exemptions; no C builds"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("managed CI only; no local package/tool installation")
    repository = Path(__file__).resolve().parents[2]
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = args.root.parent.resolve(strict=True) / args.root.name
    if not root.is_relative_to(temporary) or root.is_relative_to(repository) or root.exists():
        raise ValueError("new isolated RUNNER_TEMP root required")
    inputs_path = repository / "scripts/ci/fixtures/audit-rust-code-sdk/inputs.json"
    inputs_bytes = inputs_path.read_bytes()
    inputs = json.loads(inputs_bytes)
    if inputs["schema"] != "legion-rust-code-fixture-inputs/1":
        raise ValueError("unknown fixture input schema")
    root.mkdir()
    vendor = root / "vendor"
    vendor.mkdir()
    archives = root / "archives"
    archives.mkdir()
    retained_archives = {}
    for package in inputs["packages"]:
        name, version = package["name"], package["version"]
        prefix = f"{name}-{version}"
        expected_url = f"https://static.crates.io/crates/{name}/{prefix}.crate"
        if name != "smallvec" or version not in ("0.6.9", "0.6.10") or package["url"] != expected_url:
            raise ValueError("unsupported fixed source package")
        with urllib.request.urlopen(expected_url, timeout=60) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != package["sha256"]:
            raise ValueError("official crate checksum mismatch")
        archive_path = archives / f"{prefix}.crate"
        archive_path.write_bytes(data)
        retained_archives[prefix] = {"path": str(archive_path), "digest": digest(data), "bytes": len(data), "url": expected_url}
        destination = vendor / prefix
        destination.mkdir()
        extracted = {}
        total = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 1000:
                raise ValueError("crate member bound")
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or not path.parts or path.parts[0] != prefix or any(part in (".", "..") for part in path.parts):
                    raise ValueError("unsafe crate member")
                if member.isdir():
                    continue
                if not member.isfile() or len(path.parts) < 2 or member.size > 1024 * 1024:
                    raise ValueError("crate links/nonregular/oversized member refused")
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if relative in extracted or relative == ".cargo-checksum.json":
                    raise ValueError("duplicate/reserved crate member")
                payload = archive.extractfile(member).read(1024 * 1024 + 1)
                total += len(payload)
                if total > 4 * 1024 * 1024 or len(payload) != member.size:
                    raise ValueError("crate expansion bound")
                extracted[relative] = hashlib.sha256(payload).hexdigest()
                if extracted[relative] != package["files"].get(relative):
                    raise ValueError("source-owned crate file pin mismatch")
                output = destination / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(payload)
        if extracted != package["files"]:
            raise ValueError("incomplete fixed crate closure")
        checksum = {"files": extracted, "package": package["sha256"]}
        (destination / ".cargo-checksum.json").write_text(json.dumps(checksum, sort_keys=True, separators=(",", ":")) + "\n")
    home = root / "cargo-home"
    home.mkdir()
    config_path = home / "config.toml"
    native = native_linker(repository, root)
    config_path.write_text('[source.crates-io]\nreplace-with="legion-fixed-vendor"\n[source.legion-fixed-vendor]\ndirectory=' + json.dumps(str(vendor)) + '\n[target.aarch64-apple-darwin]\nlinker=' + json.dumps(native['tools']['clang']['path']) + '\nrustflags=' + json.dumps(['-C', 'link-arg=-fuse-ld=' + native['tools']['ld']['path'], '-C', 'link-arg=-isysroot', '-C', 'link-arg=' + native['sdkRoot'], '-C', 'link-arg=-Wl,-Z', '-C', 'link-arg=-L' + str(Path(native['sdkRoot']) / 'usr/lib'), '-C', 'link-arg=-F' + str(Path(native['sdkRoot']) / 'System/Library/Frameworks'), '-C', 'link-arg=-L' + str(Path(native['resourceRoot']) / 'lib/darwin')], separators=(',', ':')) + '\n')
    database = root / "database"
    advisory = inputs["advisory"]
    original = (repository / advisory["path"]).read_bytes()
    if hashlib.sha256(original).hexdigest() != advisory["sha256"]:
        raise ValueError("unchanged checked-in official advisory pin mismatch")
    output = database / advisory["databasePath"]
    output.parent.mkdir(parents=True)
    output.write_bytes(original)
    # Database::open with --no-fetch needs no Git metadata. No freshness is manufactured.
    enrollment = {
        "schema": "legion-rust-code-fixture-enrollment/1",
        "scope": inputs["scope"],
        "productionQualification": False,
        "inputsDigest": digest(inputs_bytes),
        "archives": retained_archives,
        "nativeLinker": native,
        "vendor": {"root": str(vendor), "files": tree(vendor)},
        "cargoHome": {"root": str(home), "configPath": str(config_path), "configDigest": digest(config_path.read_bytes())},
        "database": {"root": str(database), "files": tree(database), "advisory": advisory},
    }
    enrollment_path = root / "enrollment.json"
    enrollment_path.write_text(json.dumps(enrollment, sort_keys=True, indent=2) + "\n")
    exports = {"CARGO_HOME": str(home), "LEGION_RUST_CODE_ENROLLMENT_JSON": str(enrollment_path), "SDKROOT": native["sdkRoot"]}
    export_path = root / "environment.json"
    export_path.write_text(json.dumps(exports, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"schema": "legion-rust-code-fixture-provisioned/1", "enrollment": str(enrollment_path), "digest": digest(enrollment_path.read_bytes()), "environment": str(export_path)}, sort_keys=True))


if __name__ == "__main__":
    main()
