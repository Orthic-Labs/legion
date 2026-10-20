#!/usr/bin/env python3
"""External CI provisioning, separate from every sandboxed project execution.

Downloads one official SDK archive, verifies published SHA512, then populates
an isolated NuGet cache & freezes all resolved inputs before qualification.
Never invoke this from native provider execution. All output requires scratch.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request
import zipfile

SDK = "8.0.426"
RUNTIME = "8.0.32"
METADATA = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"
SDK_URL = "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.426/dotnet-sdk-8.0.426-osx-arm64.tar.gz"
SDK_SHA512 = "17cd408c92eb6ceedc06d41fa726c783b9be020c6ae5f3624ad3a0b2c26a78aa7d09f38338003163a72bb14d437731debf533c0451a5c6a05de3b1e37a3aa50a"
PACKAGES = {"Microsoft.NET.Test.Sdk": "17.11.1", "MSTest.TestAdapter": "3.6.4", "MSTest.TestFramework": "3.6.4"}
FSHARP_VERSION = "0.27.0"
FSHARP_HASH = "9TDJCUYrime4mR6ypEN6N95JnBqq3ieFawUQawxkev/+7UaXSk1namitl/cxfFWtYsiiUoSDNf9hO0WKBpnCCw=="
FSHARP_CATALOG = "https://api.nuget.org/v3/catalog0/data/2026.06.05.06.37.41/dotnet-fsharplint.0.27.0.json"
FSHARP_COMMIT = "43c8586c82eb2309b5cb9fee1b32d59e899f07e5"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def tree(root):
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("symlink/special enrollment input: " + str(path))
        if path.is_file():
            files[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return files


def fetch(url, destination):
    with urllib.request.urlopen(url, timeout=120) as response, destination.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    return destination.read_bytes()


def package_provenance(lock, name, row, packages, failure_root):
    version = row["resolved"].lower()
    identity = name.lower() + "/" + version
    cache = packages / name.lower() / version
    filename = name.lower() + "." + version + ".nupkg"
    originals = {"packages.lock.json": lock.read_bytes()}
    errors = {}
    for filename_part in (filename, filename + ".sha512", ".nupkg.metadata"):
        try:
            originals[filename_part] = (cache / filename_part).read_bytes()
        except OSError as error:
            errors[filename_part] = str(error)
    archive_hash = (base64.b64encode(hashlib.sha512(originals[filename]).digest()).decode()
                    if filename in originals else None)
    cache_hash = content_hash = None
    try:
        cache_hash = originals.get(filename + ".sha512", b"").decode("utf-8").strip()
    except UnicodeError as error:
        errors[filename + ".sha512"] = str(error)
    try:
        metadata = json.loads(originals.get(".nupkg.metadata", b""))
        if not isinstance(metadata, dict):
            raise ValueError("NuGet metadata must be an object")
        content_hash = metadata.get("contentHash")
    except (ValueError, UnicodeError) as error:
        errors.setdefault(".nupkg.metadata", str(error))
    expected = row.get("contentHash")
    # NuGet.Client c754078, PackageExtractor.cs:434-445: signed archive hash
    # goes to .sha512; unsigned content hash goes to .nupkg.metadata & locks.
    archive_matches = archive_hash is not None and cache_hash == archive_hash
    lock_matches = isinstance(expected, str) and bool(expected) and content_hash == expected
    if errors or not archive_matches or not lock_matches:
        failure_root.mkdir(parents=True, exist_ok=False)
        for original_name, data in originals.items():
            (failure_root / original_name).write_bytes(data)
        comparison = {"schema": "legion-dotnet-provisioning-failure/1", "id": name,
                      "version": version, "lockPath": str(lock), "cachePath": str(cache),
                      "lockContentHash": expected, "metadataContentHash": content_hash,
                      "archiveSha512": archive_hash, "cacheArchiveSha512": cache_hash,
                      "archiveMatchesSidecar": archive_matches, "metadataMatchesLock": lock_matches,
                      "inputErrors": errors}
        (failure_root / "comparison.json").write_bytes(canonical(comparison))
        raise ValueError("expanded NuGet input hash mismatch for " + identity + "; retained " + str(failure_root))
    return {"id": name, "version": version, "contentHash": content_hash,
            "archiveSha512": archive_hash,
            "url": "https://api.nuget.org/v3-flatcontainer/" + identity + "/" + filename}


def project(extension):
    references = "".join(f'<PackageReference Include="{name}" Version="{version}" />' for name, version in PACKAGES.items())
    compile_items = '<Compile Include="Answer.fs" /><Compile Include="Tests.fs" />' if extension == "fsproj" else ""
    return '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><IsTestProject>true</IsTestProject><IsPackable>false</IsPackable><GenerateProgramFile>false</GenerateProgramFile><EnableNETAnalyzers>true</EnableNETAnalyzers><AnalysisLevel>8.0</AnalysisLevel></PropertyGroup><ItemGroup>' + references + compile_items + '</ItemGroup></Project>\n'


SOURCES = {
    "csharp": ("csproj", "cs", "public class Answer { public int Double(int value) { return value * 2; } }\n", "using Microsoft.VisualStudio.TestTools.UnitTesting;\n[TestClass] public class AnswerTests { [TestMethod] public void Doubles() { Assert.AreEqual(4, new Answer().Double(2)); } }\n"),
    "visualBasic": ("vbproj", "vb", "Public Class Answer\n Public Function DoubleValue(value As Integer) As Integer\n  Return value * 2\n End Function\nEnd Class\n", "Imports Microsoft.VisualStudio.TestTools.UnitTesting\n<TestClass> Public Class AnswerTests\n <TestMethod> Public Sub Doubles()\n  Assert.AreEqual(4, New Answer().DoubleValue(2))\n End Sub\nEnd Class\n"),
    "fsharp": ("fsproj", "fs", "namespace Fixture\ntype Answer() =\n member _.Double(value: int) = value * 2\n", "namespace Fixture\nopen Microsoft.VisualStudio.TestTools.UnitTesting\n[<TestClass>]\ntype AnswerTests() =\n [<TestMethod>]\n member _.Doubles() = Assert.AreEqual(4, Answer().Double(2))\n"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.absolute()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("this pinned enrollment supports native macOS arm64 only")
    ci_scratch = os.environ.get("RUNNER_TEMP") if os.environ.get("GITHUB_ACTIONS") == "true" else None
    allowed = [Path("/Volumes/D/scratch")] + ([Path(ci_scratch).resolve(strict=True)] if ci_scratch else [])
    if not any(root.resolve().is_relative_to(path) for path in allowed):
        raise ValueError("provisioning output must remain under approved scratch or CI RUNNER_TEMP")
    root.mkdir(parents=True, exist_ok=False)
    root = root.resolve(strict=True)
    metadata_bytes = fetch(METADATA, root / "releases.json")
    metadata = json.loads(metadata_bytes)
    official = [file for release in metadata["releases"] for sdk in release.get("sdks", [release.get("sdk", {})]) if sdk.get("version") == SDK for file in sdk.get("files", []) if file.get("url") == SDK_URL]
    if not official or any(row["hash"] != SDK_SHA512 for row in official):
        raise ValueError("pinned SDK does not match fetched official release metadata")
    if not any(release.get("runtime", {}).get("version") == RUNTIME and any(sdk.get("version") == SDK for sdk in release.get("sdks", [release.get("sdk", {})])) for release in metadata["releases"]):
        raise ValueError("pinned SDK/runtime pairing differs from official release metadata")
    archive = root / "sdk.tar.gz"
    archive_bytes = fetch(SDK_URL, archive)
    if hashlib.sha512(archive_bytes).hexdigest() != SDK_SHA512:
        raise ValueError("official SDK archive SHA512 mismatch")
    sdk = root / "sdk"
    sdk.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError("SDK archive contains unsupported link/special entry")
            target = sdk / member.name
            if target.is_absolute() and not target.resolve().is_relative_to(sdk):
                raise ValueError("SDK archive traversal")
        source.extractall(sdk, filter="data")
    packages = root / "packages"
    packages.mkdir()
    config = root / "provision.NuGet.Config"
    config.write_text('<configuration><packageSources><clear /><add key="official" value="https://api.nuget.org/v3/index.json" /></packageSources><fallbackPackageFolders><clear /></fallbackPackageFolders></configuration>\n')
    environment = {"PATH": str(sdk), "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"), "DOTNET_ROOT": str(sdk), "DOTNET_CLI_HOME": str(root / "home"), "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true", "MSBuildEnableWorkloadResolver": "false", "NUGET_PACKAGES": str(packages)}
    for name in ("home", "tmp"):
        (root / name).mkdir()
    seeds = root / "fixtures"
    seeds.mkdir()
    global_json = canonical({"sdk": {"version": SDK, "rollForward": "disable", "allowPrerelease": False}})
    (seeds / "global.json").write_bytes(global_json)
    (seeds / ".editorconfig").write_text("root = true\n\n[*.{cs,vb}]\ndotnet_analyzer_diagnostic.severity = none\ndotnet_diagnostic.CA1822.severity = warning\ndotnet_code_quality.CA1822.api_surface = all\n\n[Tests.{cs,vb}]\ndotnet_diagnostic.CA1822.severity = none\n")
    catalog_bytes = fetch(FSHARP_CATALOG, root / "fsharplint.catalog.json")
    catalog = json.loads(catalog_bytes)
    if catalog["packageHashAlgorithm"] != "SHA512" or catalog["packageHash"] != FSHARP_HASH or catalog["repository"]["commit"] != FSHARP_COMMIT:
        raise ValueError("FSharpLint official catalog pin mismatch")
    fsharp_archive = root / "fsharplint.nupkg"
    fsharp_url = "https://api.nuget.org/v3-flatcontainer/dotnet-fsharplint/0.27.0/dotnet-fsharplint.0.27.0.nupkg"
    if base64.b64encode(hashlib.sha512(fetch(fsharp_url, fsharp_archive)).digest()).decode() != FSHARP_HASH:
        raise ValueError("FSharpLint published package hash mismatch")
    fsharp_root = root / "fsharplint"
    fsharp_root.mkdir()
    with zipfile.ZipFile(fsharp_archive) as archive_zip:
        for item in archive_zip.infolist():
            target = fsharp_root / item.filename
            if not target.resolve().is_relative_to(fsharp_root) or "\\" in item.filename or ((item.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError("FSharpLint archive unsafe path/type")
        archive_zip.extractall(fsharp_root)
    defaults = json.loads((fsharp_root / "tools/net8.0/any/fsharplint.json").read_text())
    def disable_rules(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "enabled":
                    value[key] = False
                else:
                    disable_rules(child)
        elif isinstance(value, list):
            for child in value:
                disable_rules(child)
    disable_rules(defaults)
    defaults["redundantNewKeyword"]["enabled"] = True
    (seeds / "fsharplint.json").write_bytes(canonical(defaults))
    # Fetch exact top-level official version indexes before resolution; retain bytes.
    for name, version in PACKAGES.items():
        index = root / (name.lower() + ".versions.json")
        if version not in json.loads(fetch("https://api.nuget.org/v3-flatcontainer/" + name.lower() + "/index.json", index))["versions"]:
            raise ValueError("pinned official package version is unavailable")
    for language, (extension, source_extension, answer, tests) in SOURCES.items():
        directory = seeds / language
        directory.mkdir()
        (directory / ("Fixture." + extension)).write_text(project(extension))
        (directory / ("Answer." + source_extension)).write_text(answer)
        (directory / ("Tests." + source_extension)).write_text(tests)
        # This is provisioning with explicit network permission, before any audit plan.
        result = subprocess.run([str(sdk / "dotnet"), "restore", str(directory / ("Fixture." + extension)), "--use-lock-file", "--configfile", str(config), "--packages", str(packages), "--artifacts-path", str(root / "provision-artifacts"), "--disable-parallel", "-p:NuGetAudit=false", "-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false"], cwd=seeds, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        (root / (language + ".restore.stdout")).write_bytes(result.stdout)
        (root / (language + ".restore.stderr")).write_bytes(result.stderr)
        if result.returncode:
            raise ValueError("external package provisioning failed for " + language)
    provenance = {}
    # CI exports the child output only after provisioning; derive its uploaded
    # location here too, so first failing original inputs survive provisioning.
    failure_root = Path(os.environ.get("LEGION_DOTNET_CHILD_OUTPUT") or
                        (str(Path(ci_scratch) / "legion-provider-qualification/code-dotnet-sdk")
                         if ci_scratch else str(root / "code-dotnet-sdk"))) / "provisioning-failure"
    if not any(failure_root.resolve().is_relative_to(path) for path in allowed):
        raise ValueError("provisioning failure evidence must remain under approved scratch or CI RUNNER_TEMP")
    for lock in seeds.rglob("packages.lock.json"):
        for dependencies in json.loads(lock.read_text())["dependencies"].values():
            for name, row in dependencies.items():
                if row["type"] not in ("Direct", "Transitive"):
                    raise ValueError("unexpected package lock dependency type")
                package = package_provenance(lock, name, row, packages, failure_root)
                provenance[name.lower() + "/" + package["version"]] = package
    sdk_files, package_files = tree(sdk), tree(packages)
    enrollment = {"schema": "legion-dotnet-sdk-enrollment/1", "sdkVersion": SDK, "runtimeVersion": RUNTIME, "sdkRoot": str(sdk), "sdkDigest": digest(canonical(sdk_files)), "sdkFiles": sdk_files, "packagesRoot": str(packages), "packagesDigest": digest(canonical(package_files)), "packageFiles": package_files, "sdkProvenance": {"metadataUrl": METADATA, "metadataDigest": digest(metadata_bytes), "archiveUrl": SDK_URL, "archiveSha512": SDK_SHA512, "version": SDK, "rid": "osx-arm64"}, "packageProvenance": sorted(provenance.values(), key=lambda row: row["id"].lower()), "fixturesRoot": str(seeds), "fixtureFiles": tree(seeds)}
    enrollment["fsharpAnalyzer"] = {"id": "dotnet-fsharplint", "version": FSHARP_VERSION, "root": str(fsharp_root), "digest": digest(canonical(tree(fsharp_root))), "files": tree(fsharp_root), "entrypoint": "tools/net8.0/any/dotnet-fsharplint.dll", "catalogUrl": FSHARP_CATALOG, "catalogDigest": digest(catalog_bytes), "archiveUrl": fsharp_url, "archiveSha512": FSHARP_HASH, "sourceCommit": FSHARP_COMMIT, "knownRule": "FL0014"}
    output = root / "enrollment.json"
    output.write_bytes(canonical(enrollment))
    print(json.dumps({"enrollment": str(output), "digest": digest(output.read_bytes()), "fixtureRoot": str(seeds), "productionAdmission": False}))


if __name__ == "__main__":
    main()
