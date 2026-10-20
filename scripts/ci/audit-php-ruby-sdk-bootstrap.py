#!/usr/bin/env python3
"""Managed macOS arm64 CI provisioning from fixed official PHP/Ruby inputs.

Never installs a runtime, resolves dependencies, enrolls authority or qualifies a
provider. Homebrew runtime identity is observed bytes, not archive provenance.
All package execution & native extension compilation is CI-only & network denied.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import shlex
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

SCHEMA = "legion-php-ruby-sdk-enrollment/1"
SOURCE = "scripts/ci/audit-php-ruby-sdk-bootstrap.py"
LOCK = "scripts/ci/php-ruby-sdk-inputs.json"
CAPTURE = "scripts/ci/provision-python-qualification-tools.py"
REPLAY = "scripts/ci/audit-pip-audit-provider-accuracy.py"
ENV = ("LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON", "LEGION_PHP_RUBY_SDK_PHP",
       "LEGION_PHP_RUBY_SDK_RUBY", "LEGION_PHP_RUBY_SDK_BIN_DIR")
VERSIONS = {"composer":"2.10.3", "phpstan":"2.3.1", "phpunit":"13.4.3"}
RUNTIME_CLAIM = "observed managed Homebrew prefix and native closure; no official runtime archive claim"
SANDBOX = "(version 1)(allow default)(deny network*)"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def regular(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative, "unsafe source path")
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and str(rel) == relative and ".." not in rel.parts, "noncanonical source path")
    path = Path(root)
    for part in rel.parts:
        path /= part
        require(not path.is_symlink(), "source alias forbidden: " + relative)
    require(path.is_file(), "source file absent: " + relative)
    return path


def source_inputs(root):
    lock = parsed(regular(root, LOCK).read_bytes())
    require(lock["schema"] == "legion-php-ruby-sdk-inputs/1", "input schema differs")
    require(lock["target"] == {"platform":"darwin", "machine":"arm64", "minimumMacOS":"15.0",
        "phpFormula":"php@8.4", "minimumPHP":"8.4.1", "rubyFormula":"ruby@3.3", "rubyMinor":"3.3",
        "runtimeIdentity":RUNTIME_CLAIM}, "managed target differs")
    for relative, descriptor in lock["sourceFiles"].items():
        path = regular(root, relative)
        require(path.stat().st_size == descriptor["bytes"] and file_digest(path) == descriptor["digest"], "official source bytes changed: " + relative)
    require({row["name"]:row["version"] for row in lock["phars"]} == VERSIONS, "PHAR versions differ")
    composer = next(row for row in lock["phars"] if row["name"] == "composer")
    require(regular(root, composer["officialPinFile"]).read_text().split()[0] == composer["sha256"], "Composer official checksum differs")
    phpstan = next(row for row in lock["phars"] if row["name"] == "phpstan")
    release = parsed(regular(root, phpstan["officialPinFile"]).read_bytes())
    asset = [row for row in release["assets"] if row["name"] == "phpstan.phar"]
    require(release["tag_name"] == phpstan["version"] and len(asset) == 1 and asset[0]["digest"] == "sha256:" + phpstan["sha256"]
            and asset[0]["browser_download_url"] == phpstan["url"] and asset[0]["size"] == phpstan["size"], "PHPStan official release pin differs")
    phpunit = next(row for row in lock["phars"] if row["name"] == "phpunit")
    provenance = parsed(regular(root, phpunit["officialPinFile"]).read_bytes())
    require(provenance["url"] == phpunit["url"] and provenance["sha256"] == phpunit["sha256"] and provenance["bytes"] == phpunit["size"], "PHPUnit official observed bytes differ")
    package = parsed(regular(root, "scripts/ci/php-ruby-sdk-assets/phpunit-13.4.3-composer.txt").read_bytes())
    require(package["name"] == "phpunit/phpunit" and package["require"]["php"] == ">=8.4.1", "PHPUnit runtime requirement differs")
    release = parsed(regular(root, "scripts/ci/php-ruby-sdk-assets/phpunit-latest.json").read_bytes())
    require(release["tag_name"] == phpunit["version"] and release["html_url"] == "https://github.com/sebastianbergmann/phpunit/releases/tag/13.4.3", "PHPUnit official release identity differs")
    gems = lock["gems"]
    require(len(gems) == 18 and len({row["name"] for row in gems}) == 18, "gem closure differs")
    require(lock["gemRoots"] == {"rubocop":"1.80.2", "bundler":"2.6.9", "rake":"13.2.1", "minitest":"5.25.5"}
            and lock["nativeExtensionGems"] == ["json", "prism", "racc"], "gem roots/native extension boundary differs")
    names = {row["name"]:row["version"] for row in gems}
    require(all(names[name] == version for name, version in lock["gemRoots"].items()), "missing fixed root gem")
    for row in gems:
        metadata_raw = regular(root, row["metadataFile"]).read_bytes()
        metadata = parsed(metadata_raw)
        require(digest(metadata_raw) == "sha256:" + row["metadataSha256"] and metadata["name"] == row["name"]
                and metadata["version"] == row["version"] and metadata["platform"] == row["platform"] == "ruby"
                and metadata["sha"] == row["sha256"] and metadata.get("yanked") is False, "official gem metadata differs")
        require(sorted(metadata["dependencies"]["runtime"], key=lambda dep:dep["name"]) == sorted(row["dependencies"], key=lambda dep:dep["name"]), "runtime gem dependency metadata differs")
        require(all(dep["name"] in names for dep in row["dependencies"]), "gem dependency escapes pinned closure")
    advisory = lock["advisory"]
    raw = regular(root, advisory["file"]).read_bytes()
    provenance = parsed(regular(root, advisory["provenanceFile"]).read_bytes())
    require(digest(raw) == advisory["digest"] == "sha256:20e797fa56d83ba55647bf7616700fade0d35d4bec515d85c88098ed8cce8430"
            and len(raw) == advisory["bytes"] == 1637 and advisory["packages"] == ["symfony/process"]
            and sorted(parsed(raw)["advisories"]) == advisory["packages"], "captured official advisory query changed")
    require(provenance["url"] == advisory["endpoint"] == "https://packagist.org/api/security-advisories/"
            and provenance["method"] == advisory["method"] == "POST"
            and provenance["requestBody"] == advisory["requestBody"] == "packages%5B0%5D=symfony%2Fprocess"
            and provenance["sha256"] == advisory["digest"][7:] and provenance["bytes"] == len(raw)
            and provenance["headers"]["Date"] == "Mon, 19 Oct 2026 22:03:19 GMT"
            and advisory["snapshotAt"] == "2026-10-19T22:03:19Z", "official advisory capture provenance differs")
    descriptors = dict(lock["sourceFiles"])
    for relative in (LOCK, SOURCE, CAPTURE, REPLAY):
        path = regular(root, relative)
        descriptors[relative] = {"digest":file_digest(path), "bytes":path.stat().st_size}
    return lock, dict(sorted(descriptors.items()))


def safe_absolute(value):
    require(isinstance(value, str) and value.startswith("/") and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts and "\n" not in value and "\r" not in value, "unsafe external path")
    return PurePosixPath(value)


def observed_target(value, runtime):
    pending = list(safe_absolute(value).parts[1:])
    current, hops = [], 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            require(current, "runtime alias escaped root")
            current.pop()
            continue
        current.append(part)
        key = "/".join(current)
        if key in runtime["links"]:
            hops += 1
            require(hops <= 40, "observed runtime alias cycle")
            target = runtime["links"][key]
            current.pop()
            if target.startswith("/"):
                current = []
            pending = list(PurePosixPath(target).parts[1:] if target.startswith("/") else PurePosixPath(target).parts) + pending
    return PurePosixPath("/", *current)


def verify_enrollment(repository_root, value, live=False):
    """Pure offline validation by default; live=True only replays bytes, never tools."""
    root = Path(repository_root).resolve()
    lock, inputs = source_inputs(root)
    require(type(live) is bool and value["schema"] == SCHEMA and value["qualificationEligible"] is False
            and value["runtimeIdentity"] == RUNTIME_CLAIM and value["inputs"] == inputs, "enrollment source/claim binding differs")
    private = safe_absolute(value["privateRoot"])
    require(not private.is_relative_to(root), "private external closure entered project")
    gem_root = safe_absolute(value["gemRoot"])
    require(gem_root == private / "gems", "private gem root differs")
    replay = runpy.run_path(str(regular(root, REPLAY)))["runtime_closure"]
    for language in ("php", "ruby"):
        runtime = value["runtime"][language]
        require(runtime["exclusions"] == [], "runtime exclusions forbidden")
        prefix = safe_absolute(value["managedPrefixes"][language])
        formula = "php@8.4" if language == "php" else "ruby@3.3"
        require(prefix.parent == PurePosixPath("/opt/homebrew/Cellar") / formula and str(prefix) in runtime["roots"], "complete managed formula prefix omitted")
        private_roots = [private / "assets", private / "advisory"] if language == "php" else [gem_root]
        require(all(str(path) in runtime["roots"] for path in private_roots), "complete private tool/input directory omitted")
        replay(runtime, live)
        native = value["nativeDiscovery"][language]
        require(native["digest"] == digest(canonical({k:v for k,v in native.items() if k != "digest"}))
                and native["systemExemptions"] == ["/usr/lib", "/System/Library"] and native["images"], "native discovery identity differs")
        require(native["inspector"]["path"] == "/usr/bin/otool" and re.fullmatch(r"sha256:[0-9a-f]{64}", native["inspector"]["digest"]), "native inspector identity absent")
        for image in native["images"]:
            require(safe_absolute(image["path"]).as_posix()[1:] in runtime["files"]
                    and safe_absolute(image["executable"]).as_posix()[1:] in runtime["files"], "native image/executable escaped sealed runtime")
            for dep in image["dependencies"]:
                resolved = safe_absolute(dep["resolved"])
                if dep["systemExempt"]:
                    require(any(resolved.is_relative_to(base) for base in native["systemExemptions"]), "invalid system native exemption")
                else:
                    require(str(resolved)[1:] in runtime["files"], "native dependency omitted from runtime")
    for name in ("php", "ruby", "bundle", "rubocop"):
        tool = value["tools"][name]
        path = safe_absolute(tool["path"])
        language = "php" if name == "php" else "ruby"
        require(not path.is_relative_to(root) and value["runtime"][language]["files"].get(str(path)[1:]) == tool["digest"], "tool outside sealed runtime")
        if name in ("php", "ruby"):
            require(path.is_relative_to(value["managedPrefixes"][name]) and path.name == name, "runtime binary escaped managed formula")
    require(re.fullmatch(r"8\.4\.\d+(?:[-+].*)?", value["tools"]["php"]["version"]) and tuple(map(int, value["tools"]["php"]["version"].split("-")[0].split("+")[0].split("."))) >= (8,4,1), "PHP >=8.4.1 in managed 8.4 line required")
    require(re.fullmatch(r"3\.3\.\d+", value["tools"]["ruby"]["version"]) and value["tools"]["bundle"]["version"] == "2.6.9"
            and value["tools"]["rubocop"]["version"] == "1.80.2", "Ruby tool versions differ")
    php = value["runtimeObservation"]["php"]
    require(php["version"] == value["tools"]["php"]["version"] and str(observed_target(php["binary"], value["runtime"]["php"])) == value["tools"]["php"]["path"]
            and php["ini"] is False and php["scanned"] is False and {"ctype", "dom", "filter", "json", "libxml", "mbstring", "tokenizer", "xmlwriter", "phar"}.issubset({name.lower() for name in php["modules"]}), "isolated PHP module observation differs")
    ruby = value["runtimeObservation"]["ruby"]
    require(ruby["version"] == value["tools"]["ruby"]["version"]
            and str(observed_target(ruby["prefix"], value["runtime"]["ruby"])) == value["managedPrefixes"]["ruby"]
            and str(observed_target(ruby["executable"], value["runtime"]["ruby"])) == value["tools"]["ruby"]["path"], "managed Ruby executable context differs")
    for row in lock["phars"]:
        asset = value["assets"][row["name"]]
        path = safe_absolute(asset["path"])
        require(path == private / "assets" / row["filename"] and asset["version"] == row["version"]
                and asset["digest"] == "sha256:" + row["sha256"] and value["runtime"]["php"]["files"].get(str(path)[1:]) == asset["digest"], "PHAR outside sealed official closure")
    expected_archives = [{"name":row["name"], "version":row["version"], "path":str(private / "downloads" / row["filename"]),
        "digest":"sha256:" + row["sha256"], "bytes":row["size"]} for row in lock["gems"]]
    require(value["archives"] == expected_archives, "closed official gem archives differ")
    require(value["gemAudit"]["names"] == sorted(row["name"] for row in lock["gems"])
            and value["gemAudit"]["nativeExtensionGems"] == lock["nativeExtensionGems"]
            and value["gemAudit"]["installedDependenciesSatisfied"] is True, "actual gem dependency audit absent")
    advisory = value["advisory"]
    require(advisory == {"path":str(private / "advisory" / Path(lock["advisory"]["file"]).name), "digest":lock["advisory"]["digest"],
        "bytes":1637, "provenanceFile":str(private / "advisory" / Path(lock["advisory"]["provenanceFile"]).name),
        "provenanceDigest":inputs[lock["advisory"]["provenanceFile"]]["digest"], "packages":["symfony/process"], "snapshotAt":"2026-10-19T22:03:19Z"}, "advisory scope/identity differs")
    for key, checksum in (("path","digest"), ("provenanceFile","provenanceDigest")):
        path = safe_absolute(advisory[key])
        require(value["runtime"]["php"]["files"].get(str(path)[1:]) == advisory[checksum], "feed omitted from sealed PHP inputs")
    expected_environment = dict(zip(ENV, (str(private / "enrollment.json"), value["tools"]["php"]["path"], value["tools"]["ruby"]["path"], str(gem_root / "bin"))))
    require(value["environment"] == expected_environment, "exact four-path exports differ")
    if live:
        for row in value["archives"]:
            path = Path(row["path"])
            require(path.is_file() and not path.is_symlink() and path.resolve() == path and path.stat().st_size == row["bytes"] and file_digest(path) == row["digest"], "retained gem archive changed")
    return {"schema":SCHEMA, "runtimeIdentity":RUNTIME_CLAIM, "qualificationEligible":False,
        "runtimeDigests":{name:value["runtime"][name]["digest"] for name in ("php", "ruby")}, "exports":expected_environment}


def download(row, directory):
    name = row["filename"]
    require(re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:gem|phar)", name), "unsafe archive filename")
    url = urllib.parse.urlparse(row["url"])
    allowed = {"composer":"getcomposer.org", "phpstan":"github.com", "phpunit":"phar.phpunit.de"}
    host = allowed.get(row["name"], "rubygems.org")
    require(url.scheme == "https" and url.hostname == host and not url.query and not url.fragment
            and url.username is None and url.password is None and url.port is None, "nonofficial archive URL")
    if host == "rubygems.org":
        require(row["url"] == "https://rubygems.org/downloads/" + name, "noncanonical RubyGem URL")
    require(type(row["size"]) is int and 0 < row["size"] < 64*1024*1024 and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "invalid archive pin/bound")
    path = directory / name
    request = urllib.request.Request(row["url"], headers={"User-Agent":"Legion-CI-official-pinned-inputs/1"})
    with urllib.request.urlopen(request, timeout=120) as response, path.open("xb") as stream:
        final = urllib.parse.urlparse(response.url)
        hosts = {host, "release-assets.githubusercontent.com"} if host == "github.com" else {host}
        require(final.scheme == "https" and final.hostname in hosts and final.username is None and final.password is None, "official archive redirect escaped allowed host")
        total = 0
        while True:
            chunk = response.read(1024*1024)
            if not chunk:
                break
            total += len(chunk)
            require(total <= row["size"], "oversized pinned archive")
            stream.write(chunk)
    require(total == row["size"] and file_digest(path) == "sha256:" + row["sha256"], "official archive digest/length differs: " + name)
    return path


# These two official pinned archives carry exact detached-signature members.
# Outer archive SHA-256 pins them; this records their presence/size only and
# makes no signer-trust or signature-verification claim.
GEM_SIGNATURE_MEMBERS = {
    "minitest-5.25.5.gem": {
        "metadata.gz.sig": 256,
        "data.tar.gz.sig": 256,
        "checksums.yaml.gz.sig": 256,
    },
    "ruby-progressbar-1.13.0.gem": {
        "metadata.gz.sig": 384,
        "data.tar.gz.sig": 384,
        "checksums.yaml.gz.sig": 384,
    },
}
GEM_PAYLOAD_MEMBERS = {"checksums.yaml.gz", "data.tar.gz", "metadata.gz"}


def inspect_gem(path, row):
    # Inspect only pinned bytes. Do not execute gemspecs or extract unknown paths.
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        signature_members = GEM_SIGNATURE_MEMBERS.get(row["filename"], {})
        expected_members = GEM_PAYLOAD_MEMBERS | set(signature_members)
        require({item.name for item in members} == expected_members
                and len(members) == len(expected_members)
                and all(item.isfile() and item.size <= 32*1024*1024 for item in members)
                and all(next(item.size for item in members if item.name == name) == size
                        for name, size in signature_members.items()),
                "unexpected gem archive members")
        compressed_metadata = archive.extractfile("metadata.gz").read()
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_metadata), mode="rb") as stream:
            metadata = stream.read(32*1024*1024 + 1)
        require(len(metadata) <= 32*1024*1024, "expanded gem metadata exceeds bound")
        require(digest(metadata) == "sha256:" + row["gemMetadataSha256"], "actual gem metadata member differs")
        data = archive.extractfile("data.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == row["fileCount"] and len({item.name for item in members}) == len(members), "gem data file closure differs")
        require(sum(item.size for item in members) <= 64*1024*1024, "expanded gem bound exceeded")
        for item in members:
            relative = PurePosixPath(item.name)
            require(item.isfile() and not relative.is_absolute() and ".." not in relative.parts and str(relative) == item.name
                    and "\\" not in item.name, "unsafe gem data entry")


def retain_failure(label, record, stdout, stderr):
    # Keep bounded original process bytes under CI's existing uploaded QA root.
    failure = Path(os.environ["RUNNER_TEMP"]) / "legion-provider-qualification/provisioning-failures/php-ruby" / label
    failure.mkdir(parents=True, exist_ok=True)
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        retained = data[:65536]
        path = failure / (stream + ".bin")
        path.write_bytes(retained)
        record[stream] = {"bytes": len(data), "digest": digest(data), "retainedBytes": len(retained),
            "retainedDigest": digest(retained), "truncated": len(retained) != len(data), "path": str(path)}
    evidence = failure / "process.json"
    evidence.write_bytes(canonical(record) + b"\n")
    print("PHP_RUBY_BOOTSTRAP_FAILURE " + canonical({"label": label, "exitCode": record["exitCode"],
        "stderrPreview": stderr[:16384].decode("utf-8", "replace"),
        "retainedProcess": str(evidence)}).decode(), file=sys.stderr)


def run_offline(arguments, environment, cwd, logs, label, timeout=600, return_result=False):
    sandbox = Path("/usr/bin/sandbox-exec")
    require(sandbox.is_file() and not sandbox.is_symlink(), "managed macOS sandbox unavailable")
    require(re.fullmatch(r"[a-z0-9-]+", label), "unsafe provisioning log label")
    result = subprocess.run([str(sandbox), "-p", SANDBOX, *map(str, arguments)], env=environment, cwd=cwd,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    (logs / (label + ".stdout")).write_bytes(result.stdout)
    (logs / (label + ".stderr")).write_bytes(result.stderr)
    if result.returncode != 0:
        retain_failure(label, {"argv": list(map(str, arguments)), "cwd": str(cwd), "exitCode": result.returncode},
            result.stdout, result.stderr)
    require(result.returncode == 0, "offline provisioning command failed: " + label)
    return result if return_result else result.stdout


def link_closed_roots(api, initial):
    """Seal parent aliases & all data-link targets before Mach-O discovery."""
    roots, links, seen = set(), {}, set()
    queue = list(map(Path, initial))
    approved = [api["resolve_link_chain"](path, links) for path in queue]
    visited = 0
    while queue:
        raw = queue.pop(0)
        path = api["resolve_link_chain"](raw, links)
        require(path.is_absolute() and path not in (Path("/"), Path("/opt"), Path("/opt/homebrew"), Path("/opt/homebrew/lib"), Path("/opt/homebrew/share")), "overbroad runtime link target")
        require(any(path.is_relative_to(base) for base in [Path("/opt/homebrew"), Path("/usr/lib"), Path("/System/Library"), *approved]), "runtime data symlink escaped managed/private closure")
        roots.add(str(path))
        if path in seen:
            continue
        seen.add(path)
        require(len(roots) <= 1024, "runtime link closure bound exceeded")
        pending = [path]
        while pending:
            node = pending.pop()
            visited += 1
            require(visited <= 250000, "runtime file traversal bound exceeded")
            mode = node.lstat().st_mode
            if stat.S_ISLNK(mode):
                queue.append(node)
            elif stat.S_ISDIR(mode):
                pending.extend(sorted(node.iterdir()))
            else:
                require(stat.S_ISREG(mode), "unsupported runtime entry")
    return sorted(roots), links


def capture_runtime(api, roots, executable):
    roots, initial_links = link_closed_roots(api, roots)
    bound, aliases, absent, native = api["native_dependency_closure"](roots, [], Path(executable))
    for name, target in initial_links.items():
        require(name not in aliases or aliases[name] == target, "runtime alias changed during native discovery")
        aliases[name] = target
    runtime = api["snapshot"](bound, [], aliases, absent)
    return runtime, native


GEM_AUDIT = r'''require 'rubygems/package'; require 'json'
rows=JSON.parse(File.binread(ARGV.fetch(0))); root=ARGV.fetch(1); mode=ARGV.fetch(2)
Gem.use_paths(root,[root]); Gem::Specification.reset
pins=rows.to_h{|r| [r.fetch('name'),r]}; native=[]
rows.each do |r|
  s= mode=='archive' ? Gem::Package.new(File.join(ARGV.fetch(3),r.fetch('filename'))).spec : Gem::Specification.load(File.join(root,'specifications',"#{r.fetch('name')}-#{r.fetch('version')}.gemspec"))
  raise 'gem identity differs' unless s && s.name==r.fetch('name') && s.version.to_s==r.fetch('version') && s.platform.to_s=='ruby'
  raise 'Ruby version incompatible' unless s.required_ruby_version.satisfied_by?(Gem::Version.new(RUBY_VERSION))
  declared=r.fetch('dependencies').to_h{|d| [d.fetch('name'),Gem::Requirement.new(*d.fetch('requirements').split(/,\s*/))]}
  actual=s.runtime_dependencies.to_h{|d| [d.name,d.requirement]}
  raise 'actual dependency metadata differs' unless declared==actual && s.runtime_dependencies.length==actual.length
  actual.each{|name,req| raise 'dependency not closed/satisfied' unless pins.key?(name) && req.satisfied_by?(Gem::Version.new(pins.fetch(name).fetch('version')))}
  native << s.name unless s.extensions.empty?
end
expected=rows.map{|r| "#{r.fetch('name')}-#{r.fetch('version')}.gemspec"}.sort
raise 'installed spec closure differs' if mode=='installed' && Dir.children(File.join(root,'specifications')).sort!=expected
puts JSON.generate({'names'=>pins.keys.sort,'nativeExtensionGems'=>native.sort,'installedDependenciesSatisfied'=>mode=='installed'})
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--exports-file", type=Path)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "macOS"
            and sys.platform == "darwin" and platform.machine() == "arm64" and int(platform.mac_ver()[0].split(".")[0]) >= 15,
            "provisioning requires managed macOS >=15 arm64 CI")
    repository = args.repository_root.resolve(strict=True)
    require(Path(__file__).resolve(strict=True) == repository / SOURCE, "provisioner must come from supplied checkout")
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    out = args.output_root.absolute()
    safe_absolute(str(out))
    require(out == out.resolve() and out.is_relative_to(temporary) and out != temporary and not out.is_relative_to(repository)
            and not out.exists(), "fresh canonical private RUNNER_TEMP child required")
    exports = args.exports_file.absolute() if args.exports_file else out / "exports.sh"
    require(exports == exports.resolve() and exports.parent == out and not exports.exists(), "exports must be fresh private output file")
    lock, inputs = source_inputs(repository)
    out.mkdir(parents=True, mode=0o700)
    for name in ("assets", "advisory", "downloads", "gems", "home", "tmp", "logs"):
        (out / name).mkdir(mode=0o700)
    (out / "gems/bin").mkdir(mode=0o700)
    logs = out / "logs"
    env = {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "HOME":str(out / "home"), "TMPDIR":str(out / "tmp"),
        "LANG":"en_US.UTF-8", "HOMEBREW_NO_AUTO_UPDATE":"1", "HOMEBREW_NO_ANALYTICS":"1", "HOMEBREW_NO_ENV_HINTS":"1",
        "GEM_HOME":str(out / "gems"), "GEM_PATH":str(out / "gems"), "GEM_SPEC_CACHE":str(out / "tmp/gem-spec-cache"),
        "RUBYOPT":"", "RUBYLIB":"", "BUNDLE_USER_HOME":str(out / "tmp/bundle"), "BUNDLE_DISABLE_VERSION_CHECK":"true"}
    brew = Path("/opt/homebrew/bin/brew")
    require(brew.is_file(), "existing managed arm64 Homebrew required; no runtime installation fallback")
    api = runpy.run_path(str(regular(repository, CAPTURE)))
    aliases, prefixes, tools = {}, {}, {}
    for language, formula in (("php","php@8.4"), ("ruby","ruby@3.3")):
        raw = run_offline([brew,"--prefix",formula], env, out, logs, language + "-managed-prefix", timeout=60).decode().strip()
        require(raw == "/opt/homebrew/opt/" + formula, "unexpected managed runtime formula prefix")
        prefix = api["resolve_link_chain"](Path(raw), aliases)
        require(prefix.is_dir() and prefix.is_relative_to("/opt/homebrew/Cellar/" + formula), "managed runtime prefix missing/crossed formula")
        prefixes[language] = str(prefix)
        tools[language] = {"path":str(api["resolve_link_chain"](Path(raw) / "bin" / language, aliases))}
    baseline = {language:capture_runtime(api, [prefixes[language], "/opt/homebrew/opt/" + ("php@8.4" if language == "php" else "ruby@3.3")], tools[language]["path"])[0] for language in ("php", "ruby")}
    php_probe = "echo json_encode(['version'=>PHP_VERSION,'binary'=>PHP_BINARY,'modules'=>get_loaded_extensions(),'ini'=>php_ini_loaded_file(),'scanned'=>php_ini_scanned_files()],JSON_THROW_ON_ERROR);"
    php = parsed(run_offline([tools["php"]["path"],"-n","-r",php_probe], env, out, logs, "php-isolated-runtime"))
    require(php["ini"] is False and php["scanned"] is False and Path(php["binary"]).resolve() == Path(tools["php"]["path"]), "PHP ini/executable context escaped isolation")
    required_modules = {"ctype", "dom", "filter", "json", "libxml", "mbstring", "tokenizer", "xmlwriter", "phar"}
    require(required_modules.issubset({name.lower() for name in php["modules"]}), "PHP -n lacks mandatory PHAR/test modules; no php.ini fallback")
    tools["php"].update(version=php["version"], digest=file_digest(tools["php"]["path"]))
    ruby_probe = "puts RUBY_VERSION; puts RbConfig::CONFIG.fetch('prefix'); puts RbConfig.ruby"
    ruby = run_offline([tools["ruby"]["path"],"--disable-gems","-rrbconfig","-e",ruby_probe], env, out, logs, "ruby-isolated-runtime").decode().splitlines()
    require(len(ruby) == 3 and Path(ruby[1]).resolve() == Path(prefixes["ruby"]) and Path(ruby[2]).resolve() == Path(tools["ruby"]["path"]), "Ruby prefix/executable context differs")
    tools["ruby"].update(version=ruby[0], digest=file_digest(tools["ruby"]["path"]))
    require(re.fullmatch(r"8\.4\.\d+", php["version"]) and tuple(map(int, php["version"].split("."))) >= (8,4,1)
            and re.fullmatch(r"3\.3\.\d+", ruby[0]), "existing managed PHP>=8.4.1/Ruby3.3 required")
    assets = {}
    for row in lock["phars"]:
        path = download(row, out / "assets")
        assets[row["name"]] = {"path":str(path), "digest":file_digest(path), "version":row["version"]}
    for row in lock["gems"]:
        path = download(row, out / "downloads")
        inspect_gem(path, row)
    # No dependency resolver/index is consulted. Real RubyGems compiles only the
    # three declared native extension gems inside this private CI destination.
    gem_rows = out / "gem-inputs.json"
    gem_rows.write_bytes(canonical(lock["gems"]))
    audit_args = [tools["ruby"]["path"],"-e",GEM_AUDIT,str(gem_rows),str(out / "gems")]
    before_audit = parsed(run_offline([*audit_args,"archive",str(out / "downloads")], env, out, logs, "gem-archive-dependency-audit"))
    require(before_audit["nativeExtensionGems"] == lock["nativeExtensionGems"], "unexpected native extension package")
    env["PATH"] = str(Path(tools["ruby"]["path"]).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin"
    gem_program = Path(prefixes["ruby"]) / "bin/gem"
    require(gem_program.is_file(), "managed RubyGems entry absent")
    run_offline([tools["ruby"]["path"],gem_program,"install","--local","--ignore-dependencies","--no-document",
        "--install-dir",out / "gems","--bindir",out / "gems/bin", *[out / "downloads" / row["filename"] for row in lock["gems"]]], env, out, logs, "gem-offline-install", timeout=1200)
    gem_audit = parsed(run_offline([*audit_args,"installed",str(out / "downloads")], env, out, logs, "gem-installed-dependency-audit"))
    require(gem_audit["installedDependenciesSatisfied"] is True and gem_audit["nativeExtensionGems"] == lock["nativeExtensionGems"], "installed native/dependency closure differs")
    for name, version in (("bundle","2.6.9"), ("rubocop","1.80.2")):
        launcher = out / "gems/bin" / name
        require(launcher.is_file() and not launcher.is_symlink(), "real installed launcher absent")
        arguments = [tools["ruby"]["path"], launcher, "--version"]
        result = run_offline(arguments, env, out, logs, name + "-version", return_result=True)
        output = result.stdout.decode("utf-8", "replace").strip()
        expected = "Bundler version " + version if name == "bundle" else version
        if output != expected:
            retain_failure(name + "-version", {"executable": str(arguments[0]), "argv": list(map(str, arguments)),
                "cwd": str(out), "exitCode": result.returncode, "failure": "launcher-version-mismatch",
                "expectedVersion": expected, "observedVersionPreview": output[:4096],
                "observedVersionPreviewTruncated": len(output) > 4096},
                result.stdout, result.stderr)
            require(False, "installed launcher version differs")
        tools[name] = {"path":str(launcher), "digest":file_digest(launcher), "version":version}
    for name, row in assets.items():
        output = run_offline([tools["php"]["path"],"-n",row["path"],"--version"], env, out, logs, name + "-version").decode()
        require(re.search(r"(?<![0-9.])" + re.escape(row["version"]) + r"(?![0-9.])", output), "actual PHAR version differs")
    for key in ("file", "provenanceFile"):
        source = regular(repository, lock["advisory"][key])
        (out / "advisory" / source.name).write_bytes(source.read_bytes())
    for language in ("php", "ruby"):
        expected = baseline[language]
        require(api["snapshot"](expected["roots"], [], expected["links"], expected["absent"]) == expected, "managed runtime changed during provisioning")
    runtimes, discovery = {}, {}
    for language, roots in (("php", [prefixes["php"],str(out / "assets"),str(out / "advisory"),"/opt/homebrew/opt/php@8.4"]),
                            ("ruby", [prefixes["ruby"],str(out / "gems"),"/opt/homebrew/opt/ruby@3.3"])):
        runtimes[language], discovery[language] = capture_runtime(api, roots, tools[language]["path"])
    environment = dict(zip(ENV, (str(out / "enrollment.json"),tools["php"]["path"],tools["ruby"]["path"],str(out / "gems/bin"))))
    advisory = {"path":str(out / "advisory" / Path(lock["advisory"]["file"]).name), "digest":lock["advisory"]["digest"], "bytes":1637,
        "provenanceFile":str(out / "advisory" / Path(lock["advisory"]["provenanceFile"]).name), "provenanceDigest":inputs[lock["advisory"]["provenanceFile"]]["digest"],
        "packages":["symfony/process"], "snapshotAt":"2026-10-19T22:03:19Z"}
    value = {"schema":SCHEMA, "qualificationEligible":False, "runtimeIdentity":RUNTIME_CLAIM, "privateRoot":str(out), "managedPrefixes":prefixes,
        "gemRoot":str(out / "gems"), "tools":tools, "assets":assets, "advisory":advisory, "runtime":runtimes,
        "nativeDiscovery":discovery, "environment":environment, "inputs":inputs, "gemAudit":gem_audit,
        "archives":[{"name":row["name"],"version":row["version"],"path":str(out / "downloads" / row["filename"]),"digest":"sha256:" + row["sha256"],"bytes":row["size"]} for row in lock["gems"]],
        "runtimeObservation":{"php":php,"ruby":{"version":ruby[0],"prefix":ruby[1],"executable":ruby[2]}},
        "provisioningExecution":{"network":"denied for every runtime/package command", "sandboxProfile":SANDBOX,
            "nativeBuilds":"CI-only real RubyGems json/prism/racc extensions; no local or official binary archive claim",
            "logs":{path.name:{"digest":file_digest(path),"bytes":path.stat().st_size} for path in sorted(logs.iterdir())}}}
    verify_enrollment(repository, value, live=True)
    output = out / "enrollment.json"
    output.write_bytes(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode() + b"\n")
    exports.write_text("".join("export " + name + "=" + shlex.quote(path) + "\n" for name, path in environment.items()))
    verify_enrollment(repository, value, live=True)
    print("PHP_RUBY_SDK_ENROLLMENT " + canonical({"path":str(output),"digest":file_digest(output),"exportsFile":str(exports),"environment":environment,"qualificationEligible":False}).decode())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print("php-ruby-sdk-provisioning-failed: " + str(error), file=sys.stderr)
        sys.exit(1)
