#!/usr/bin/env python3
"""CI-only native harness for the shipped fixed-path installer transaction.

Compiles production & development modes of LegionInstaller.swift with exactly two
fixture substitutions: resource directory & home directory. Transaction,
validation, entry point & Process execution remain unchanged; only fixture
payload executables simulate setup.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


SOURCE = Path(__file__).with_name("LegionInstaller.swift")
RELATIVE_ROOT = Path("Library/Application Support/Orthic Labs/Legion")
DISABLED = '[plugins."legion@legion-installed"]\nenabled = false\n'
UNRELATED = 'model = "fixture-model"\n'
STUB = r'''#!__PYTHON__
import json
import os
from pathlib import Path
import shutil
import stat
import sys

binary = Path(__file__)
root = binary.parent.parent
generation = (root / "generation.txt").read_text()
step = " ".join(sys.argv[1:])
with open(os.environ["LEGION_FIXTURE_LOG"], "a") as log:
    log.write(json.dumps({"binary": str(binary), "real": str(binary.resolve()),
                          "generation": generation, "step": step}) + "\n")
if generation == "candidate" and step == "setup repair --confirm":
    if os.environ.get("LEGION_FIXTURE_MIGRATE_HOST") == "1":
        home = Path(os.environ["LEGION_INSTALL_FIXTURE_HOME"])
        shutil.rmtree(home / ".codex/plugins/legion")
        (home / "Library/Application Support/Legion/integrations/projections/codex.json").unlink()
        config = home / ".codex/config.toml"
        config.write_text('model = "fixture-model"')
if generation == "candidate" and step == "doctor" and os.environ.get("LEGION_FIXTURE_TAMPER") == "1":
    (root / "generation.txt").write_text("tampered")
if generation == "candidate" and step == "doctor" and os.environ.get("LEGION_FIXTURE_FAIL_HISTORY_CLEANUP") == "1":
    os.chflags(root.parent / "current.previous", stat.UF_IMMUTABLE)
if generation == "candidate" and step == "doctor" and os.environ.get("LEGION_FIXTURE_FAIL_STAGING_CLEANUP") == "1":
    for transaction in root.parent.glob(".install-*"):
        os.chflags(transaction, stat.UF_IMMUTABLE)
if generation == "candidate" and step == os.environ.get("LEGION_FIXTURE_FAIL_STEP"):
    sys.exit(17)
if generation == "candidate" and step == "setup remove --confirm" and os.environ.get("LEGION_FIXTURE_FAIL_CLEANUP") == "1":
    sys.exit(19)
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def payload(path, generation, native=True):
    for directory in ("bin", "plugin/skills/sage", "share/legion"):
        (path / directory).mkdir(parents=True, exist_ok=True)
    for name in ("legion", "legion-hook", "legion-mcp"):
        binary = path / "bin" / name
        binary.write_text(STUB.replace("__PYTHON__", sys.executable))
        binary.chmod(0o755)
    (path / "generation.txt").write_text(generation)
    (path / "plugin/skills/sage/SKILL.md").write_text("prior skill content\n")
    metadata = {"version": "0.3.23"}
    if native:
        metadata["nativeMarketplaces"] = {"name": "legion-installed"}
    (path / "share/legion/release.json").write_text(json.dumps(metadata))


def tree(path):
    result = {}
    for item in [path, *sorted(path.rglob("*"))]:
        relative = str(item.relative_to(path))
        mode = item.lstat().st_mode & 0o7777
        if item.is_symlink():
            result[relative] = ("link", os.readlink(item), mode)
        elif item.is_dir():
            result[relative] = ("directory", mode)
        else:
            result[relative] = ("file", hashlib.sha256(item.read_bytes()).hexdigest(), mode)
    return result


def host_projection(home, root):
    codex = home / ".codex"
    target = codex / "plugins/legion"
    (target / "skills").mkdir(parents=True)
    (target / "skills/sage").symlink_to(root / "current/plugin/skills/sage", target_is_directory=True)
    (target / "plugin.json").write_text('{"name":"legion"}\n')
    files = {}
    for relative in ("plugin.json", "skills/sage/SKILL.md"):
        canonical = json.dumps(list((target / relative).read_bytes()), separators=(",", ":"))
        files[relative] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    ledger = home / "Library/Application Support/Legion/integrations/projections/codex.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps({
        "schemaVersion": 1, "owner": "legion-client-projection-v1", "clientId": "codex",
        "projection": "agent-plugins-with-explicit-sidecar", "origin": "installed",
        "createdRoot": True, "installRoot": str(root), "targetRoot": str(target), "files": files,
    }))
    (codex / "config.toml").write_text(UNRELATED + DISABLED)
    return ledger, ledger.read_bytes(), (target / "plugin.json").read_bytes()


def compile_fixture(output):
    source = SOURCE.read_text()
    mode = "LEGION_DEVELOPMENT_INSTALL"
    require(f"#if {mode}" in source, "development mode must be compile-time bound")
    require(all(line.startswith("#if ") for line in source.splitlines() if mode in line),
            "installer must not select development mode from arguments or environment")
    repository = SOURCE.parents[3]
    ci_source = (repository / "scripts/ci/right-git-ci.sh").read_text()
    compile_lines = [line for line in ci_source.splitlines() if "swiftc " in line and "LegionInstaller.swift" in line]
    require(len(compile_lines) == 1 and f"-D {mode}" in compile_lines[0]
            and '"$dev_app/Contents/MacOS/Legion Installer"' in compile_lines[0],
            "only CI development wrapper must select development mode")
    sign_manifest = json.loads((repository / "packaging/macos/dev-sign-manifest.json").read_text())
    require(any(entry["file"] == "Legion Installer.app"
                and entry["identifier"] == "com.orthiclabs.legion.installer"
                for entry in sign_manifest["entries"]), "development installer must retain signed production identity")
    require('return { path: file, sha256: fileEvidence(target).sha256 };' in ci_source,
            "development payload manifest must bind signed installer bytes")
    substitutions = {
        "let resources = Bundle.main.resourceURL!":
            'let resources = URL(fileURLWithPath: ProcessInfo.processInfo.environment["LEGION_INSTALL_FIXTURE_RESOURCES"]!, isDirectory: true)',
        "let home = fileManager.homeDirectoryForCurrentUser":
            'let home = URL(fileURLWithPath: ProcessInfo.processInfo.environment["LEGION_INSTALL_FIXTURE_HOME"]!, isDirectory: true)',
    }
    for original, replacement in substitutions.items():
        require(source.count(original) == 1, f"fixture seam changed: {original}")
        source = source.replace(original, replacement)
    copied = output / "LegionInstaller.fixture.swift"
    copied.write_text(source)
    executables = {}
    for development in (False, True):
        executable = output / ("LegionInstaller.development.fixture" if development else "LegionInstaller.fixture")
        command = ["xcrun", "swiftc", "-parse-as-library"]
        if development:
            command.extend(["-D", mode])
        subprocess.run([*command, str(copied), "-framework", "Cocoa", "-o", str(executable)], check=True)
        executables[development] = executable
    return executables


def scenario(output, executable, name, *, legacy=False, fresh=False, native=True,
             failure=None, cleanup_failure=False, migrate_host=False, tamper=False,
             unsafe_payload=False, foreign_current=False, unknown_backup=False, locked=False,
             development=False, runtime_development_opt_in=False, history_links=False,
             nested_history_link=False, history_cleanup_failure=False,
             staging_cleanup_failure=False, stale_transaction=False):
    case = output / name
    home = case / "home"
    root = home / RELATIVE_ROOT
    root.mkdir(parents=True)
    resources = case / "resources"
    resources.mkdir()
    payload(resources / "payload", "candidate")
    expected = tree(resources / "payload")
    (resources / "version.txt").write_text("0.3.23\n")
    current = root / "current"
    previous = root / "current.previous"
    prior = None
    versions = root / "versions"
    outside_histories = []
    if stale_transaction:
        transaction = root / ".install-00000000-0000-0000-0000-000000000042"
        payload(transaction / "prior", "older")
        outside = case / "outside-transaction"
        payload(outside, "outside")
        outside_histories.append((outside, tree(outside)))
        (transaction / "foreign").symlink_to(outside, target_is_directory=True)
    if not fresh:
        installed = root / "versions/0.3.23" if legacy else current
        if foreign_current:
            installed = case / "unowned"
        payload(installed, "prior", native=native)
        prior = tree(installed)
        if legacy or foreign_current:
            current.symlink_to(installed, target_is_directory=True)
        versions.mkdir(exist_ok=True)
        (versions / "unknown.txt").write_text("obsolete unknown history")
        payload(versions / "obsolete", "older")
        payload(previous, "older")
    if unsafe_payload:
        (resources / "payload/unsafe").symlink_to(case / "outside")
    if unknown_backup:
        shutil.rmtree(previous)
        previous.mkdir()
        (previous / "private-notes.txt").write_text("obsolete unknown backup")
    if history_links:
        for history in (previous, versions):
            shutil.rmtree(history)
            outside = case / ("outside-" + history.name)
            payload(outside, "outside")
            outside_histories.append((outside, tree(outside)))
            history.symlink_to(outside, target_is_directory=True)
    if nested_history_link:
        outside = case / "outside-nested"
        payload(outside, "outside")
        outside_histories.append((outside, tree(outside)))
        (versions / "foreign").symlink_to(outside, target_is_directory=True)
    previous_before = tree(previous) if previous.exists() else None
    versions_before = tree(versions) if versions.exists() else None
    host = host_projection(home, root) if migrate_host else None
    if not migrate_host:
        (home / ".codex").mkdir()
        (home / ".codex/config.toml").write_text(UNRELATED + DISABLED)
    log = case / "calls.jsonl"
    environment = dict(os.environ)
    # Keep fixture host state isolated even if CI supplies real user overrides.
    environment.pop("CODEX_HOME", None)
    environment.pop("LEGION_STATE_ROOT", None)
    environment.update({
        "LEGION_INSTALL_FIXTURE_HOME": str(home),
        "LEGION_INSTALL_FIXTURE_RESOURCES": str(resources),
        "LEGION_FIXTURE_LOG": str(log),
        "LEGION_FIXTURE_FAIL_STEP": failure or "",
        "LEGION_FIXTURE_FAIL_CLEANUP": "1" if cleanup_failure else "0",
        "LEGION_FIXTURE_MIGRATE_HOST": "1" if migrate_host else "0",
        "LEGION_FIXTURE_TAMPER": "1" if tamper else "0",
        "LEGION_FIXTURE_FAIL_HISTORY_CLEANUP": "1" if history_cleanup_failure else "0",
        "LEGION_FIXTURE_FAIL_STAGING_CLEANUP": "1" if staging_cleanup_failure else "0",
    })
    # Runtime inputs must never change a production executable's mode.
    environment.pop("LEGION_DEVELOPMENT_INSTALL", None)
    if runtime_development_opt_in:
        environment["LEGION_DEVELOPMENT_INSTALL"] = "1"
    lock = open(root / ".install.lock", "a")
    if locked:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        arguments = [str(executable), "--headless"]
        if runtime_development_opt_in:
            arguments.append("--development-install")
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=90)
    finally:
        lock.close()
        if history_cleanup_failure and previous.exists():
            os.chflags(previous, 0)
        if staging_cleanup_failure:
            for transaction in root.glob(".install-*"):
                os.chflags(transaction, 0)
    (case / "installer.stdout").write_text(result.stdout)
    (case / "installer.stderr").write_text(result.stderr)
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    for call in calls:
        require(call["binary"] == str(current / "bin/legion"), f"{name}: executed outside current: {call}")
        require(call["real"] == str(current / "bin/legion"), f"{name}: current was a symlink during execution: {call}")
    rejected = unsafe_payload or foreign_current or locked
    failed = failure is not None or cleanup_failure or tamper or rejected or history_cleanup_failure or staging_cleanup_failure
    require((result.returncode != 0) == failed, f"{name}: unexpected status {result.returncode}\n{result.stderr}")
    if rejected:
        require(not calls, f"{name}: rejected payload executed")
        require(tree(current.resolve()) == prior, f"{name}: rejected install changed prior payload")
        if foreign_current:
            require(current.is_symlink(), f"{name}: foreign pointer changed")
    elif history_cleanup_failure or staging_cleanup_failure:
        require(not current.is_symlink() and tree(current) == expected, f"{name}: history cleanup failure lost activated current")
        require([call["step"] for call in calls] == ["setup repair --confirm", "setup status", "doctor"],
                f"{name}: cleanup failure reentered registration rollback")
        require("retained-history cleanup failed" in result.stderr, f"{name}: history cleanup failure was not reported")
    elif development:
        require(not current.is_symlink() and current.is_dir(), f"{name}: candidate authority lost from real current")
        actual = tree(current)
        if tamper:
            require((current / "generation.txt").read_text() == "tampered", f"{name}: tampered current state hidden")
            actual.pop("generation.txt")
            expected.pop("generation.txt")
        require(actual == expected, f"{name}: candidate payload changed or prior bytes restored")
        require(all(call["generation"] == "candidate" for call in calls), f"{name}: prior payload executed")
        require(not any(call["step"] == "setup remove --confirm" for call in calls), f"{name}: candidate authority removed")
        steps = ["setup repair --confirm", "setup status", "doctor"]
        if failure:
            steps = steps[:steps.index(failure) + 1]
        require([call["step"] for call in calls] == steps, f"{name}: development activation steps changed")
        if failed:
            require("Development payload remains" in result.stderr, f"{name}: retained failure state was not reported")
            require("Rollback incomplete" not in result.stderr and "Rollback issues" not in result.stderr,
                    f"{name}: development failure entered production rollback")
    elif cleanup_failure:
        require(not current.is_symlink() and tree(current) == expected, f"{name}: cleanup failure lost candidate")
        require(tree(previous) == previous_before, f"{name}: cleanup failure changed old history")
        require(not any(call["generation"] == "prior" for call in calls), f"{name}: restored registrations despite failed cleanup")
        require("Rollback incomplete" in result.stderr, f"{name}: cleanup failure was not reported")
    elif failed:
        if fresh:
            require(not current.exists() and not previous.exists(), f"{name}: failed first install retained an active payload")
        else:
            require(not current.is_symlink() and tree(current) == prior, f"{name}: prior payload was not restored at real current")
            require(tree(previous) == previous_before, f"{name}: failed activation changed old history")
            require(calls[-1]["generation"] == "prior" and calls[-1]["step"] == "setup repair --confirm", f"{name}: prior registration repair missing")
        removes = [call for call in calls if call["step"] == "setup remove --confirm"]
        require(bool(removes) == (not native), f"{name}: wrong native registration rollback policy")
    else:
        require(not current.is_symlink() and tree(current) == expected, f"{name}: exact candidate missing at real current")
        require(not previous.exists() and not previous.is_symlink(), f"{name}: retained previous installation")
        require([call["step"] for call in calls] == ["setup repair --confirm", "setup status", "doctor"], f"{name}: activation steps changed")
    if failed and not history_cleanup_failure and not staging_cleanup_failure:
        require((tree(previous) if previous.exists() else None) == previous_before,
                f"{name}: unsuccessful activation altered prior history")
    if staging_cleanup_failure:
        require(not previous.exists() and not previous.is_symlink(),
                f"{name}: staging cleanup failed before old backup was removed")
    if not rejected:
        for name_ in ("legion", "legion-hook", "legion-mcp"):
            link = home / ".local/bin" / name_
            require(link.is_symlink() and link.resolve() == current / "bin" / name_, f"{name}: unstable launcher {name_}")
    if failed and not staging_cleanup_failure:
        require((tree(versions) if versions.exists() else None) == versions_before,
                f"{name}: unsuccessful activation altered legacy versions")
    else:
        require(not versions.exists() and not versions.is_symlink(), f"{name}: retained version history")
    for outside, before in outside_histories:
        require(tree(outside) == before, f"{name}: history cleanup traversed outside installation root")
    require((home / ".codex/config.toml").read_text().rstrip("\n") == (UNRELATED + DISABLED).rstrip("\n"), f"{name}: host choice or unrelated setting changed")
    if host and not development:
        ledger, ledger_bytes, plugin_bytes = host
        require(ledger.read_bytes() == ledger_bytes, f"{name}: prior projection ledger lost")
        require((home / ".codex/plugins/legion/plugin.json").read_bytes() == plugin_bytes, f"{name}: prior projection lost")
        require((home / ".codex/plugins/legion/skills/sage").is_symlink(), f"{name}: prior skill link lost")
    if not failed:
        require(not previous.exists() and not previous.is_symlink(), f"{name}: retained prior backup")
        require(not any(path.read_text() in ("prior", "older") for path in root.rglob("generation.txt")),
                f"{name}: retained prior executable bytes")
        require({path.name for path in root.iterdir()} == {"current", ".install.lock"},
                f"{name}: successful install retained transaction or history state")
    staging = list(root.glob(".install-*"))
    if cleanup_failure or history_cleanup_failure or staging_cleanup_failure:
        require(len(staging) == 1, f"{name}: incomplete cleanup lost transaction recovery state")
        if not development:
            require(tree(staging[0] / "prior") == prior, f"{name}: incomplete cleanup lost recoverable prior bytes")
    else:
        require(not staging, f"{name}: transaction staging was not cleaned")
    print(f"PASS {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    arguments = parser.parse_args()
    require(sys.platform == "darwin" and os.environ.get("CI") == "true", "native installer harness runs only on macOS CI")
    output = arguments.output_root.resolve()
    require(not output.exists(), f"output path already exists: {output}")
    output.mkdir(parents=True)
    executables = compile_fixture(output)
    cases = [
        ("fresh", {"fresh": True}),
        ("fresh-failure", {"fresh": True, "native": False, "failure": "doctor"}),
        ("legacy-migration", {"legacy": True}),
        ("same-version-update", {}),
        ("legacy-repair-failure", {"legacy": True, "native": False, "failure": "setup repair --confirm"}),
        ("native-status-failure", {"failure": "setup status"}),
        ("native-doctor-failure", {"failure": "doctor"}),
        ("host-projection-rollback", {"legacy": True, "native": False, "failure": "setup status", "migrate_host": True}),
        ("cleanup-failure", {"legacy": True, "native": False, "failure": "setup status", "cleanup_failure": True}),
        ("post-activation-tamper", {"tamper": True}),
        ("unsafe-payload", {"unsafe_payload": True}),
        ("foreign-current", {"foreign_current": True}),
        ("unknown-backup", {"unknown_backup": True}),
        ("unknown-backup-rollback", {"unknown_backup": True, "failure": "doctor"}),
        ("history-links", {"history_links": True}),
        ("nested-history-link", {"nested_history_link": True}),
        ("history-cleanup-failure", {"history_cleanup_failure": True}),
        ("staging-cleanup-failure", {"staging_cleanup_failure": True}),
        ("stale-transaction-cleaned", {"stale_transaction": True}),
        ("concurrent-install", {"locked": True}),
        ("production-runtime-dev-opt-in-ignored", {"runtime_development_opt_in": True, "failure": "doctor"}),
    ]
    for name, options in cases:
        scenario(output, executables[False], name, **options)
    development_cases = [
        ("dev-fresh", {"fresh": True}),
        ("dev-same-version-update", {}),
        ("dev-legacy-migration", {"legacy": True}),
        ("dev-fresh-failure", {"fresh": True, "native": False, "failure": "doctor"}),
        ("dev-repair-failure", {"native": False, "failure": "setup repair --confirm"}),
        ("dev-status-failure", {"failure": "setup status"}),
        ("dev-doctor-failure", {"failure": "doctor"}),
        ("dev-disabled-intent", {"legacy": True, "native": False, "migrate_host": True}),
        ("dev-disabled-intent-failure", {"legacy": True, "native": False, "failure": "setup status", "migrate_host": True}),
        ("dev-post-activation-tamper", {"tamper": True}),
        ("dev-unsafe-payload", {"unsafe_payload": True}),
        ("dev-foreign-current", {"foreign_current": True}),
        ("dev-unknown-backup-cleaned", {"unknown_backup": True}),
        ("dev-history-links", {"history_links": True}),
        ("dev-nested-history-link", {"nested_history_link": True}),
        ("dev-history-cleanup-failure", {"history_cleanup_failure": True}),
        ("dev-staging-cleanup-failure", {"staging_cleanup_failure": True}),
        ("dev-stale-transaction-cleaned", {"stale_transaction": True}),
        ("dev-concurrent-install", {"locked": True}),
    ]
    for name, options in development_cases:
        scenario(output, executables[True], name, development=True, **options)


if __name__ == "__main__":
    main()
