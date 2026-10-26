"""Shell units for the declared qualification BUILD stage in right-git-ci.sh.

Stub cargo & a stub ci-qualification-child wrapper record every invocation; no
real build, test, deadline or cleanup runs. The stub cargo models artifact
reuse: a timed `cargo test` is warm only when a `--no-run` build with the exact
same argv, cwd & build environment ran first; otherwise it pays the compile
cost inside the case. The stub wrapper models a per-case deadline (seconds, not
the real 300 s) and the mandatory-cleanup exit 125.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = SOURCE_ROOT / "scripts/ci/right-git-ci.sh"
WRAPPER_SOURCE = SOURCE_ROOT / "engine/bins/legion-dev/src/ci_qualification_child.rs"
BUILD_ENV = ["RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
             "LEGION_REASONING_NATIVE_RUNNER_DIR", "TMPDIR", "PATH"]
# Exact pre-change timed argv of sequence 6 (after the cargo path); the wrapper
# keys its deadline on it, and qualification records bind COMMAND_BEGIN argv.
SEQ6_TIMED = ["test", "--locked", "--manifest-path", "engine/Cargo.toml", "-p", "legion",
              "--test", "reasoning_runtime_qualification", "reasoning_runtime_production_no_call_contract",
              "--", "--exact", "--nocapture", "--test-threads=1"]
SEQ5_TIMED = ["test", "--locked", "-p", "legion-audit", "--test", "reasoning_runtime_qualification",
              "reasoning_runtime_no_call_contract", "--", "--exact", "--nocapture", "--test-threads=1"]

CARGO_STUB = r'''#!/usr/bin/env bash
"$MOCK_PYTHON" - "$@" <<'PY'
import hashlib, json, os, sys, time
argv = sys.argv[1:]
build = "--no-run" in argv
env = {key: os.environ.get(key) for key in json.loads(os.environ["MOCK_BUILD_ENV"])}
identity = [x for x in argv if x != "--no-run"]
key = hashlib.sha256(json.dumps([os.getcwd(), identity, env]).encode()).hexdigest()
marker = os.path.join(os.environ["MOCK_ARTIFACTS"], key)
with open(os.environ["MOCK_CALLS"], "a") as calls:
    calls.write(json.dumps({"tool": "cargo", "mode": "build" if build else "test", "cwd": os.getcwd(),
                            "argv": argv, "env": env, "warm": os.path.exists(marker)}) + "\n")
if not os.path.exists(marker):
    print("   Compiling legion (cold)", file=sys.stderr, flush=True)
    time.sleep(float(os.environ["MOCK_BUILD_SECONDS"]))
    if build and os.environ.get("MOCK_BUILD_STATUS", "0") != "0":
        sys.exit(int(os.environ["MOCK_BUILD_STATUS"]))
    open(marker, "w").close()
print("    Finished `test` profile", file=sys.stderr, flush=True)
if not build:
    time.sleep(float(os.environ["MOCK_TEST_SECONDS"]))
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out", flush=True)
PY
'''

WRAPPER_STUB = r'''#!/usr/bin/env bash
[[ "$1" == ci-qualification-child && "$2" == --sequence && "$4" == -- ]] || exit 99
sequence="$3"; shift 4
"$MOCK_PYTHON" -c 'import json, os, sys; open(os.environ["MOCK_CALLS"], "a").write(json.dumps({"tool": "wrapper", "sequence": int(sys.argv[1]), "cwd": os.getcwd(), "argv": sys.argv[2:]}) + "\n")' "$sequence" "$@"
case "$(basename "$1")" in python3|python3.exe) exit 0 ;; esac
"$@" &
pid=$!
ticks=0
while kill -0 "$pid" 2>/dev/null; do
  if (( ticks >= MOCK_DEADLINE_TENTHS )); then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    printf 'AUDIT_QUALIFICATION_COMMAND_TIMEOUT {"sequence":%s,"timedOut":true,"wrapperExitCode":124}\n' "$sequence" >&2
    exit 124
  fi
  sleep 0.1
  ticks=$((ticks + 1))
done
native=0
wait "$pid" || native=$?
if [[ "${MOCK_CLEANUP_FAILED:-0}" == 1 ]]; then
  printf 'AUDIT_QUALIFICATION_COMMAND_END_RECEIPT {"sequence":%s,"nativeExitCode":%s,"wrapperExitCode":125,"cleanup":{"failed":[4242]}}\n' "$sequence" "$native" >&2
  exit 125
fi
exit "$native"
'''


def function(shell, name):
    match = re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", shell)
    assert match is not None, name
    return match.group(0)


def bash_path():
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    if git is None:
        return None
    git_dir = Path(git).resolve().parent
    candidates = [git_dir / "bash.exe", git_dir.parent / "bin/bash.exe", git_dir.parent / "usr/bin/bash.exe",
                  git_dir.parent.parent / "bin/bash.exe", git_dir.parent.parent / "usr/bin/bash.exe",
                  Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/bin/bash.exe"]
    return next((str(path) for path in candidates if path.is_file()), None)


class QualificationBuildStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qualification-build-stage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "work/engine").mkdir(parents=True)
        (self.root / "artifacts").mkdir()
        self.cargo = self.root / "bin/cargo"
        self.wrapper = self.root / "bin/legion-dev"
        self.cargo.parent.mkdir()
        self.cargo.write_text(CARGO_STUB, newline="\n")
        self.wrapper.write_text(WRAPPER_STUB, newline="\n")
        self.cargo.chmod(0o755)
        self.wrapper.chmod(0o755)
        shell = SCRIPT.read_text()
        block = shell.split("# BEGIN qualification build stage.\n", 1)[1].split("# END qualification build stage.", 1)[0]
        functions = "".join(function(shell, name) for name in (
            "audit_native_command", "audit_qualification_dispatch", "audit_cargo_test", "run_audit_qualification"))
        reasoning = shell.split("# Source-owned corpus checks never resolve a harness or authorize generation.\n", 1)[1]
        self.reasoning = reasoning.split("unset LEGION_REASONING_NATIVE_RUNNER_DIR\n", 1)[0]
        self.prelude = functions + block
        self.bash = bash_path()
        self.assertIsNotNone(self.bash, "Bash is required for qualification build stage units")

    def run_gate(self, body=None, emulate_pre_fix=False, **mock):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("MOCK_", "LEGION_"))}
        env.update(RUNNER_TEMP=(self.root / "runner").as_posix(), GITHUB_WORKSPACE=(self.root / "work").as_posix(),
                   MOCK_PYTHON=Path(sys.executable).as_posix(), MOCK_CALLS=(self.root / "calls").as_posix(),
                   MOCK_ARTIFACTS=(self.root / "artifacts").as_posix(), MOCK_BUILD_ENV=json.dumps(BUILD_ENV),
                   MOCK_BUILD_SECONDS="0.8", MOCK_TEST_SECONDS="0", MOCK_DEADLINE_TENTHS="5",
                   RUSTFLAGS="-Cdebuginfo=1", CARGO_TARGET_DIR=(self.root / "target").as_posix(),
                   CARGO_PROFILE_DEV_DEBUG="1", RIGHT_GIT_RUST_CHANGED="false")
        env.update(mock)
        harness = ("set -euo pipefail\n"
                   'python3() { "$MOCK_PYTHON" "$@"; }\n'
                   f'audit_cargo_bin="{self.cargo.as_posix()}"\n'
                   f'ci_dev_helper="{self.wrapper.as_posix()}"\n'
                   + self.prelude
                   + ("qualification_cargo_build() { return 0; }\n" if emulate_pre_fix else "")
                   + "audit_qualification_failures=0\naudit_qualification_sequence=4\n"
                   + (self.reasoning if body is None else body)
                   + 'printf "FAILURES=%s\\n" "$audit_qualification_failures"\n')
        result = subprocess.run([self.bash, "-c", harness], cwd=self.root / "work", env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout)
        path = self.root / "calls"
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return result.stdout, calls

    @staticmethod
    def ends(log):
        return dict(re.findall(r"(?m)^AUDIT_QUALIFICATION_COMMAND_END ([0-9]+) ([0-9]+)$", log))

    def test_pre_fix_model_reproduces_cold_compile_timeout(self):
        # Control for the model: without the build stage the cold compile lands
        # inside the case budget and sequence 6 times out, as in run 40280723295.
        # The stub deadline counts 0.1 s sleep ticks, which a loaded runner stretches (macOS run 40285889201
        # finished a 0.8 s build inside 5 ticks), so the cold build here is far past any plausible 5 ticks.
        log, calls = self.run_gate(emulate_pre_fix=True, MOCK_BUILD_SECONDS="4.0")
        self.assertEqual(self.ends(log), {"5": "124", "6": "124"}, log)
        self.assertIn("FAILURES=2", log)
        self.assertFalse([call for call in calls if call.get("mode") == "build"])

    def test_docs_only_build_stage_runs_before_timed_case_outside_its_budget(self):
        # Build cost (0.8 s) exceeds the stub case deadline (0.5 s); it passes
        # only because the build is not inside the wrapper.
        log, calls = self.run_gate()
        self.assertEqual(self.ends(log), {"5": "0", "6": "0"}, log)
        self.assertIn("FAILURES=0", log)
        sequence = [(call["tool"], call.get("mode"), call.get("sequence")) for call in calls]
        self.assertEqual(sequence, [("cargo", "build", None), ("wrapper", None, 5), ("cargo", "test", None),
                                    ("cargo", "build", None), ("wrapper", None, 6), ("cargo", "test", None)])
        self.assertTrue(all(call["warm"] for call in calls if call.get("mode") == "test"))
        for number in ("5", "6"):
            begin = re.search(r'(?m)^AUDIT_QUALIFICATION_COMMAND_BEGIN .*"sequence":' + number + r'\}$', log).start()
            build_begin = log.index(f"AUDIT_QUALIFICATION_BUILD_BEGIN {number} ")
            build_end = log.index(f"AUDIT_QUALIFICATION_BUILD_END {number} 0")
            command_end = log.index(f"AUDIT_QUALIFICATION_COMMAND_END {number} 0")
            self.assertTrue(begin < build_begin < build_end < command_end, log)
        self.assertEqual(log.count("test result: ok."), 2, "build stage must not emit test outcomes into the span")

    def test_build_and_timed_run_share_exact_identity(self):
        log, calls = self.run_gate()
        builds = [call for call in calls if call.get("mode") == "build"]
        tests = [call for call in calls if call.get("mode") == "test"]
        wrapped = [call for call in calls if call["tool"] == "wrapper"]
        self.assertEqual(len(builds), len(tests), 2)
        for build, test, wrap in zip(builds, tests, wrapped):
            self.assertEqual(build["argv"][:2], ["test", "--no-run"])
            self.assertEqual(build["argv"][:1] + build["argv"][2:], test["argv"])
            self.assertEqual((build["cwd"], build["env"]), (test["cwd"], test["env"]))
            self.assertEqual(wrap["argv"], [self.cargo.as_posix()] + test["argv"])
        self.assertEqual(Path(builds[0]["cwd"]).name, "engine")
        self.assertEqual(Path(builds[1]["cwd"]).name, "work")
        self.assertEqual(tests[0]["argv"], SEQ5_TIMED)
        self.assertEqual(tests[1]["argv"], SEQ6_TIMED)
        self.assertEqual(builds[1]["env"]["LEGION_REASONING_NATIVE_RUNNER_DIR"],
                         (self.root / "runner").as_posix() + "/legion-provider-qualification/reasoning-native-runner")
        self.assertEqual(builds[1]["env"]["RUSTFLAGS"], "-Cdebuginfo=1")
        begins = [json.loads(line) for line in re.findall(r"(?m)^AUDIT_QUALIFICATION_COMMAND_BEGIN (.*)$", log)]
        self.assertEqual(begins[1], {"argv": [self.cargo.as_posix()] + SEQ6_TIMED, "sequence": 6})
        self.assertEqual(begins[0], {"argv": ["audit_cargo_test"] + SEQ5_TIMED[4:], "sequence": 5})

    def test_rust_changed_path_runs_identical_stage_without_extra_targets(self):
        _, docs_only = self.run_gate()
        (self.root / "calls").unlink()
        for marker in (self.root / "artifacts").iterdir():
            marker.unlink()
        _, rust_changed = self.run_gate(RIGHT_GIT_RUST_CHANGED="true")
        strip = lambda calls: [{key: value for key, value in call.items() if key != "warm"} for call in calls]
        self.assertEqual(strip(docs_only), strip(rust_changed))
        builds = [call["argv"] for call in rust_changed if call.get("mode") == "build"]
        self.assertEqual(builds, [["test", "--no-run"] + SEQ5_TIMED[1:], ["test", "--no-run"] + SEQ6_TIMED[1:]])

    def test_native_success_with_cleanup_failure_still_fails(self):
        log, _ = self.run_gate(MOCK_CLEANUP_FAILED="1")
        self.assertEqual(self.ends(log), {"5": "125", "6": "125"}, log)
        self.assertIn('"nativeExitCode":0,"wrapperExitCode":125', log)
        self.assertIn("FAILURES=2", log)
        self.assertIn("::error::Audit qualification command failed (exit 125)", log)

    def test_case_exceeding_deadline_still_times_out(self):
        log, calls = self.run_gate(MOCK_TEST_SECONDS="4.0")
        self.assertEqual(self.ends(log), {"5": "124", "6": "124"}, log)
        self.assertIn("FAILURES=2", log)
        self.assertTrue(all(call["warm"] for call in calls if call.get("mode") == "test"))

    def test_build_failure_fails_its_sequence_without_running_the_case(self):
        log, calls = self.run_gate(MOCK_BUILD_STATUS="101")
        self.assertEqual(self.ends(log), {"5": "101", "6": "101"}, log)
        self.assertIn("AUDIT_QUALIFICATION_BUILD_END 6 101", log)
        self.assertFalse([call for call in calls if call["tool"] == "wrapper"])
        self.assertIn("FAILURES=2", log)

    def test_dotnet_child_route_builds_same_argv_and_keeps_wrapped_argv(self):
        body = ('LEGION_DOTNET_CHILD_OUTPUT="$RUNNER_TEMP/dotnet" run_audit_qualification audit_cargo_test '
                '--lib some::selector -- --ignored --exact\n')
        log, calls = self.run_gate(body=body)
        self.assertEqual(self.ends(log), {"5": "0"}, log)
        self.assertEqual([call["tool"] for call in calls], ["cargo", "wrapper"])
        build, wrap = calls
        self.assertEqual(build["argv"], ["test", "--no-run", "--locked", "-p", "legion-audit", "--lib", "some::selector",
                                         "--", "--ignored", "--exact"])
        self.assertEqual(wrap["argv"][0], "python3")
        self.assertEqual(wrap["argv"][4:], ["--", self.cargo.as_posix(), "test", "--locked", "-p", "legion-audit",
                                            "--lib", "some::selector", "--", "--ignored", "--exact"])
        self.assertEqual(build["cwd"], wrap["cwd"])

    def test_wrapper_deadline_and_mandatory_cleanup_are_unchanged(self):
        source = WRAPPER_SOURCE.read_text()
        self.assertIn("    Duration::from_secs(300)\n}", source)
        self.assertIn("let status = if cleanup_error.is_some() || wait_error.is_some() || sweep_failed {\n        125",
                      source)


if __name__ == "__main__":
    unittest.main()
