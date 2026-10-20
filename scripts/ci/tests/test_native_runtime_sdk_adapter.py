"""Constructed alias topology controls; no native tools or SDKs are executed."""
import contextlib
import copy
import io
import os
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = runpy.run_path(str(ROOT / "scripts/ci/provision-python-qualification-tools.py"))
RETAINED = "sdk/Actual.framework/Versions/A/Actual.tbd"
CHILD = "sdk/Aggregate.framework/Versions/A/Frameworks/Actual.framework"
LINKS = {
    "sdk/Aggregate.framework/Frameworks": "Versions/Current/Frameworks",
    "sdk/Aggregate.framework/Versions/Current": "A",
    CHILD: "../../../../Actual.framework",
    "sdk/Actual.framework/Actual.tbd": "Versions/Current/Actual.tbd",
    "sdk/Actual.framework/Versions/Current": "A",
}


def manifest(links=None, files=None, roots=None, absent=None):
    value = {
        "files": {RETAINED: API["digest_bytes"](b"retained stub\n")} if files is None else files,
        "links": dict(LINKS) if links is None else links,
        "roots": ["/" + RETAINED] if roots is None else roots,
        "absent": [] if absent is None else absent,
    }
    return dict(value, root="/", exclusions=[], digest=API["digest_bytes"](API["canonical"](value)))


class NativeRuntimeManifestTests(unittest.TestCase):
    def reject(self, value):
        with self.assertRaises(ValueError):
            API["validate_runtime_aliases"](value)

    def test_sibling_framework_container_ends_at_retained_bytes(self):
        value = manifest()
        self.assertEqual(API["validate_runtime_aliases"](value), {})
        self.assertEqual(value["roots"], ["/" + RETAINED])
        self.assertEqual(value["absent"], [])

    def test_nested_containers_reach_finite_retained_endpoint(self):
        links = dict(LINKS, **{
            "sdk/Outer.framework/Frameworks": "Versions/A/Frameworks",
            "sdk/Outer.framework/Versions/A/Frameworks/Aggregate.framework": "../../../../Aggregate.framework",
        })
        self.assertEqual(API["validate_runtime_aliases"](manifest(links=links)), {})

    def test_unrelated_orphan_alias_is_rejected(self):
        self.reject(manifest(links=dict(LINKS, **{"host/orphan": "empty"})))

    def test_link_cycles_and_unseeded_container_cycles_are_rejected(self):
        for extra in ({"host/a": "b", "host/b": "a"},
                      {"host/a/to-b": "../b", "host/b/to-a": "../a"}):
            with self.subTest(extra=extra):
                self.reject(manifest(links=dict(LINKS, **extra)))

    def test_retargeted_descendant_is_rejected(self):
        links = dict(LINKS)
        links[CHILD] = "/host/unbound"
        self.reject(manifest(links=links))

    def test_missing_descendant_or_retained_bytes_is_rejected(self):
        links = dict(LINKS)
        del links[CHILD]
        self.reject(manifest(links=links))
        self.reject(manifest(files={}))

    def test_omitted_intermediate_hop_is_rejected(self):
        links = dict(LINKS)
        del links["sdk/Actual.framework/Versions/Current"]
        self.reject(manifest(links=links))

    def test_empty_root_and_absence_cannot_seed_container_proof(self):
        links = dict(LINKS)
        links[CHILD] = "/host/empty"
        self.reject(manifest(links=links, roots=["/" + RETAINED, "/host/empty"]))
        self.reject(manifest(
            links={"host/container": "target", "host/target/hop": "missing"},
            absent=["/host/target/hop/missing.dylib"]))

    def test_walked_root_link_cannot_escape_through_retained_bytes(self):
        self.reject(manifest(links={"enrolled/export": "/sdk/Actual.framework"},
                             roots=["/" + RETAINED, "/enrolled"]))

    def test_excluded_route_is_rejected(self):
        value = manifest()
        value["exclusions"] = ["/sdk/Actual.framework"]
        self.reject(value)


@unittest.skipUnless(os.name == "posix", "live snapshot uses POSIX filesystem-root paths")
class NativeRuntimeLiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve(strict=True)
        self.retained = self.base / RETAINED
        self.retained.parent.mkdir(parents=True)
        self.retained.write_bytes(b"retained stub\n")
        for name, raw in LINKS.items():
            path = self.base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(raw, target_is_directory=not name.endswith(".tbd"))
        self.aliases = {}
        selected = self.base / "sdk/Aggregate.framework/Frameworks/Actual.framework/Actual.tbd"
        self.assertEqual(API["resolve_link_chain"](selected, self.aliases), self.retained)
        self.roots = [str(self.retained)]
        self.baseline = API["snapshot"](self.roots, [], self.aliases, [])

    def reject(self, aliases=None):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises((ValueError, OSError)):
            API["snapshot"](self.roots, [], self.aliases if aliases is None else aliases, [])

    def test_live_sibling_framework_snapshot_and_manifest_agree(self):
        self.assertEqual(API["validate_runtime_aliases"](self.baseline), {})
        self.assertEqual(self.baseline["links"], dict(sorted(self.aliases.items())))
        self.assertEqual(self.baseline["files"], {
            self.retained.relative_to("/").as_posix(): API["digest_bytes"](b"retained stub\n")})
        self.assertEqual(API["snapshot"](self.roots, [], self.baseline["links"], []), self.baseline)

    def test_live_orphan_alias_is_rejected(self):
        empty = self.base / "host/empty"
        empty.mkdir(parents=True)
        orphan = empty.parent / "orphan"
        orphan.symlink_to("empty", target_is_directory=True)
        aliases = dict(self.aliases)
        aliases[orphan.relative_to("/").as_posix()] = "empty"
        self.reject(aliases)

    def test_live_cycle_is_rejected(self):
        child = self.base / CHILD
        child.unlink()
        child.symlink_to("Actual.framework", target_is_directory=True)
        aliases = dict(self.aliases)
        aliases[child.relative_to("/").as_posix()] = "Actual.framework"
        self.reject(aliases)

    def test_live_retargeted_descendant_is_rejected(self):
        child = self.base / CHILD
        child.unlink()
        (self.base / "sdk/Unbound.framework").mkdir()
        child.symlink_to("../../../../Unbound.framework", target_is_directory=True)
        self.reject()

    def test_live_missing_descendant_is_rejected(self):
        (self.base / CHILD).unlink()
        self.reject()

    def test_live_omitted_hop_is_rejected(self):
        aliases = copy.deepcopy(self.aliases)
        del aliases[(self.base / "sdk/Actual.framework/Versions/Current").relative_to("/").as_posix()]
        self.reject(aliases)


if __name__ == "__main__":
    unittest.main()
