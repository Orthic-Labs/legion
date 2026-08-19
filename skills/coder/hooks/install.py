# dependency-class: HOST_CAPABILITY(agent-host-config) — writes into the embedding agent host's own config tree.
"""Install this dir's synced Claude Code hooks into the LOCAL machine.

Self-locating + cross-platform: registers each hook in hooks.json into this
machine's ~/.claude/settings.json (under its event/matcher) and
~/.claude/hooks/hooks-manifest.json, using THIS machine's absolute path to the
hook file in the repo. Idempotent — dedupes by hook filename, safe to re-run.
Run it after a fresh clone / git pull on any machine (Windows or Mac).

    python  tools/skills/coder/hooks/install.py   # Windows
    python3 tools/skills/coder/hooks/install.py    # Mac

The hook .py files stay in the repo (git-synced); only the per-machine
registration (which carries absolute paths) is written locally.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLAUDE = os.path.expanduser("~/.claude")
SETTINGS = os.path.join(CLAUDE, "settings.json")
MANIFEST = os.path.join(CLAUDE, "hooks", "hooks-manifest.json")
PYBIN = "python" if os.name == "nt" else "python3"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    hooks = load(os.path.join(HERE, "hooks.json"))
    settings = load(SETTINGS)
    manifest = load(MANIFEST) if os.path.exists(MANIFEST) else {"hooks": []}
    shutil.copyfile(SETTINGS, SETTINGS + ".pre-synced-hooks.bak")

    settings.setdefault("hooks", {})
    for hk in hooks:
        abs_path = os.path.join(HERE, hk["file"]).replace("\\", "/")
        command = f"{PYBIN} {abs_path}"
        basename = hk["file"]
        event, matcher = hk["event"], hk["matcher"]

        # settings.json: find/create the event→matcher entry, dedupe by basename.
        ev = settings["hooks"].setdefault(event, [])
        entry = next((e for e in ev if e.get("matcher") == matcher), None)
        if entry is None:
            entry = {"matcher": matcher, "hooks": []}
            ev.append(entry)
        entry["hooks"] = [h for h in entry["hooks"] if not h.get("command", "").endswith(basename)]
        entry["hooks"].append({"type": "command", "command": command})

        # hooks-manifest.json: replace the entry by id.
        man = dict(hk["manifest"])
        man["command"] = command
        manifest["hooks"] = [h for h in manifest.get("hooks", []) if h.get("id") != man["id"]]
        manifest["hooks"].append(man)
        print(f"registered {man['id']} -> {command}")

    with open(SETTINGS, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    print(f"done. backup: {SETTINGS}.pre-synced-hooks.bak")
    print("Restart Claude Code to load the hooks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
