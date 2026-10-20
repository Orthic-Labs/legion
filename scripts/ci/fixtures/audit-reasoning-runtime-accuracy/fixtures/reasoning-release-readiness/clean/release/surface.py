import os
from pathlib import Path

SURFACE = {
    "shippedTargets": [
        "macos",
        "windows"
    ],
    "platforms": {
        "macos": {
            "signing": "release/signing/macos.sh",
            "updater": "release/updater/macos.json",
            "bundle": "release/bundles/macos.toml",
            "attribution": "release/THIRD_PARTY_NOTICES.md"
        },
        "windows": {
            "signing": "release/signing/windows.ps1",
            "updater": "release/updater/windows.json",
            "bundle": "release/bundles/windows.toml",
            "attribution": "release/THIRD_PARTY_NOTICES.md"
        }
    }
}

def validate(target):
    for role, path in SURFACE["platforms"][target].items():
        if path is None or not Path(path).is_file():
            raise RuntimeError(f"{target}: missing {role} release surface")

if __name__ == "__main__":
    validate(os.environ["TARGET"])
