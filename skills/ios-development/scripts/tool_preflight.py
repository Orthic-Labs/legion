#!/usr/bin/env python3
"""Read-only PATH preflight. Never executes tools, installs, or edits configuration."""
import argparse
import json
from pathlib import Path
import platform
import shutil


def inspect_tool(tool, system, locate=shutil.which):
    found = [{"command": name, "path": path} for name in tool["executables"]
             if (path := locate(name))]
    if found:
        state, next_step = "installed-candidate", "Verify version/schema and reuse if compatible; do not reinstall."
    elif system not in tool["platforms"]:
        state, next_step = "unsupported-environment", "Use a supported authorized environment; do not install here."
    elif not tool["executables"]:
        state, next_step = "manual-check", "Inspect the existing project/app/source integration before proposing setup."
    else:
        state, next_step = "not-on-path", "Check connected MCP tools and alternate existing locations, then follow the setup recipe if genuinely missing."
    return {"id": tool["id"], "state": state, "found": found,
            "nextStep": next_step, "scope": tool["scope"],
            "recipe": tool["recipeReference"], "versionVerified": False,
            "mcpRegistrationVerified": False}


def inspect_selected(catalog, ids, system, locate=shutil.which):
    indexed = {tool["id"]: tool for tool in catalog["tools"]}
    unknown = set(ids) - indexed.keys()
    if unknown:
        raise ValueError("Unknown tool ids: " + ", ".join(sorted(unknown)))
    return [inspect_tool(indexed[id], system, locate) for id in dict.fromkeys(ids)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", action="append", default=[], help="Selected catalog id; repeat for multiple tools")
    parser.add_argument("--list", action="store_true", help="List catalog ids without probing")
    args = parser.parse_args()
    catalog = json.loads((Path(__file__).resolve().parent.parent / "config/tool-catalog.json").read_text())
    if args.list:
        print(json.dumps({"tools": [tool["id"] for tool in catalog["tools"]]}))
        return
    if not args.tool:
        parser.error("select at least one --tool; do not provision every tool")
    try:
        result = inspect_selected(catalog, args.tool, platform.system())
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"readOnly": True, "environment": platform.system(),
                      "tools": result, "note": "PATH evidence only; no compatibility, MCP, authorization or native-validation pass is implied."}, indent=2))


if __name__ == "__main__":
    main()
