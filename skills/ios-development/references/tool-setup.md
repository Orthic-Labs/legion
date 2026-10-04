# Tool setup: detect, reuse, provision once, verify

This is an agent-run setup playbook, not a request for the user to research tools. It
ships inside both standalone Apple skills. The [catalog](../config/tool-catalog.json)
names official sources, commands, platform/scope, probes and version policy. Recipes
were checked on 2026-10-04; inspect current official instructions and the project's pins
before applying them. No upstream binaries, package managers, account credentials or
client registrations are embedded in this skill.

## Mandatory lifecycle

1. **Detect.** Identify the execution computer, OS/architecture, agent client and config
   scope. Inventory PATH, already connected MCP servers/tools, project lockfiles/wrappers,
   and the selected tools' installed versions. Read existing config locally without
   echoing secrets. A CLI missing from PATH does not prove its MCP server is absent.
2. **Select.** Name the capability the task needs and the smallest adequate tool/route.
   Prefer compatible project choices. Both Apple skills reuse the same environment tools;
   do not install a second copy because the other skill was selected. Avoid redundant UI
   adapters if an existing server already exposes the necessary capability.
3. **Reuse.** Verify the existing version and actual help/tool schema against the project.
   If compatible, use it with zero installation/configuration changes. An old name is not
   an instruction to upgrade. If incompatible, explain the exact conflict and propose a
   scoped alternative; do not overwrite the working installation.
4. **Propose setup when needed.** Follow the catalog's official source, not a guessed
   package name or a search ad. Resolve the intended release/architecture, prerequisites,
   destination, PATH change and client/project scope. Tell the user what is missing,
   why it is needed, the exact changes and any permissions or persistent access. Carry
   out setup only under the applicable live authorization; software installation and
   persistent MCP access are separate approval boundaries. Respect denial. Never install
   a package manager, add credentials, purchase an app or weaken security implicitly.
5. **Apply narrowly and idempotently.** Recheck just before the approved change. If another
   process already supplied a compatible tool or identical registration, reuse it. Preserve
   all unrelated config, comments, servers, dependencies and user customizations. Merge
   only the approved entry using the host's supported command or structured editor; never
   replace an entire config file with the example below. A conflicting entry requires
   resolution, not deletion/renaming to bypass it. Preview the diff and retain a protected
   preimage where appropriate; do not put credential-bearing config in logs or Git.
6. **Verify and continue.** Resolve the executable, record its version/help, and for MCP
   reconnect/reload as required, enumerate the actual tools, and make the smallest safe
   read-only discovery call. Verify the target workspace/scheme/device. Report setup,
   authentication and native task validation as different states. Setup failure or a
   declined permission leaves a precise blocked step, while independent work continues.

Loading this skill is not installation approval. Setup approval is not permission to
sign, upload, publish, create credentials, access unrelated data or bypass trust prompts.
If the environment cannot support the needed tool, identify the supported authorized
machine/host route rather than repeatedly trying installation.

## Persistence and re-entry

- A CLI installation normally persists for the computer/user environment; both skills
  share it. A fresh container, different machine, removed binary or changed PATH needs a
  new check, not a promise that prior setup follows the user everywhere.
- MCP registration persists in the selected client scope. A second client may need its
  own registration while reusing the same binary. Project-local config follows that
  project; user-level config may cover multiple projects. Choose the user's intended
  scope explicitly instead of silently creating global access.
- Project packages and build plugins persist in project manifests/lockfiles. They are
  separate from user-machine tools and require an authorized project change.
- On every use, do lightweight detection/version verification; install only when actually
  missing and authorized. Do not rerun installation, init, setup or upgrades every session.
- Existing config modified since the preview must be reread and the change recomputed.
  Never restore an old preimage over later user edits. Roll back only your own change.

## Optional read-only preflight helper

From this skill's directory, with Python 3.8+ already available:

```sh
python3 scripts/tool_preflight.py --list
python3 scripts/tool_preflight.py --tool mobilebuildmcp --tool asc
```

The helper only resolves PATH entries; it executes no discovered tool, starts no server,
reads no client config, writes no file and performs no network request. It returns
`installed-candidate`, `not-on-path`, `manual-check` or `unsupported-environment`, never
"ready". The agent still verifies compatibility, MCP inventory, auth and permissions.
Without Python, do the catalog's PATH checks directly; don't install Python just to run
this convenience check. Python is scoped only to this helper route.

## Release selection and source checks

Use a compatible project pin first. Otherwise inspect the official release/package
metadata, select a supported release and record the resolved version before requesting
setup. Review source/release identity and available integrity signatures/checksums. A
source-manifest commit records what was inspected, not a universal install version.

The commands below are recipes to adapt after detection/authorization, not a bulk script.
Homebrew formula names resolve to moving releases; inspect the formula/version before
approval. An exact old version may require the upstream's supported release asset or
versioned package route instead. With npm, replace `<approved-version>` with that exact
version, not `latest`; don't execute the placeholder. Do not blindly pipe a remote shell
script into a shell. Prefer the documented package/release route and inspect installers
when one is necessary. Never silently upgrade a dependency to make an example work.

## mobilebuildmcp

Official [MobileBuildMCP repository](https://github.com/getsentry/MobileBuildMCP)
provides both CLI and MCP modes. Existing XcodeBuildMCP may still be the compatible
project choice: inspect its version/interface before any migration.

After selecting a supported version, choose one installation method:

```sh
brew tap getsentry/xcodebuildmcp
brew install mobilebuildmcp
# Alternative, not an additional installation:
npm install -g mobilebuildmcp@<approved-version>
```

The npm route needs a supported Node runtime; check upstream's current requirements.
Before any invocation, opt out of telemetry in the process environment and inspect
higher-priority project/session overrides. On POSIX shells, probe with
`MOBILEBUILDMCP_SENTRY_DISABLED=true mobilebuildmcp --help`, then the same environment
for `mobilebuildmcp tools`.
Use the actual version's schemas, not historical tool names. Installation alone does not
register it with a client. MCP can also run from a pinned npm package on demand, but a
stable installed binary avoids repeated package-resolution checks.

Upstream documents runtime telemetry, a per-workspace daemon and macro-validation
bypass behavior. Inspect these before invocation. Do not invoke a build route that
silently weakens validation: choose the approved project CLI instead if the selected
server version cannot preserve it. Do not start unrelated workflows/daemons.

### MCP client configuration

Follow the [official client guide](https://github.com/getsentry/mobilebuildmcp.com/blob/main/app/docs/_content/clients.mdx)
for the detected client/version. The following are fragments to merge only after
approval for the exact scope. Use the resolved absolute executable path when the GUI
client does not inherit the shell PATH. No shell aliases or unexpanded placeholders.

Codex: inspect existing registrations and client help first. A supported CLI form is
`codex mcp add MobileBuildMCP -- mobilebuildmcp mcp`. Alternatively the user-level
`~/.codex/config.toml` server fragment is:

```toml
[mcp_servers.MobileBuildMCP]
command = "/absolute/verified/path/mobilebuildmcp"
args = ["mcp"]
[mcp_servers.MobileBuildMCP.env]
MOBILEBUILDMCP_SENTRY_DISABLED = "true"
```

Cursor: project `.cursor/mcp.json` or user `~/.cursor/mcp.json`; Claude Desktop:
`~/Library/Application Support/Claude/claude_desktop_config.json`. Merge the server
inside the existing `mcpServers` object:

```json
{
  "MobileBuildMCP": {
    "command": "/absolute/verified/path/mobilebuildmcp",
    "args": ["mcp"],
    "env": {"MOBILEBUILDMCP_SENTRY_DISABLED": "true"}
  }
}
```

Claude Code supports `claude mcp add MobileBuildMCP -- mobilebuildmcp mcp`; inspect
its current scope/env options before using it. Select the approved scope and set the
verified telemetry policy before starting the server. Other hosts must use their own
supported schema, not a Codex/Cursor fragment pasted into an unrelated file.

These examples opt out of telemetry according to the current upstream environment
interface. [Configuration](https://github.com/getsentry/mobilebuildmcp.com/blob/main/app/docs/_content/configuration.mdx)
has higher-priority project/session overrides: inspect effective `sentryDisabled`, not
just the environment. In a new authorized project configuration, `schemaVersion: 1`
and `sentryDisabled: true` express that choice; merge rather than overwrite an existing
file. Verify the chosen version recognizes the setting. After client reload, tool
listing is required: a config file on disk is not proof the server connected.

## axe

[AXe](https://github.com/cameroncooke/AXe) supports Homebrew installation:
`brew install cameroncooke/axe/axe`. Check its release compatibility with the selected
runtime first. Verify `axe --help`, then `axe list-simulators`. Inspect the intended
simulator's identity before UI actions. Preserve packaged companion frameworks. If the
chosen MobileBuildMCP already provides working UI automation, don't install duplicate
AXe just to satisfy a name in this catalog. Permissions/device actions remain separate.

## docsetquery

[DocSetQuery](https://github.com/PaulSolt/DocSetQuery) is a repository of Python tools,
not an assumed Homebrew formula or MCP server. Fetch the reviewed revision into an
approved persistent tools directory; don't overwrite an existing checkout. Inspect
imports/prerequisites and use an isolated environment for any approved dependencies.
Probe `python3 <checkout>/tools/docset_query.py --help` and `docindex.py --help`.
Use an existing compatible local docset with `--docset`/`DOCSET_ROOT`; inspect cache
configuration before writes. The upstream defaults reference a Dash Apple docset and a
user cache. Export/index operations write documentation/cache files, so choose their
scope intentionally. No license to redistribute Apple documentation follows from the
tool's MIT license. If docsets are unavailable, use official web documentation.

## xcbeautify

[xcbeautify](https://github.com/cpisciotta/xcbeautify) supports `brew install xcbeautify`
or `mint install cpisciotta/xcbeautify`. Choose the existing package manager, verify
`xcbeautify --version` and `--help`, retain raw output and use pipeline failure semantics
that preserve the build's exit status. A missing formatter never blocks a native build.

## sourcery

[Sourcery](https://github.com/krzysztofzablocki/Sourcery) supports Homebrew, release
binaries, Mint and project-level routes. Prefer the project-pinned method; otherwise
`brew install sourcery` is a documented route on supported hosts. Verify version/help,
templates, configuration and compiler compatibility. Binary installation does not
approve generated-code changes, new build phases or package plugins. Source-build and
platform support differ, so inspect upstream's chosen method, not a guessed universal
command. Keep generation deterministic and review its output.

## inject

[Inject](https://github.com/krzysztofzablocki/Inject) integrates through the project's
Swift package dependencies (or existing CocoaPods setup). It also requires the linked
InjectionIII/InjectionForXcode developer app and compatible debug settings. Review the
upstream setup for the project's compiler; approve the specific dependency, code and
debug-setting changes before applying them. Do not automatically add it to every app.
Verify an actual intended hot-reload update and keep release targets unaffected. The
machine app and project integration persist separately; do not reinstall on each use.

## ascctl

[Xopoko AppStoreConnectCLI](https://github.com/Xopoko/AppStoreConnectCLI) installs as
`ascctl`: `brew tap Xopoko/tap`, then `brew install ascctl`. Check `ascctl --help` and
its JSON `ok` result before configuration. Follow its OpenAPI operation discovery and
config/auth help. Its flags, profiles and commands are not those of `asc` below.
Installation is separate from account setup. Never echo or embed API private keys;
use the host's approved secure credential process and required user handoff/confirmation.
Check only the specifically authorized account/app after authentication is authorized.

## asc

[rorkai App Store Connect CLI](https://github.com/rorkai/App-Store-Connect-CLI) installs
as `asc`; the current Homebrew recipe is `brew install asc`. Otherwise use the official
release asset for the execution OS/architecture and verify its published integrity.
The [upstream privacy section](https://github.com/rorkai/App-Store-Connect-CLI#privacy-and-telemetry)
documents default command telemetry. Unless explicitly authorized, set process-scoped
`ASC_TELEMETRY_DISABLED=1` and `DO_NOT_TRACK=1` before **any** invocation, including
help/version; verify the selected version honors the opt-out. On POSIX shells, use
`ASC_TELEMETRY_DISABLED=1 DO_NOT_TRACK=1 asc version` and the same environment for
`asc --help` and subsequent commands. Set equivalent process environment variables on
Windows without globally changing the user environment. Windows package availability
must be checked rather than presumed. The related [rorkai playbooks](https://github.com/rorkai/app-store-connect-cli-skills)
are referenced by this skill; installing the CLI does not require installing that whole
pack again. Preserve an existing approved pack if present. Match help to the chosen
version and keep credential, signing and publication approval separate.

## rocketsim

[RocketSim CLI](https://www.rocketsim.app/docs/features/agentic-development/rocketsim-cli/)
comes with the app. In an authorized existing installation use Settings → CLI & Agent
→ Install Command Line Tool and approve the target PATH directory. This creates a
`rocketsim` symlink to the app's executable; app updates maintain it. Probe
`rocketsim doctor`, which separates CLI, app, simulator and permission readiness.
The app must be running. A purchase, app install or new accessibility permission is
not implied by choosing this adapter. It handles simulator UI, not project builds.

## codexmonitor

[CodexMonitor](https://github.com/Dimillian/CodexMonitor) is a separate agent/workspace
application. Use an existing installation only when it is the user's selected workflow;
if they request setup, inspect official release/build instructions and prerequisites
for that OS. Verify app version and the configured Codex CLI/workspace. It is not an
Apple compiler or simulator-testing prerequisite. Do not create remote services, import
sessions or replace the user's current agent harness as incidental Apple setup.

## agent-scripts

[agent-scripts](https://github.com/steipete/agent-scripts) contains independent helpers
and personal workflow material. This bundle already adapts relevant profiling method;
it does not need an install-all operation. For a specifically requested helper, inspect
the pinned file, its license/dependencies and effects, then fetch only the approved
helper into a reusable tools location. Do not import unrelated rules, hooks, credentials,
browser session access or orchestration. Native profiling uses the platform's existing
Instruments/xctrace route when adequate.

## Failure and acceptance checklist

- Existing compatible CLI + client registration: no installation and no config write
- CLI exists, MCP absent: reuse binary; propose only approved client registration
- MCP works, CLI absent from PATH: use the server; don't infer a missing capability
- Different version/pin or conflicting config: preserve it; explain and resolve explicitly
- Tool missing, setup allowed: install selected tool once, verify, continue requested task
- Setup denied, network blocked or unsupported OS: explain the exact blocker/fallback
- Second skill or second invocation: repeat lightweight checks, reuse the same setup
- Tool installed but auth absent: installation is complete, account operation remains blocked
- Successful help/server connection: setup evidence only; run the requested native checks
