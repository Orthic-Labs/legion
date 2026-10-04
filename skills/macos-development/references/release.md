# Release preparation and authorized execution

## Read the existing release contract

Identify product/bundle IDs, targets, supported architectures/OS versions, distribution
channel, signing settings, entitlements, provisioning method, version/build numbers,
archive/export commands, and CI ownership. Preserve the established release pipeline,
including Cargo/Tauri or project-specific tools. Do not create a second signing system.

## Local preparation

- Review least-privilege entitlements, privacy usage descriptions, declared privacy
  manifests where applicable, and resources. Compare declared capabilities with actual
  code and the chosen distribution route; do not add blanket exceptions.
- Build/test the intended release configuration. An unsigned build can validate some
  compilation/packaging stages, but it cannot prove signing, installation, notarization,
  store acceptance, or operation under the actual distribution restrictions.
- Check version metadata and archive contents. Confirm the selected scheme produces the
  requested app and includes the right assets, extensions, symbols, and architectures.
- For iOS, distinguish simulator, physical-device, archive, export, TestFlight upload, and
  App Store submission. Each is a separate state with different evidence/authority.
- For macOS, distinguish a local app bundle, signed app, notarized/stapled artifact,
  installer, and distribution channel. Mac App Store and Developer ID constraints differ.
- Test install/launch/update and relevant sandbox/permission behavior using isolated
  test state when a suitable authorized Mac/device environment is available.

## Authority and credentials

The skill never grants permission to sign, access developer accounts, create credentials,
alter certificates/profiles, accept agreements, upload binaries or metadata, submit for
review, publish, buy services, or change app/account settings. Check the live request and
applicable Legion/host policy before the relevant effect. Keep credentials out of chat,
source, scripts, logs, and generated artifacts; use the approved secure mechanism.

AppStoreConnectCLI is a task-selected adapter. Reuse an available compatible installation;
if missing, follow [tool setup](tool-setup.md) to propose authorized one-time setup.
Xopoko's AppStoreConnectCLI uses ascctl and an OpenAPI-oriented workflow; rorkai's
app-store-connect-cli-skills describe a different asc CLI. Detect the installed tool and
version; their command syntax and authentication assumptions are not interchangeable.
Discover its actual command/version and inspect a read-only status first. Confirm app,
team, version/build, destination and intended action before a consequential mutation;
absence of the adapter requires a concrete setup proposal or a supported existing alternative,
while useful local preparation continues. Installation does not authorize account access.

Do not disable code-signing, Gatekeeper, sandboxing, library validation, or macro security
to force success. Explain the concrete blocker and smallest supported next step.

## Completion evidence

Report the exact artifact and requested state reached, with build/validation results and
unrun stages. Successful transport/upload does not mean processing, review, approval, or
publication succeeded. Follow the specific authorized operation to its requested terminal
state or report the blocker; do not infer completion from an intermediate receipt.

Primary documentation: https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases
and https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
