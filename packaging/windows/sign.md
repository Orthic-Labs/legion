# Windows signing contract: windows-raw-exe-authenticode-before-portable-v1.
# Uses Microsoft Artifact Signing/SignTool with RFC3161 timestamping.

## Target identity

Each invocation must select exactly one target. The archive name, release
identity, signing receipt, and release architecture must agree:

| Legion architecture | Cargo target | Release architecture | signed file |
| --- | --- | --- | --- |
| `x86_64` | `x86_64-pc-windows-msvc` | `x64` | `bin\legion.exe` |
| `arm64` | `aarch64-pc-windows-msvc` | `arm64` | `bin\legion.exe` |

Never infer target identity from a host architecture or a filename. All three
raw EXEs are fully patched before signing, then copied byte-for-byte into the
portable ZIP. A receipt is valid only when it records exactly three files with
`Authenticode: Valid`, subject `CN=Damned Ventures LLC`, a trusted timestamp,
and each final SHA-256.

Signing inputs use canonical `sign-windows.mjs` environment names:
`AZURE_ARTIFACT_SIGNING_DLIB_PATH`, `AZURE_ARTIFACT_SIGNING_METADATA`,
`AZURE_ARTIFACT_SIGNING_ENDPOINT`, `AZURE_ARTIFACT_SIGNING_ACCOUNT`, and
`AZURE_ARTIFACT_SIGNING_PROFILE`.

name: Legion Windows signing

steps:
  - name: Sign
    run: |
      signtool.exe sign `
        /v /debug `
        /fd SHA256 `
        /tr "http://timestamp.acs.microsoft.com" `
        /td SHA256 `
        /dlib "$env:AZURE_ARTIFACT_SIGNING_DLIB_PATH" `
        /dmdf "$env:AZURE_ARTIFACT_SIGNING_METADATA" `
        "dist\native\windows-x86_64\legion-<version>\bin\legion.exe"
  - name: Verify
    run: signtool.exe verify /pa /all /v "dist\native\windows-x86_64\legion-<version>\bin\legion.exe"

For ARM64, run same two steps against
`dist\native\windows-arm64\legion-<version>\bin\legion.exe` & select the
`aarch64-pc-windows-msvc` target at assembly time.

receipt:
  path: .right-release/receipts/windows-<architecture>-raw-exe.json
  requiredFields: [schema, files, file, after.sha256, authenticode, subject, timestampPresent]
  requiredFileCount: 3
  requiredValues:
    schema: 1
    authenticode: Valid
    subject: "CN=Damned Ventures LLC"
    timestampPresent: true

portablePackage:
  command: pnpm windows:package -- --architecture x86_64 --signature-receipt .right-release/receipts/windows-x86_64-raw-exe.json --require-signature
  alternateCommand: pnpm windows:package -- --architecture arm64 --signature-receipt .right-release/receipts/windows-arm64-raw-exe.json --require-signature
  archive: legion-<version>-windows-<architecture>.zip
  channel: BLOCKED_UNTIL_QUALIFIED

failClosed:
  - "Missing signtool.exe, Azure signing client, metadata, identity, or timestamp fails the step."
  - "A missing, stale, invalid, or digest-mismatched receipt never becomes signed evidence."
  - "Unsigned/local-build provenance remains blocked and cannot produce a publication grant."

documentation:
  - "The release job must use the current Microsoft Artifact Signing integration metadata."
  - "Verify the downloaded final artifact, not only the pre-upload path."
  - "Bind the signed digest, target triple, provenance, and qualification receipt to the release manifest."
