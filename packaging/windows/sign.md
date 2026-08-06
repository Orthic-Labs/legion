# Windows signing pipeline per SNIP-WIN-SIGN-01.
# Uses Microsoft Artifact Signing/SignTool with RFC3161 timestamping.

name: Nemesis Windows signing

steps:
  - name: Sign
    run: |
      signtool.exe sign `
        /v /debug `
        /fd SHA256 `
        /tr "http://timestamp.acs.microsoft.com" `
        /td SHA256 `
        /dlib "$env:ARTIFACT_SIGNING_DLIB" `
        /dmdf "$env:ARTIFACT_SIGNING_METADATA" `
        "dist\nemesis.exe"
  - name: Verify
    run: signtool.exe verify /pa /all /v "dist\nemesis.exe"

documentation:
  - "The release job must use the current Microsoft Artifact Signing integration metadata."
  - "Verify the downloaded final artifact, not only the pre-upload path."
  - "Bind the signed digest to the release attestation."
