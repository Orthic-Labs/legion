# winget channel per PR43. Manifest generated only after the publication guard
# allows the winget channel and a signed stable Windows binary exists.

manifest:
  Id: OrthicLabs.Legion
  Name: Legion
  Version: <VER>
  Publisher: Orthic Labs
  InstallerType: portable
  Installers:
    - Architecture: x64
      InstallerUrl: https://github.com/Orthic-Labs/legion/releases/download/v<VER>/legion-windows-x64.exe
      InstallerSha256: <SHA256>
      SignatureSha256: <SIGNED_DIGEST>

gates:
  - publication guard channel "winget" must be open before generating
  - signed PE digest bound to release attestation
