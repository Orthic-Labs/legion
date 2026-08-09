# Homebrew channel per PR43. Generated only after the publication guard allows
# the homebrew channel. Formula points to signed, checksummed releases.

formula:
  name: legion
  tap: orthic-labs/homebrew-legion
  desc: Evidence-governed whole-repository audit engine
  homepage: https://github.com/Orthic-Labs/legion
  license: SEE LICENSE IN LICENSE
  on_macos:
    - url: https://github.com/Orthic-Labs/legion/releases/download/v<VER>/legion-macos.zip
      sha256: <SHA256>
  on_linux:
    - url: https://github.com/Orthic-Labs/legion/releases/download/v<VER>/legion-linux-<ARCH>.tar.gz
      sha256: <SHA256>

gates:
  - publication guard channel "homebrew" must be open before generating
  - checksums and SBOMs recorded in release provenance
