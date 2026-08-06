# Homebrew channel per PR43. Generated only after the publication guard allows
# the homebrew channel. Formula points to signed, checksummed releases.

formula:
  name: nemesis
  tap: orthic-labs/homebrew-nemesis
  desc: Evidence-governed whole-repository audit engine
  homepage: https://github.com/Orthic-Labs/nemesis
  license: SEE LICENSE IN LICENSE
  on_macos:
    - url: https://github.com/Orthic-Labs/nemesis/releases/download/v<VER>/nemesis-macos.zip
      sha256: <SHA256>
  on_linux:
    - url: https://github.com/Orthic-Labs/nemesis/releases/download/v<VER>/nemesis-linux-<ARCH>.tar.gz
      sha256: <SHA256>

gates:
  - publication guard channel "homebrew" must be open before generating
  - checksums and SBOMs recorded in release provenance
