# macOS signing/notarization pipeline per SNIP-MAC-SIGN-01.
# Consumes Apple Developer ID credentials ONLY from protected release jobs.

name: Nemesis macOS signing

steps:
  - name: Codesign
    run: |
      codesign --force --options runtime --timestamp \
        --sign "$APPLE_DEVELOPER_ID" "dist/nemesis"
      codesign --verify --deep --strict --verbose=2 "dist/nemesis"
  - name: Archive
    run: |
      ditto -c -k --keepParent "dist/nemesis" "dist/nemesis-macos.zip"
  - name: Notarize
    run: |
      xcrun notarytool submit "dist/nemesis-macos.zip" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait
  - name: Assess
    run: spctl --assess --type execute --verbose=4 "dist/nemesis"

documentation:
  - "Staple only an artifact format Apple supports for stapling."
  - "Record notarization submission ID and result in the release manifest."
  - "For standalone binaries distributed in an archive, follow Apple's documented limitations rather than claiming a stapled binary ticket."
