# macOS signing/notarization pipeline per SNIP-MAC-SIGN-01.
# Consumes Apple Developer ID credentials ONLY from protected release jobs.

name: Legion macOS signing

steps:
  - name: Codesign
    run: |
      codesign --force --options runtime --timestamp \
        --sign "$APPLE_DEVELOPER_ID" "dist/legion"
      codesign --verify --deep --strict --verbose=2 "dist/legion"
  - name: Archive
    run: |
      ditto -c -k --keepParent "dist/legion" "dist/legion-macos.zip"
  - name: Notarize
    run: |
      xcrun notarytool submit "dist/legion-macos.zip" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait
  - name: Assess
    run: spctl --assess --type execute --verbose=4 "dist/legion"

documentation:
  - "Staple only an artifact format Apple supports for stapling."
  - "Record notarization submission ID and result in the release manifest."
  - "For standalone binaries distributed in an archive, follow Apple's documented limitations rather than claiming a stapled binary ticket."
