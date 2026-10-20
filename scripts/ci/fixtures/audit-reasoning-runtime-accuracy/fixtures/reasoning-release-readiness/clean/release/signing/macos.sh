#!/bin/sh
set -eu
: "${APP:?}" "${APPLE_SIGNING_ID:?}" "${APPLE_CERT_BASE64:?}" "${APPLE_CERT_PASSWORD:?}" "${APPLE_ID:?}" "${APPLE_PASSWORD:?}" "${APPLE_TEAM_ID:?}"
KEYCHAIN="$RUNNER_TEMP/signing.keychain-db"
CERT="$RUNNER_TEMP/signing.p12"
KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
trap 'security delete-keychain "$KEYCHAIN"; rm -f "$CERT"' EXIT
printf '%s' "$APPLE_CERT_BASE64" | base64 --decode > "$CERT"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$CERT" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
codesign --force --options runtime --timestamp --entitlements release/macos.entitlements --keychain "$KEYCHAIN" --sign "$APPLE_SIGNING_ID" "$APP"
codesign --verify --strict "$APP"
ditto -c -k --keepParent "$APP" "$RUNNER_TEMP/notarize.zip"
xcrun notarytool submit "$RUNNER_TEMP/notarize.zip" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
xcrun stapler staple "$APP"
