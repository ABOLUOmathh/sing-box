#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APPLE_ROOT="$WORKSPACE_ROOT/clients/apple"

cd "$APPLE_ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  if command -v git >/dev/null 2>&1; then
    VERSION="$(git describe --tags --always 2>/dev/null || echo "1.14.3")"
    VERSION="${VERSION#v}"
  else
    VERSION="1.14.3"
  fi
fi

echo "=================================================="
echo " Packaging sing-box iOS for TrollStore / Sideload"
echo " Version: $VERSION"
echo " Target : iOS 15.0+ / 16.0+"
echo "=================================================="

# Check if Libbox.xcframework exists
if [[ ! -d "$APPLE_ROOT/Libbox.xcframework" ]]; then
  echo "Error: Libbox.xcframework not found in $APPLE_ROOT!"
  echo "Please build Libbox first with: go run ./cmd/internal/build_libbox -target apple -platform ios"
  exit 1
fi

DERIVED_DATA="$APPLE_ROOT/build/DerivedData"
rm -rf "$DERIVED_DATA"
mkdir -p "$DERIVED_DATA"

# Safety guarantee: ensure Swift 5 compatibility for deinit in ExtensionProfile.swift
if [[ -f "$APPLE_ROOT/Library/Network/ExtensionProfile.swift" ]]; then
  sed -i '' 's/nonisolated deinit/deinit/g' "$APPLE_ROOT/Library/Network/ExtensionProfile.swift" 2>/dev/null || \
  sed -i 's/nonisolated deinit/deinit/g' "$APPLE_ROOT/Library/Network/ExtensionProfile.swift" 2>/dev/null || true
fi

echo "==> Compiling SFI scheme with xcodebuild..."
xcodebuild build \
  -project sing-box.xcodeproj \
  -scheme SFI \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED_DATA" \
  -skipPackagePluginValidation \
  -skipMacroValidation \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  AD_HOC_CODE_SIGNING_ALLOWED=YES \
  ENABLE_BITCODE=NO \
  COMPILER_INDEX_STORE_ENABLE=NO

APP_SRC="$(find "$DERIVED_DATA/Build/Products/Release-iphoneos" -maxdepth 1 -name "*.app" 2>/dev/null | head -n 1)"
if [[ -z "$APP_SRC" || ! -d "$APP_SRC" ]]; then
  echo "Error: .app was not produced under $DERIVED_DATA/Build/Products/Release-iphoneos" >&2
  ls -la "$DERIVED_DATA/Build/Products" || true
  exit 1
fi
echo "==> Found app bundle at: $APP_SRC"

STAGE_DIR="$APPLE_ROOT/build/ipa_stage"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/Payload"

echo "==> Staging sing-box.app into Payload directory..."
cp -R "$APP_SRC" "$STAGE_DIR/Payload/sing-box.app"
APP_DEST="$STAGE_DIR/Payload/sing-box.app"

# Clean up signatures and provisioning profiles
rm -rf "$APP_DEST/SC_Info" "$APP_DEST/_CodeSignature" "$APP_DEST/embedded.mobileprovision"
find "$APP_DEST" -name '.DS_Store' -delete

# Sign entitlements with ldid if available
if command -v ldid >/dev/null 2>&1; then
  echo "==> Signing binaries with ldid and native entitlements..."
  MAIN_BIN="$APP_DEST/sing-box"
  if [[ ! -f "$MAIN_BIN" ]]; then
    MAIN_BIN="$(find "$APP_DEST" -maxdepth 1 -type f -perm +111 2>/dev/null | head -n 1)"
  fi
  if [[ -f "$APPLE_ROOT/SFI/SFI.entitlements" && -n "$MAIN_BIN" && -f "$MAIN_BIN" ]]; then
    ldid -S"$APPLE_ROOT/SFI/SFI.entitlements" "$MAIN_BIN"
  elif [[ -n "$MAIN_BIN" && -f "$MAIN_BIN" ]]; then
    ldid -S "$MAIN_BIN"
  fi

  if [[ -d "$APP_DEST/PlugIns" ]]; then
    for appex in "$APP_DEST/PlugIns"/*.appex; do
      if [[ -d "$appex" ]]; then
        appex_name="$(basename "$appex" .appex)"
        ent_file="$APPLE_ROOT/$appex_name/$appex_name.entitlements"
        bin_file="$appex/$appex_name"
        if [[ -f "$bin_file" ]]; then
          if [[ -f "$ent_file" ]]; then
            echo "    Signing extension $appex_name with $ent_file"
            ldid -S"$ent_file" "$bin_file"
          else
            ldid -S "$bin_file"
          fi
        fi
      fi
    done
  fi
elif command -v codesign >/dev/null 2>&1; then
  echo "==> Signing with ad-hoc codesign..."
  codesign --force --deep -s - "$APP_DEST" || true
fi

OUTPUT_DIR="$APPLE_ROOT/build"
mkdir -p "$OUTPUT_DIR"
IPA_NAME="sing-box-${VERSION}-ios-trollstore.ipa"
IPA_PATH="$OUTPUT_DIR/$IPA_NAME"

echo "==> Archiving Payload into $IPA_NAME..."
(cd "$STAGE_DIR" && zip -qry9 "$IPA_PATH" Payload)

echo "=================================================="
echo " Successfully created TrollStore IPA:"
echo " File: $IPA_PATH"
echo " Size: $(du -h "$IPA_PATH" | cut -f1)"
echo "=================================================="
