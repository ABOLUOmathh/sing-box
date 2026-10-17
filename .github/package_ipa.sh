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
  BASE_PACKAGE_IDENTIFIER="io.nekohasekai.sfa.hx" \
  APP_GROUP_IDENTIFIER="group.io.nekohasekai.sfa.hx" \
  INFOPLIST_KEY_CFBundleDisplayName="sing-boxHX" \
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

# Clean up stale signatures and provisioning profiles
rm -rf "$APP_DEST/SC_Info" "$APP_DEST/_CodeSignature" "$APP_DEST/embedded.mobileprovision" "$APP_DEST/Export.plist"
find "$APP_DEST" -name '.DS_Store' -delete

APP_ID="io.nekohasekai.sfa.hx"
APP_GROUP="group.io.nekohasekai.sfa.hx"
APP_DISPLAY_NAME="sing-boxHX"

# Expand Info.plist variables if PlistBuddy is present
if [[ -x /usr/libexec/PlistBuddy ]]; then
  /usr/libexec/PlistBuddy -c "Set :BasePackageIdentifier ${APP_ID}" "$APP_DEST/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :AppGroupIdentifier ${APP_GROUP}" "$APP_DEST/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName ${APP_DISPLAY_NAME}" "$APP_DEST/Info.plist" 2>/dev/null || \
  /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string ${APP_DISPLAY_NAME}" "$APP_DEST/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleName ${APP_DISPLAY_NAME}" "$APP_DEST/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${APP_ID}" "$APP_DEST/Info.plist" 2>/dev/null || true
  if [[ -d "$APP_DEST/PlugIns" ]]; then
    for appex in "$APP_DEST/PlugIns"/*.appex; do
      if [[ -d "$appex" ]]; then
        appex_name="$(basename "$appex" .appex)"
        /usr/libexec/PlistBuddy -c "Set :BasePackageIdentifier ${APP_ID}" "$appex/Info.plist" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c "Set :AppGroupIdentifier ${APP_GROUP}" "$appex/Info.plist" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${APP_ID}.${appex_name}" "$appex/Info.plist" 2>/dev/null || true
      fi
    done
  fi
fi

# Generate concrete, verified entitlements XML without unresolved build variables

cat <<EOF > "$STAGE_DIR/App.entitlements"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider</string>
	</array>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${APP_GROUP}</string>
	</array>
	<key>get-task-allow</key>
	<false/>
</dict>
</plist>
EOF

cat <<EOF > "$STAGE_DIR/Extension.entitlements"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider</string>
	</array>
	<key>com.apple.developer.networking.wifi-info</key>
	<true/>
	<key>com.apple.developer.networking.multicast</key>
	<true/>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${APP_GROUP}</string>
	</array>
	<key>get-task-allow</key>
	<false/>
</dict>
</plist>
EOF

cat <<EOF > "$STAGE_DIR/GenericExtension.entitlements"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${APP_GROUP}</string>
	</array>
	<key>get-task-allow</key>
	<false/>
</dict>
</plist>
EOF

echo "==> Signing all Mach-O binaries in Frameworks and subdirectories..."
# Sign all frameworks directly
if [[ -d "$APP_DEST/Frameworks" ]]; then
  for fw in "$APP_DEST/Frameworks"/*; do
    if [[ -d "$fw" && "$fw" =~ \.framework$ ]]; then
      fw_name="$(basename "$fw" .framework)"
      fw_bin="$fw/$fw_name"
      if [[ -f "$fw_bin" ]]; then
        echo "    Signing framework: $fw_name"
        command -v ldid >/dev/null 2>&1 && ldid -S "$fw_bin"
        command -v codesign >/dev/null 2>&1 && codesign -f -s - "$fw" 2>/dev/null || true
      fi
    elif [[ -f "$fw" && "$fw" =~ \.dylib$ ]]; then
      echo "    Signing dylib: $(basename "$fw")"
      command -v ldid >/dev/null 2>&1 && ldid -S "$fw"
      command -v codesign >/dev/null 2>&1 && codesign -f -s - "$fw" 2>/dev/null || true
    fi
  done
fi

# Find and sign any other Mach-O files (dylibs, helper binaries)
while IFS= read -r macho; do
  [[ -z "$macho" ]] && continue
  if [[ "$macho" == "$APP_DEST/sing-box" ]]; then continue; fi
  if [[ "$macho" =~ \.appex/ ]]; then continue; fi
  if file -b "$macho" | grep -q "Mach-O"; then
    echo "    Ad-hoc signing: $(basename "$macho")"
    command -v ldid >/dev/null 2>&1 && ldid -S "$macho"
    command -v codesign >/dev/null 2>&1 && codesign -f -s - "$macho" 2>/dev/null || true
  fi
done < <(find "$APP_DEST" -type f)

# Sign Extensions with concrete entitlements
if [[ -d "$APP_DEST/PlugIns" ]]; then
  for appex in "$APP_DEST/PlugIns"/*.appex; do
    if [[ -d "$appex" ]]; then
      appex_name="$(basename "$appex" .appex)"
      bin_file="$appex/$appex_name"
      if [[ -f "$bin_file" ]]; then
        # Sign any frameworks inside extension
        if [[ -d "$appex/Frameworks" ]]; then
          for efw in "$appex/Frameworks"/*; do
            if [[ -d "$efw" && "$efw" =~ \.framework$ ]]; then
              efw_bin="$efw/$(basename "$efw" .framework)"
              [[ -f "$efw_bin" ]] && command -v ldid >/dev/null 2>&1 && ldid -S "$efw_bin"
              command -v codesign >/dev/null 2>&1 && codesign -f -s - "$efw" 2>/dev/null || true
            fi
          done
        fi
        if [[ "$appex_name" == "Extension" ]]; then
          echo "    Signing Extension with Extension.entitlements"
          command -v ldid >/dev/null 2>&1 && ldid -S"$STAGE_DIR/Extension.entitlements" "$bin_file"
          command -v codesign >/dev/null 2>&1 && codesign -f -s - --entitlements "$STAGE_DIR/Extension.entitlements" "$appex" 2>/dev/null || true
        else
          echo "    Signing $appex_name with GenericExtension.entitlements"
          command -v ldid >/dev/null 2>&1 && ldid -S"$STAGE_DIR/GenericExtension.entitlements" "$bin_file"
          command -v codesign >/dev/null 2>&1 && codesign -f -s - --entitlements "$STAGE_DIR/GenericExtension.entitlements" "$appex" 2>/dev/null || true
        fi
      fi
    fi
  done
fi

# Sign Main Executable with concrete App.entitlements
MAIN_BIN="$APP_DEST/sing-box"
if [[ ! -f "$MAIN_BIN" ]]; then
  MAIN_BIN="$(find "$APP_DEST" -maxdepth 1 -type f | while read -r f; do file -b "$f" | grep -q "Mach-O" && echo "$f" && break; done)"
fi
echo "==> Signing main executable with App.entitlements: $(basename "$MAIN_BIN")"
command -v ldid >/dev/null 2>&1 && ldid -S"$STAGE_DIR/App.entitlements" "$MAIN_BIN"

# Final deep codesign pass
if command -v codesign >/dev/null 2>&1; then
  echo "==> Applying final deep signature with codesign..."
  codesign --force --deep -s - --entitlements "$STAGE_DIR/App.entitlements" "$APP_DEST" 2>/dev/null || true
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
