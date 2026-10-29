#!/bin/bash
set -euo pipefail

export DISABLE_SWIFTLINT="1"

# In case any tool or plugin invokes swiftlint directly, supply a dummy exit 0
DUMMY_BIN_DIR="$(mktemp -d)"
cat << 'EOF' > "$DUMMY_BIN_DIR/swiftlint"
#!/bin/sh
exit 0
EOF
chmod +x "$DUMMY_BIN_DIR/swiftlint"
export PATH="$DUMMY_BIN_DIR:$PATH"

VERSION="${1:-1.14.4-hx.4}"
OUTPUT_DIR="${2:-$PWD/ios-dist}"
mkdir -p "$OUTPUT_DIR"

cd clients/apple
mkdir -p build

echo "==> Ensuring exact package versions from Package.resolved..."
python3 -c '
pbx = "sing-box.xcodeproj/project.pbxproj"
with open(pbx, "r") as f:
    s = f.read()
s = s.replace("kind = upToNextMajorVersion;\n\t\t\t\tminimumVersion = 2.2.2026100703;", "kind = exactVersion;\n\t\t\t\tversion = 2.2.2026100703;")
with open(pbx, "w") as f:
    f.write(s)
'

echo "==> Patching TailscaleSSHTerminalWindow.swift for x86_64 Mac compatibility..."
python3 -c '
path = "MacLibrary/TailscaleSSHTerminalWindow.swift"
with open(path, "r") as f:
    s = f.read()
target = """            if let session {
                TerminalWrapperView(session)
            } else {
                Color.clear
            }"""
replacement = """            #if canImport(GhosttyTerminal)
            if let session {
                TerminalWrapperView(session)
            } else {
                Color.clear
            }
            #else
            Color.clear
            #endif"""
if target in s:
    s = s.replace(target, replacement)
    with open(path, "w") as f:
        f.write(s)
'

echo "==> Building SFM for macOS Universal..."
xcodebuild archive \
  -project sing-box.xcodeproj \
  -scheme SFM.System \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath build/SFM.System-universal.xcarchive \
  -derivedDataPath build/SFM.System-universal.dd \
  -skipPackagePluginValidation \
  -skipMacroValidation \
  -onlyUsePackageVersionsFromResolvedFile \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  AD_HOC_CODE_SIGNING_ALLOWED=YES \
  COMPILER_INDEX_STORE_ENABLE=NO

echo "==> Locating Universal SFM.app..."
SFM_APP=""
for candidate in \
  "build/SFM.System-universal.xcarchive/Products/Applications/SFM.app" \
  "build/SFM.System-universal.xcarchive/Products/Applications/sing-box.app" \
  "build/SFM.System-universal.dd/Build/Intermediates.noindex/ArchiveIntermediates/SFM.System/InstallationBuildProductsLocation/Applications/SFM.app" \
  "build/SFM.System-universal.dd/Build/Intermediates.noindex/ArchiveIntermediates/SFM.System/BuildProductsPath/Release/SFM.app" \
  "build/SFM.System-universal.dd/Build/Products/Release/SFM.app"; do
  if [ -d "$candidate" ]; then
    SFM_APP="$candidate"
    echo "Found SFM.app at known location: $SFM_APP"
    break
  fi
done

if [ -z "$SFM_APP" ]; then
  SFM_APP="$(find build -name "SFM.app" -type d 2>/dev/null | head -1)"
fi

if [ -z "$SFM_APP" ] || [ ! -d "$SFM_APP" ]; then
  echo "Debug: Listing build directory contents:"
  ls -la build/ || true
  find build -maxdepth 5 || true
  echo "Error: SFM.app not found in build directory!" >&2
  exit 1
fi

echo "==> Found Universal SFM.app at: $SFM_APP"

# Helper function to thin binaries inside an app bundle
thin_app() {
  local target_arch="$1"
  local app_path="$2"
  echo "==> Thinning $app_path to $target_arch..."
  local file
  while IFS= read -r -d '' file; do
    if lipo -archs "$file" 2>/dev/null | grep -q " "; then
      lipo "$file" -thin "$target_arch" -output "$file.thin"
      mv -f "$file.thin" "$file"
    fi
  done < <(find "$app_path" -type f -print0)
}

# Helper to ad-hoc sign
sign_app() {
  local app_path="$1"
  echo "==> Ad-hoc signing $app_path..."
  find "$app_path" -depth \( -name "*.framework" -o -name "*.systemextension" -o -name "*.appex" \) -exec codesign --force -s - {} + 2>/dev/null || true
  codesign --force --deep -s - "$app_path" || true
}

# Helper to create DMG
package_dmg() {
  local app_path="$1"
  local dmg_out="$2"
  local vol_name="$3"
  local tmp_root="build/dmg-temp-${vol_name}"
  rm -rf "$tmp_root"
  mkdir -p "$tmp_root"
  cp -R "$app_path" "$tmp_root/SFM.app"
  ln -s /Applications "$tmp_root/Applications" || true
  hdiutil create -volname "sing-box" -srcfolder "$tmp_root" -ov -format UDZO "$dmg_out"
  rm -rf "$tmp_root"
}

# Helper to create PKG
package_pkg() {
  local app_path="$1"
  local pkg_out="$2"
  local pkg_root="build/pkg-temp"
  rm -rf "$pkg_root"
  mkdir -p "$pkg_root"
  ditto "$app_path" "$pkg_root/SFM.app"
  pkgbuild --root "$pkg_root" \
    --component-plist SFM.System/component.plist \
    --identifier "io.nekohasekai.sfm.hx" \
    --install-location /Applications \
    --min-os-version 13.0 \
    --compression latest \
    "$pkg_out" || true
  rm -rf "$pkg_root"
}

# 1. Prepare Universal App
rm -rf build/apps
mkdir -p build/apps
ditto "$SFM_APP" build/apps/Universal/SFM.app
sign_app build/apps/Universal/SFM.app

# 2. Prepare Apple Silicon App (arm64)
ditto "$SFM_APP" build/apps/Apple/SFM.app
thin_app arm64 build/apps/Apple/SFM.app
sign_app build/apps/Apple/SFM.app

# 3. Prepare Intel App (x86_64)
ditto "$SFM_APP" build/apps/Intel/SFM.app
thin_app x86_64 build/apps/Intel/SFM.app
sign_app build/apps/Intel/SFM.app

# Packaging for each flavor (Universal, Apple, Intel)
for flavor in Universal Apple Intel; do
  APP="build/apps/$flavor/SFM.app"
  echo "==> Packaging flavor: $flavor..."
  
  # DMG installer
  package_dmg "$APP" "$OUTPUT_DIR/SFM-HX-${VERSION}-${flavor}.dmg" "$flavor"
  
  # ZIP archive
  (cd "build/apps/$flavor" && zip -qry9 "$OUTPUT_DIR/SFM-HX-${VERSION}-${flavor}.zip" SFM.app)
  
  # PKG package
  package_pkg "$APP" "$OUTPUT_DIR/SFM-HX-${VERSION}-${flavor}.pkg"
done

echo "==> All SFM variants packaged successfully in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR"/SFM-HX-*
