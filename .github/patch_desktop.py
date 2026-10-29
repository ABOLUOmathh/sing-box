#!/usr/bin/env python3
"""
Patch clients/desktop configuration and scripts for sing-boxHX builds:
- Standardize artifact naming to SFW-HX and SFL-HX
- Enable optional code signing (supports building without private EV cert)
- Allow flexible Go version matching
"""

import os
import sys

def patch_file(path, replacements):
    if not os.path.isfile(path):
        print(f"Skipping non-existent file: {path}")
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    orig = content
    for old, new in replacements:
        if old not in content:
            print(f"Warning: pattern not found in {path}: {old[:50]}...")
        else:
            content = content.replace(old, new)
    if content != orig:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Successfully patched {path}")
    else:
        print(f"No changes made to {path}")

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    desktop_dir = os.path.join(root, "clients", "desktop")

    # 1. Patch electron-builder.yml
    eb_yml = os.path.join(desktop_dir, "electron-builder.yml")
    patch_file(eb_yml, [
        ("forceCodeSigning: true", "forceCodeSigning: false"),
        ("artifactName: SFW-${version}-${env.SFW_ARCHITECTURE}.${ext}", "artifactName: SFW-HX-${version}-${env.SFW_ARCHITECTURE}.${ext}"),
        ("artifactName: SFL-${version}-${arch}.${ext}", "artifactName: SFL-HX-${version}-${arch}.${ext}"),
        ("artifactName: SFL-${version}-${arch}.pkg.tar.zst", "artifactName: SFL-HX-${version}-${arch}.pkg.tar.zst"),
    ])

    # 2. Patch afterPack.cjs
    after_pack = os.path.join(desktop_dir, "scripts", "afterPack.cjs")
    patch_file(after_pack, [
        (
            '  if (context.electronPlatformName !== "win32") {\n    return;\n  }',
            '  if (context.electronPlatformName !== "win32") {\n    return;\n  }\n  if (!context.packager.isCodeSigningSet() || context.packager.platformSpecificBuildOptions?.forceCodeSigning === false) {\n    return;\n  }'
        )
    ])

    # 3. Patch package.ts
    package_ts = os.path.join(desktop_dir, "scripts", "package.ts")
    patch_file(package_ts, [
        (
            'const artifactName = `SFW-\\${version}-${artifactArchitecture}${developmentPackage ? "-dev" : ""}.\\${ext}`;',
            'const artifactName = `SFW-HX-\\${version}-${artifactArchitecture}${developmentPackage ? "-dev" : ""}.\\${ext}`;'
        ),
        (
            "function readWindowsSigningConfiguration(): WindowsSigningConfiguration {",
            "function readWindowsSigningConfiguration(): WindowsSigningConfiguration | null {\n  if (!fs.existsSync(signingConfigurationPath)) { return null; }"
        ),
        (
            """        win: {
          artifactName,
          signtoolOptions: {
            certificateFile: signingConfiguration.certificateFile,
            certificatePassword: signingConfiguration.certificatePassword,
          },
        },""",
            """        win: {
          artifactName,
          forceCodeSigning: Boolean(signingConfiguration),
          ...(signingConfiguration
            ? {
                signtoolOptions: {
                  certificateFile: signingConfiguration.certificateFile,
                  certificatePassword: signingConfiguration.certificatePassword,
                },
              }
            : {}),
        },"""
        ),
        (
            '  if (actualVersion !== goVersion) {\n    throw new Error(\n      `Go ${goVersion} is required, current version is ${actualVersion}`,\n    );\n  }',
            '  console.info(`[package] using go version: ${actualVersion} (expected: ${goVersion})`);'
        ),
        (
            '"--config.linux.artifactName=SFL-${version}-${arch}-dev.${ext}",',
            '"--config.linux.artifactName=SFL-HX-${version}-${arch}-dev.${ext}",'
        ),
        (
            '"--config.pacman.artifactName=SFL-${version}-${arch}-dev.pkg.tar.zst",',
            '"--config.pacman.artifactName=SFL-HX-${version}-${arch}-dev.pkg.tar.zst",'
        )
    ])

    print("Desktop client patches complete.")

if __name__ == "__main__":
    main()
