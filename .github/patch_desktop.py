#!/usr/bin/env python3
"""
Patch clients/desktop configuration and scripts for sing-boxHX builds:
- Sync version.json with target release version and Go version
- Fix broken pnpm@11.13.0 packageManager pins
- Standardize artifact naming to SFW-HX and SFL-HX
- Enable optional code signing (supports building without private EV cert)
- Allow flexible Go version matching and local toolchain
"""

import os
import sys
import json
import subprocess

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

    # Determine target version
    target_version = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VERSION", "1.14.4")
    if target_version.startswith("v"):
        target_version = target_version[1:]

    # Determine local Go version
    try:
        res = subprocess.run(["go", "env", "GOVERSION"], stdout=subprocess.PIPE, text=True, check=True)
        go_ver = res.stdout.strip()
    except Exception:
        go_ver = "go1.26.10"
    if not go_ver:
        go_ver = "go1.26.10"

    # 1. Update version.json directly
    version_json_path = os.path.join(desktop_dir, "version.json")
    version_data = {
        "version": target_version,
        "go_version": go_ver
    }
    with open(version_json_path, "w", encoding="utf-8") as f:
        json.dump(version_data, f, indent=2)
    print(f"Updated {version_json_path} to version {target_version}, go {go_ver}")

    # 2. Fix broken pnpm@11.13.0 in package.json and dashboard/package.json
    for pj in [
        os.path.join(desktop_dir, "package.json"),
        os.path.join(desktop_dir, "dashboard", "package.json"),
    ]:
        if os.path.isfile(pj):
            try:
                with open(pj, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "packageManager" in data:
                    del data["packageManager"]
                with open(pj, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                print(f"Removed broken packageManager pin from {pj}")
            except Exception as e:
                print(f"Warning: failed to process {pj}: {e}")

    # 3. Patch electron-builder.yml
    eb_yml = os.path.join(desktop_dir, "electron-builder.yml")
    patch_file(eb_yml, [
        ("forceCodeSigning: true", "forceCodeSigning: false"),
        ("artifactName: SFW-${version}-${env.SFW_ARCHITECTURE}.${ext}", "artifactName: SFW-HX-${version}-${env.SFW_ARCHITECTURE}.${ext}"),
        ("artifactName: SFL-${version}-${arch}.${ext}", "artifactName: SFL-HX-${version}-${arch}.${ext}"),
        ("artifactName: SFL-${version}-${arch}.pkg.tar.zst", "artifactName: SFL-HX-${version}-${arch}.pkg.tar.zst"),
    ])

    # 4. Patch afterPack.cjs
    after_pack = os.path.join(desktop_dir, "scripts", "afterPack.cjs")
    patch_file(after_pack, [
        (
            '  if (context.electronPlatformName !== "win32") {\n    return;\n  }',
            '  if (context.electronPlatformName !== "win32") {\n    return;\n  }\n  if (!context.packager.platformSpecificBuildOptions || context.packager.platformSpecificBuildOptions.forceCodeSigning === false) {\n    return;\n  }'
        ),
        (
            '    const signed = await context.packager.signIf(executablePath);\n    if (!signed) {\n      throw new Error(`failed to sign ${relativePath.join("/")}`);\n    }',
            '    try {\n      await context.packager.signIf(executablePath);\n    } catch (e) {\n      console.warn(`Skipping code signing for ${relativePath.join("/")}: ${e}`);\n    }'
        )
    ])

    # 5. Patch package.ts
    package_ts = os.path.join(desktop_dir, "scripts", "package.ts")
    patch_file(package_ts, [
        (
            'return { ...process.env, GOTOOLCHAIN: goVersion };',
            'return { ...process.env, GOTOOLCHAIN: "local" };'
        ),
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
