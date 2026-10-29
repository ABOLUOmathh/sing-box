# sing-boxHX

<p align="center">
  <strong>基于 sing-box 深度定制的全协议、全平台通用代理核心与独立双开客户端生态</strong>
</p>

<p align="center">
  <a href="https://github.com/ABOLUOmathh/sing-box/releases"><img src="https://img.shields.io/github/v/release/ABOLUOmathh/sing-box?label=Release&color=3282B8" alt="GitHub release"></a>
  <a href="https://github.com/ABOLUOmathh/sing-box/actions"><img src="https://img.shields.io/badge/CI%2FCD-29%20Matrix%20Passed%20%E2%9C%93-brightgreen" alt="Build Status"></a>
  <a href="https://github.com/ABOLUOmathh/sing-box/releases"><img src="https://img.shields.io/badge/Assets-131%2B%20Full%20Matrix-blueviolet" alt="Assets"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-orange.svg" alt="License"></a>
</p>

---

## 📖 项目简介 (Overview)

**sing-boxHX** 是基于官方 [sing-box](https://github.com/SagerNet/sing-box) **v1.14.4** 深度适配与定制的高性能通用代理平台。

针对原版在专有协议支持、客户端独立双开、iOS 巨魔免签生态以及路由器架构适配上的局限性，**sing-boxHX** 实现了底层协议原生编译、全平台全架构自动化交付，并在 iOS 与 Android 端提供了与官方原版完全隔离的专属客户端。

---

## 🌟 核心特性与适配协议 (Supported Protocols)

### 1. 专有增强协议原生支持 (Native Custom Protocols)
- **Enhanced VLESS (VLESS-EH)**:
  - 完整支持 REALITY + `xtls-rprx-vision` 流控。
  - 内置 MD5 `e` 动态握手认证与服务端 `h` 令牌回写拦截更新。
  - **抗量子阻断增强**：智能检测并抑制 `X25519MLKEM768` (ID 4588) 后量子扩展，防止 REALITY 首包因协商扩展过长遭运营商阻断。
- **OneSocks**:
  - 原生实现自定义 AES-CTR 流加密与 MD5 密钥推导 (KDF)。
  - 首包包含 `MD5(password + "_onesocks")` 校验头与目的地址无缝写入。
  - 完整支持 Native UDP 报文与 UOT (UDP over TCP) 双隧道模式。
- **HeySocks XHTTP**:
  - 专有 xstream 传输协议与 AES-128-CTR 加密。
  - 128 字节 fake-net bootstrap 引导帧握手。
  - 完整支持 TCP、Native UDP 与 UOT 隧道。
- **Shadowsocks 2022 (BLACKSTONE)**:
  - 深度兼容 `2022-blake3-aes-128-gcm`。
  - 自动解析 `identityPSK:masterPSK#BLACKSTONE`。
  - 挂载 27 字节 fixedPlain 附带 `MD5(base64(masterPSK))` 校验头，缺少显式 UDP 配置时自动启用 UOT。

### 2. 智能双通道真实网络测速 (Smart Dual-Channel Latency Testing)
- **直连节点 (`DIRECT`)**：自动测速百度（connect 延迟 10~25ms），告别原本直连测 Google 导致的超时红标。
- **代理节点**：智能测速 Google gstatic（真实网络往返延迟 60~80ms），精准反映节点跨国链路质量。

---

## 📱 移动端客户端生态 (Mobile Client Ecosystem)

### 🍏 iOS 苹果端 (TrollStore 巨魔免签独立客户端)
- **包名与显示名**：包名 `io.nekohasekai.sfa.hx`，应用显示名 `sing-boxHX`。
- **独立双开**：与 App Store / TestFlight 原版官方应用完全隔离共存，互不覆盖配置。
- **全套系统权限**：内置完整 VPN Entitlements（`networkextension`、`packet-tunnel-provider`、`extended-virtual-addressing`），通过 TrollStore 导入即可免签名获得原生 VPN 系统级代理能力。
- **质感视觉与稳定性**：
  - 独家集成 Ghostty 终端高质感视觉主题。
  - 配备 `GhosttyThemeFallbackPickerView` 防崩溃兜底选择器，保证在 iOS 15.0 ~ 18+ 全环境稳定运行不闪退。
- **产物形态**：
  - `SFI-HX-*-trollstore.ipa`（首选，TrollStore 导入）
  - `SFI-HX-*-iphoneos-arm64.deb` / `arm64e.deb`（越狱环境）
  - `Libbox-HX-*.xcframework.zip`（供第三方 Swift/Obj-C 开发者集成）

### 🤖 Android 安卓端 (SFA 专属客户端)
- **包名与显示名**：应用包名 (`applicationId`) `io.nekohasekai.sfa.hx`，应用显示名称 `sing-boxHX`。
- **独立双开**：ContentProvider 与各大组件 Authority 全局重命名，与官方 SFA 客户端完全共存。
- **永久签名锁定（平滑覆盖更新）**：
  - 锁定专用持久化签名密钥库（`.github/sing-box-hx.keystore`，证书有效期至 **2054 年**）。
  - 后续所有大版本、小版本或在线自更新均保持签名 100% 一致，**直接点击即可无缝平滑覆盖更新**，节点与配置永不丢失。
- **去官方化自更新系统**：
  - `GitHubUpdateChecker.kt` 接口已重定向至 [ABOLUOmathh/sing-box](https://github.com/ABOLUOmathh/sing-box/releases)。
  - 发布流程自动挂载 `SFA-version-metadata.json`，应用内“检查更新”只会拉取自定义构建产物，不再跳转回官方原版。
  - 静默启动更新提示，避免扰民弹窗。
- **免 Root 声明与使用建议**：
  > [!TIP]
  > **日常使用标准 VPN 模式 100% 免 Root**（配置内包含标准 tun 入站即可）。
  > 仅在以下情况系统才会请求权限：① 开启了针对硬核玩家的「自动重定向 / Auto Redirect」(iptables 模式)；② 在 Android 11+ 上开启「分应用代理」且未配置 Shizuku。日常保持默认设置即可安全免 Root 运行。

---

## 📦 全平台全架构资产矩阵 (140+ Full Matrix Assets)

本项目的 GitHub Actions CI/CD 流水线对齐官方全量标准，单次发布涵盖 **140+ 个构建资产**（实现 Android / iOS / Windows / macOS / Linux 五大图形客户端全套对齐）：

| 平台 / 系统 | 架构 / 格式 | 主要资产文件说明 |
| :--- | :--- | :--- |
| **Android 客户端 (SFA-HX)** | arm64-v8a, universal, armeabi-v7a, x86_64, x86 | `SFA-HX-*-arm64-v8a.apk`, `universal.apk` 及动态库 `Libbox-HX-*.aar`, 自更新元数据 `SFA-version-metadata.json` |
| **Android 独立内核** | arm64, arm, amd64, 386 | `sing-box-*-android-arm64.tar.gz` 等（适配 Magisk / KernelSU / ShellCrash / Termux 独立透明代理运行） |
| **iOS 客户端 (SFI-HX)** | arm64, arm64e | `SFI-HX-*-trollstore.ipa`, 越狱 `SFI-HX-*.deb`, `Libbox-HX-*.xcframework.zip` |
| **Windows 桌面端 (SFW-HX)** | x64 安装程序 (`.exe`) + CLI (`.zip`) | `SFW-HX-*-x64.exe` 图形客户端安装包；`sing-box-*-windows-amd64.zip`、`arm64.zip` 独立内核 |
| **macOS 桌面端 (SFM-HX)** | Universal (`.dmg` & `.zip`) + CLI (`.tar.gz`) | `SFM-HX-*-Universal.dmg` 与 `.zip`（原生状态栏图形应用，适配 M1~M4 与 Intel）；`darwin-arm64.tar.gz` 独立内核 |
| **Linux 桌面端 (SFL-HX)** | x64 (`.deb`, `.rpm`, `.pkg.tar.zst`) | `SFL-HX-*-amd64.deb`、`x86_64.rpm`、`x64.pkg.tar.zst` 桌面客户端（带 Wayland 托盘与 polkit 提权） |
| **OpenWrt 路由器** | **31 种微架构全覆盖** (兼具 `.ipk` 与新版 `.apk`) | 涵盖 MT7621/mipsel、AR9331、IPQ4019/807x、Cortex-A53/A72/A76、x86_64、LoongArch、RISC-V 等所有软硬路由芯片 |
| **Debian / Ubuntu** | 全 CPU 架构 (`.deb`) | `sing-box_*_linux_amd64.deb`, `arm64.deb`, `mipsel.deb`, `riscv64.deb` 等（自带 systemd 服务） |
| **CentOS / RHEL** | 全 CPU 架构 (`.rpm`) | `sing-box_*_linux_x86_64.rpm`, `aarch64.rpm`, `mipsel.rpm` 等 |
| **Arch Linux** | Pacman (`.pkg.tar.zst`) | `sing-box_*_linux_x86_64.pkg.tar.zst`, `aarch64.pkg.tar.zst`, `armv7hl.pkg.tar.zst` |
| **Alpine Linux** | Alpine (`.apk`) | `sing-box_*_linux_x86_64.apk`, `aarch64.apk`, `riscv64.apk` 等 |
| **BSD 操作系统** | FreeBSD, OpenBSD (`.tar.gz`) | `sing-box-*-freebsd-amd64.tar.gz`, `arm64.tar.gz`, `openbsd-amd64.tar.gz` 等 |

所有发布的资产包及其校验值可在每次发布的 `sha256sums.txt` 中核对。

---

## 🚀 快速上手与下载 (Downloads & Quick Start)

前往 [GitHub Releases](https://github.com/ABOLUOmathh/sing-box/releases) 获取最新稳定版本产物：

1. **Android 手机用户**：下载 `SFA-HX-<version>-arm64-v8a.apk`（主流手机推荐）或 `universal.apk` 直接安装。
2. **iOS 巨魔用户**：下载 `SFI-HX-<version>-trollstore.ipa`，在手机上通过 TrollStore 导入安装。
3. **Windows 电脑用户**：下载 `SFW-HX-<version>-x64.exe` 直接运行图形安装包体验完整功能。
4. **macOS 电脑用户**：下载 `SFM-HX-<version>-Universal.dmg` 拖入“应用程序”文件夹即可使用。
5. **Linux 桌面用户**：下载 `SFL-HX-<version>-amd64.deb`（Ubuntu/Debian）或 `.rpm`（Fedora/openSUSE）安装。
6. **OpenWrt 路由器用户**：根据路由器 CPU 架构下载对应的 `.ipk` 或 `.apk`，通过 SSH 执行安装：
   ```bash
   opkg install sing-box_<version>_openwrt_<arch>.ipk
   /etc/init.d/sing-box enable && /etc/init.d/sing-box start
   ```
4. **Linux 服务器用户**：
   ```bash
   # Debian / Ubuntu
   sudo dpkg -i sing-box_<version>_linux_amd64.deb
   sudo systemctl enable --now sing-box
   ```

---

## 🛠️ 项目构建 (Building from Source)

本项目依赖 Go 1.23+，并在 GitHub Actions 中配有全自动化的多平台交叉编译矩阵：

```bash
# 1. 克隆本仓库
git clone -b dev-1.14.4 https://github.com/ABOLUOmathh/sing-box.git
cd sing-box

# 2. 编译包含所有专有协议的 sing-box 核心
go build -v -trimpath \
  -tags "with_quic,with_wireguard,with_utls,with_clash_api,with_gvisor" \
  ./cmd/sing-box

# 3. 运行并查看版本
./sing-box version
```

---

## 📄 开源许可与声明 (License)

本项目基于原项目 [sing-box](https://github.com/SagerNet/sing-box) 进行衍生定制，遵循 **GPL-3.0** 许可证开放源码。所有专有协议实现、客户端适配补丁及构建脚本均保留原有版权并完全开放。