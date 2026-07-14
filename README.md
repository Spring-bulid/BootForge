# Android Boot Image Decompiler

> 纯浏览器端 Android boot.img / init_boot.img 解析与组件提取工具  
> *Client-side only. No uploads. No server. No dependencies.*

[![Demo](https://img.shields.io/badge/demo-GitHub%20Pages-blue)](https://spring-bulid.github.io/boot-image-decompiler/)
[![Tests](https://img.shields.io/badge/tests-40%2F40%20passed-brightgreen)](./tests/script.test.js)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

---

## Features

- Drag-and-drop or file-pick boot.img / init_boot.img
- Auto-detect header version: V0 / V1 / V2 / V3 / V4
- Parse metadata — kernel size, ramdisk, cmdline, OS version, security patch level, DTB, Recovery DTBO, etc.
- Enumerate components — Kernel, Ramdisk, Second Stage, DTB, Recovery DTBO/ACPIO, Boot Signature
- Per-component download with automatic compression format detection (gzip -> .gz, lz4 -> .lz4, xz -> .xz, etc.)
- Download All as ZIP with proper folder structure
- Hex dump viewer (offset + hex + ASCII, collapsible, 8 bytes/row)
- Export reports as JSON or CSV
- Accessible: ARIA labels, keyboard navigation, prefers-reduced-motion
- Zero dependencies — static HTML + JS + CSS

## Quick Start

```bash
npx serve .
# Open http://localhost:3000
```

Or deploy to any static host (GitHub Pages / Vercel / Netlify).

## Run Tests

```bash
node --test tests/script.test.js
```

40 tests covering all pure functions.

## Project Structure

```
index.html          Single-page UI
script.js           Pure functions + DOM interactions
styles.css          Design tokens + component styles
tests/
  script.test.js    40 unit tests
package.json        { "type": "module" }
```

## Supported Versions

| 版本 | 魔数 | 布局 | 组件 |
|------|------|------|------|
| V0 | `ANDROID!` | Legacy 固定偏移 | kernel, ramdisk, second |
| V1 | `ANDROID!` | Legacy + recovery_dtbo | + recovery DTBO/ACPIO |
| V2 | `ANDROID!` | Legacy + dtb | + DTB |
| V3 | `ANDROID!` | AOSP `boot_img_hdr_v3` | kernel, ramdisk |
| V4 | `ANDROID!` | AOSP `boot_img_hdr_v4` | + boot signature |

**init_boot.img**（Android 13+）：V4 头，kernel_size = 0，仅含 Generic Ramdisk。

## Technical Details

- **纯前端** — `DataView` + `Uint8Array` 解析二进制数据，无后端
- **V3/V4 AOSP 偏移量** — 严格遵循 `boot_img_hdr_v3` / `boot_img_hdr_v4` 结构体
- **ZIP 构建** — 零依赖的 PKZIP stored-method 实现（CRC-32 + Local Header + Central Directory + EOCD）
- **压缩检测** — 支持 gzip、lz4、xz、lzma、zstd、bzip2 魔术字节识别
- **Hex dump** — 8 字节/行，偏移 + 十六进制 + ASCII，可折叠，大组件截断显示
- **操作取消** — monotonic `bootOpId` 计数器防止异步竞态
- **Blob 清理** — `pagehide` 事件回收所有 `ObjectURL`
- **测试** — Node 原生 `node --test`，合成固件 fixture 覆盖 V0-V4

## License

MIT
