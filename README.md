# 🔓 Android Boot Image Decompiler

> 纯浏览器端 Android boot.img / init_boot.img 解析与组件提取工具  
> *Client-side only. No uploads. No server. No dependencies.*

[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-blue)](https://github.com)
[![Tests](https://img.shields.io/badge/tests-40%2F40%20passed-brightgreen)](./tests/script.test.js)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

---

## ✨ 功能

- 📂 **拖拽/选择** boot.img 或 init_boot.img 文件
- 🔍 **自动识别** V0 / V1 / V2 / V3 / V4 头版本
- 📊 **解析元数据** — 内核大小、ramdisk、cmdline、OS 版本、安全补丁级别、DTB、Recovery DTBO…
- 🧩 **枚举组件** — 内核、Ramdisk、二级引导、DTB、Recovery DTBO/ACPIO、启动签名
- 💾 **逐组件下载** — 自动识别压缩格式（gzip → `.gz`、lz4 → `.lz4`、xz → `.xz`…）
- 📦 **打包下载** — 全部组件打包为带文件夹结构的 ZIP
- 🔬 **Hex 预览** — 16 进制 + ASCII，可折叠
- 📋 **JSON / CSV 报告导出**
- ♿ **无障碍访问** — ARIA 标签、键盘导航、`prefers-reduced-motion`
- 🌐 **纯静态** — 单 HTML + 单 JS + 单 CSS，零依赖

## 🚀 快速开始

```bash
# 本地运行
npx serve .
# 打开 http://localhost:3000
```

或直接部署到任意静态托管（GitHub Pages / Vercel / Netlify）。

## 📸 截图

拖入 boot.img 后自动展示：

```
┌─────────────────────────────────────────────┐
│  Android Boot Image 分解                     │
├─────────────────────────────────────────────┤
│  ┌ 版本信息 ──────────────────────────────┐  │
│  │ 版本: 3   布局: v3plus   Header 大小: 48│  │
│  │ OS 版本: 14.0.0                        │  │
│  └────────────────────────────────────────┘  │
│  ┌ 内核 ──────────────────────────────────┐  │
│  │ Kernel 大小: 38.2 MB (0x262e000)       │  │
│  └────────────────────────────────────────┘  │
│  ┌ 组件列表 ──────────────────────────────┐  │
│  │ 组件          │ 偏移      │ 大小    │ 操作│  │
│  │ 内核 (Kernel) │ 0x1000    │ 38.2 MB │ 📥🔍│  │
│  │ Ramdisk       │ 0x2630000 │ 2.1 MB  │ 📥🔍│  │
│  │ 启动签名       │ 0x2852000 │ 512 B   │ 📥🔍│  │
│  └────────────────────────────────────────┘  │
│  [下载全部 (ZIP)]  [下载 JSON]  [重置]       │
└─────────────────────────────────────────────┘
```

## 🧪 测试

```bash
node --test tests/script.test.js
```

40 个测试覆盖所有纯函数：magic 校验、版本检测、头解析、组件枚举、hex dump、ZIP 构建、报告序列化、格式识别。

## 📂 项目结构

```
├── index.html          # 单页面 UI
├── script.js           # 纯函数 + DOM 交互
├── styles.css          # 设计令牌 + 组件样式
├── tests/
│   └── script.test.js  # 40 个单元测试
└── package.json        # { "type": "module" }
```

## 🔧 支持的 Boot Image 版本

| 版本 | 魔数 | 布局 | 组件 |
|------|------|------|------|
| V0 | `ANDROID!` | Legacy 固定偏移 | kernel, ramdisk, second |
| V1 | `ANDROID!` | Legacy + recovery_dtbo | + recovery DTBO/ACPIO |
| V2 | `ANDROID!` | Legacy + dtb | + DTB |
| V3 | `ANDROID!` | AOSP `boot_img_hdr_v3` | kernel, ramdisk |
| V4 | `ANDROID!` | AOSP `boot_img_hdr_v4` | + boot signature |

**init_boot.img**（Android 13+）：V4 头，kernel_size = 0，仅含 Generic Ramdisk。

## 📝 技术细节

- **纯前端** — `DataView` + `Uint8Array` 解析二进制数据，无后端
- **V3/V4 AOSP 偏移量** — 严格遵循 `boot_img_hdr_v3` / `boot_img_hdr_v4` 结构体
- **ZIP 构建** — 零依赖的 PKZIP stored-method 实现（CRC-32 + Local Header + Central Directory + EOCD）
- **压缩检测** — 支持 gzip、lz4、xz、lzma、zstd、bzip2 魔术字节识别
- **Hex dump** — 8 字节/行，偏移 + 十六进制 + ASCII，可折叠，大组件截断显示
- **操作取消** — monotonic `bootOpId` 计数器防止异步竞态
- **Blob 清理** — `pagehide` 事件回收所有 `ObjectURL`
- **测试** — Node 原生 `node --test`，合成固件 fixture 覆盖 V0-V4

## 📄 License

MIT
