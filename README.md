# boot-image-decompiler

在浏览器里拆解 Android boot.img / init_boot.img，不需要上传文件，也不依赖后端。

在线使用：https://spring-bulid.github.io/boot-image-decompiler/

## 能做什么

拖入 boot.img 或 init_boot.img，页面会解析文件头、列出里面的组件（内核、ramdisk、dtb 等），然后可以单独下载每个组件，或者打包成 ZIP 下载。组件的压缩格式（gzip / lz4 / xz 等）会自动识别，下载时会用对应的扩展名。

支持的 boot image 版本：

| 版本 | 结构 | 能拆出的组件 |
|------|------|-------------|
| V0 | 传统固定偏移 | kernel, ramdisk, second |
| V1 | V0 + recovery_dtbo 字段 | 加 recovery DTBO/ACPIO |
| V2 | V1 + dtb 字段 | 加 DTB |
| V3 | AOSP boot_img_hdr_v3 | kernel, ramdisk |
| V4 | AOSP boot_img_hdr_v4 | 加 boot signature |

init_boot.img（Android 13+）就是 V4 头但 kernel_size=0，只包含 Generic Ramdisk。

## 本地运行

不需要装任何东西，随便起个静态服务器就行：

```bash
npx serve .
```

然后打开 http://localhost:3000。或者直接双击 index.html 也行（有些浏览器可能会因为 ES module 限制加载不了，用 serve 最稳）。

## 运行测试

```bash
node --test tests/script.test.js
```

## 文件说明

```
index.html     页面
script.js      解析逻辑和交互
styles.css     样式
tests/         测试
package.json   就一个 { "type": "module" }
```

## 关于实现

整个工具就是三个静态文件，不依赖任何框架或库。boot image 的二进制解析用 DataView + Uint8Array 在浏览器本地完成，文件不会离开你的电脑。

V3/V4 的文件头偏移按照 AOSP mkbootimg 里 boot_img_hdr_v3 / v4 的结构体来读的。ZIP 打包也是自己写的 stored-method PKZIP，没有引用第三方库。
