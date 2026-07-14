/* ── Shared helpers ────────────────────────────────────────── */

const issue = (severity, code, message, region) => ({ severity, code, message, region });
const checkedRange = (offset, count, entrySize, length) => {
  if (!Number.isSafeInteger(count) || !Number.isSafeInteger(offset) || count < 0 || offset < 0 || count > Math.floor((Number.MAX_SAFE_INTEGER - offset) / entrySize)) return null;
  const size = count * entrySize; const end = offset + size;
  return end <= length ? { offset, size, end } : null;
};
const PREVIEW_LIMIT = 100;

export function serializeAnalysisRows(rows, format) {
  const safeRows = Array.isArray(rows) ? rows : [];
  if (format === "json") return `${JSON.stringify(safeRows, null, 2)}\n`;
  if (format !== "csv") return "";
  const headers = [...new Set(safeRows.flatMap((row) => row && typeof row === "object" ? Object.keys(row) : []))];
  const escape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  return `${headers.join(",")}\n${safeRows.map((row) => headers.map((header) => escape(row?.[header])).join(",")).join("\n")}${safeRows.length ? "\n" : ""}`;
}

/* ── Boot Image Constants ─────────────────────────────────── */

const BOOT_MAGIC = "ANDROID!";
const BOOT_MAGIC_BYTES = new TextEncoder().encode(BOOT_MAGIC);
const BOOT_PREVIEW_LIMIT = 100;
const HEX_BYTES_PER_ROW = 8;
const HEX_PAGE_SIZE = 4096;

// V0-V2 legacy header field offsets (all LE uint32 unless noted)
const HDR_MAGIC = 0;
const HDR_KERNEL_SIZE = 0x08;
const HDR_KERNEL_ADDR = 0x0C;
const HDR_RAMDISK_SIZE = 0x10;
const HDR_RAMDISK_ADDR = 0x14;
const HDR_SECOND_SIZE = 0x18;
const HDR_SECOND_ADDR = 0x1C;
const HDR_TAGS_ADDR = 0x20;
const HDR_PAGE_SIZE = 0x24;
const HDR_HEADER_VERSION = 0x28;
const HDR_OS_VERSION = 0x2C;
const HDR_NAME = 0x30;
const HDR_CMDLINE = 0x40;
const HDR_ID = 0x240;
const HDR_EXTRA_CMDLINE = 0x260;

// V1 appended fields (after V0 base)
const HDR_V1_RECOVERY_DTBO_SIZE = 0x660;
const HDR_V1_RECOVERY_DTBO_OFF = 0x664;
const HDR_V1_HEADER_SIZE = 0x66C;

// V2 appended fields
const HDR_V2_DTB_SIZE = 0x670;
const HDR_V2_DTB_ADDR = 0x674;

// V3/V4 restructured header offsets (AOSP boot_img_hdr_v3/v4)
const HDR_V3_KERNEL_SIZE = 0x08;
const HDR_V3_RAMDISK_SIZE = 0x0C;
const HDR_V3_OS_VERSION = 0x10;
const HDR_V3_HEADER_SIZE = 0x14;
// reserved[16] at 0x18-0x27, header_version at 0x28

// V4 signature size field
const HDR_V4_SIGNATURE_SIZE = 0x2C;

const ALIGN = (size, pageSize) => Math.ceil(size / pageSize) * pageSize;

/* ── Pure functions ────────────────────────────────────────── */

export function decodeOsVersion(ver) {
  if (typeof ver !== "number" || !Number.isSafeInteger(ver)) return null;
  const major = (ver >> 25) & 0x7F;
  const minor = (ver >> 18) & 0x7F;
  const patch = (ver >> 11) & 0x7F;
  return { major, minor, patch };
}

export function formatCmdline(raw) {
  if (typeof raw !== "string") return "";
  const nullIndex = raw.indexOf("\0");
  const text = nullIndex >= 0 ? raw.slice(0, nullIndex) : raw;
  let result = "";
  for (let i = 0; i < text.length && result.length < BOOT_PREVIEW_LIMIT; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code > 0x7E) {
      result += `\\x${code.toString(16).padStart(2, "0")}`;
    } else {
      result += text[i];
    }
  }
  return result;
}

export function validateBootMagic(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) {
    return { valid: false, message: "文件过小，无法包含有效的 Android boot image 魔术字节。" };
  }
  for (let i = 0; i < BOOT_MAGIC_BYTES.length; i += 1) {
    if (bytes[i] !== BOOT_MAGIC_BYTES[i]) {
      return { valid: false, message: "文件不包含有效的 \"ANDROID!\" 魔术字节。" };
    }
  }
  return { valid: true, message: "检测到有效的 Android boot image 魔术字节。" };
}

export function detectBootVersion(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 0x30) {
    return { version: -1, layout: "unknown" };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerVersion = view.getUint32(0x28, true);
  if (headerVersion === 1) return { version: 1, layout: "legacy" };
  if (headerVersion === 2) return { version: 2, layout: "legacy" };
  if (headerVersion === 3) return { version: 3, layout: "v3plus" };
  if (headerVersion === 4) return { version: 4, layout: "v3plus" };
  return { version: 0, layout: "legacy" };
}

export function parseBootHeader(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    return { ok: false, error: { code: "INVALID_INPUT", message: "输入必须是 Uint8Array。" } };
  }
  const magic = validateBootMagic(bytes);
  if (!magic.valid) {
    return { ok: false, error: { code: "INVALID_MAGIC", message: magic.message } };
  }
  if (bytes.length < 0x700) {
    return { ok: false, error: { code: "TRUNCATED_HEADER", message: "文件过小，无法包含完整的 boot image 文件头。" } };
  }
  const detected = detectBootVersion(bytes);
  if (detected.version < 0) {
    return { ok: false, error: { code: "UNKNOWN_VERSION", message: "无法检测 boot image 版本。" } };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const issues = [];
  const fields = {};

  function readString(offset, maxLen) {
    const slice = bytes.slice(offset, offset + maxLen);
    const nullIdx = slice.indexOf(0);
    const raw = new TextDecoder("utf-8", { fatal: false }).decode(nullIdx >= 0 ? slice.subarray(0, nullIdx) : slice);
    return raw;
  }

  try {
    if (detected.layout === "legacy") {
      // V0-V2: parse legacy fixed struct
      const kernelSize = view.getUint32(HDR_KERNEL_SIZE, true);
      const kernelAddr = view.getUint32(HDR_KERNEL_ADDR, true);
      const ramdiskSize = view.getUint32(HDR_RAMDISK_SIZE, true);
      const ramdiskAddr = view.getUint32(HDR_RAMDISK_ADDR, true);
      const secondSize = view.getUint32(HDR_SECOND_SIZE, true);
      const secondAddr = view.getUint32(HDR_SECOND_ADDR, true);
      const tagsAddr = view.getUint32(HDR_TAGS_ADDR, true);
      const pageSize = view.getUint32(HDR_PAGE_SIZE, true) || 2048;
      const osVersion = detected.version >= 1 ? view.getUint32(HDR_OS_VERSION, true) : null;
      const name = readString(HDR_NAME, 16);
      const cmdline = readString(HDR_CMDLINE, 512);
      const id = Array.from(bytes.slice(HDR_ID, HDR_ID + 32), (b) => b.toString(16).padStart(2, "0")).join("");
      const extraCmdline = detected.version >= 1 ? null : readString(HDR_EXTRA_CMDLINE, 1024);

      Object.assign(fields, {
        kernelSize, kernelAddr, ramdiskSize, ramdiskAddr,
        secondSize, secondAddr, tagsAddr,
        pageSize, headerVersion: detected.version,
        osVersion, osPatchLevel: null, name, cmdline, id,
        recoveryDtboSize: null, recoveryDtboOffset: null, headerSize: null,
        dtbSize: null, dtbAddr: null,
        vendorRamdiskSize: null, signatureSize: null,
        extraCmdline,
      });

      // V1: recovery_dtbo fields
      if (detected.version >= 1) {
        fields.recoveryDtboSize = view.getUint32(HDR_V1_RECOVERY_DTBO_SIZE, true);
        fields.recoveryDtboOffset = view.getBigUint64(HDR_V1_RECOVERY_DTBO_OFF, true);
        fields.headerSize = view.getUint32(HDR_V1_HEADER_SIZE, true);
      }

      // V2: dtb fields
      if (detected.version >= 2) {
        fields.dtbSize = view.getUint32(HDR_V2_DTB_SIZE, true);
        fields.dtbAddr = view.getBigUint64(HDR_V2_DTB_ADDR, true);
      }

      if (pageSize < 2048 || (pageSize & (pageSize - 1)) !== 0) {
        issues.push(issue("warning", "BAD_PAGE_SIZE", `非标准 page size: ${pageSize}`, "header"));
      }
    } else {
      // V3/V4: restructured header (AOSP boot_img_hdr_v3/v4)
      const kernelSize = view.getUint32(HDR_V3_KERNEL_SIZE, true);
      const ramdiskSize = view.getUint32(HDR_V3_RAMDISK_SIZE, true);
      const osVersion = view.getUint32(HDR_V3_OS_VERSION, true);
      const headerSize = view.getUint32(HDR_V3_HEADER_SIZE, true);
      const pageSize = 4096;
      let signatureSize = 0;
      if (detected.version === 4) {
        signatureSize = view.getUint32(HDR_V4_SIGNATURE_SIZE, true);
      }

      Object.assign(fields, {
        kernelSize, kernelAddr: null, ramdiskSize, ramdiskAddr: null,
        secondSize: null, secondAddr: null, tagsAddr: null,
        pageSize, headerVersion: detected.version,
        osVersion, osPatchLevel: null, name: null, cmdline: null, id: null,
        recoveryDtboSize: null, recoveryDtboOffset: null, headerSize,
        dtbSize: null, dtbAddr: null,
        vendorRamdiskSize: null, signatureSize,
        extraCmdline: null,
      });
    }
  } catch (err) {
    return { ok: false, error: { code: "PARSE_ERROR", message: `解析文件头时出错: ${err.message}` } };
  }

  return { ok: true, value: { version: detected.version, layout: detected.layout, fields, issues } };
}

export function enumerateComponents(header, bytes) {
  if (!header || !header.fields || !(bytes instanceof Uint8Array)) return [];
  const { fields, version, layout } = header;
  const pageSize = fields.pageSize && fields.pageSize >= 2048 ? fields.pageSize : 2048;
  const components = [];

  function addComponent(name, label, offset, size) {
    const present = size > 0;
    const end = offset + size;
    const checked = checkedRange(offset, size, 1, bytes.length);
    const truncated = present && !checked;
    let warning = null;
    if (truncated) {
      warning = `组件 "${label}" 超出文件范围 (偏移 0x${offset.toString(16)}, 大小 ${size})。数据已截断。`;
    }
    components.push({ name, label, offset, size, end, present, truncated, warning });
  }

  if (layout === "legacy") {
    const kernelOff = pageSize;
    addComponent("kernel", "内核 (Kernel)", kernelOff, fields.kernelSize);

    const ramdiskOff = kernelOff + ALIGN(fields.kernelSize, pageSize);
    addComponent("ramdisk", "Ramdisk", ramdiskOff, fields.ramdiskSize);

    const secondOff = ramdiskOff + ALIGN(fields.ramdiskSize, pageSize);
    addComponent("second", "二级引导 (Second Stage)", secondOff, fields.secondSize || 0);

    let nextOff = secondOff + ALIGN(fields.secondSize || 0, pageSize);

    if (version >= 1) {
      const rdSize = typeof fields.recoveryDtboSize === "number" ? fields.recoveryDtboSize : 0;
      if (rdSize > 0) {
        addComponent("recovery_dtbo", "Recovery DTBO/ACPIO", nextOff, rdSize);
        nextOff = nextOff + ALIGN(rdSize, pageSize);
      }
    }

    if (version >= 2) {
      const dtbSize = typeof fields.dtbSize === "number" ? fields.dtbSize : 0;
      if (dtbSize > 0) {
        addComponent("dtb", "设备树 (DTB)", nextOff, dtbSize);
      }
    }
  } else {
    // V3/V4 (AOSP boot_img_hdr_v3/v4 — no vendor_ramdisk, no second, no DTB)
    const kernelOff = pageSize;
    addComponent("kernel", "内核 (Kernel)", kernelOff, fields.kernelSize);

    const ramdiskOff = kernelOff + ALIGN(fields.kernelSize, pageSize);
    const ramdiskLabel = (fields.kernelSize === 0 && fields.ramdiskSize > 0) ? "Generic Ramdisk" : "Ramdisk";
    addComponent("ramdisk", ramdiskLabel, ramdiskOff, fields.ramdiskSize);

    if (version === 4 && fields.signatureSize > 0) {
      const sigOff = ramdiskOff + ALIGN(fields.ramdiskSize, pageSize);
      addComponent("boot_signature", "启动签名 (Boot Signature)", sigOff, fields.signatureSize);
    }
  }

  return components;
}

/* ── Format detection ──────────────────────────────────────── */

const COMPRESSION_SIGNATURES = [
  { magic: [0x1F, 0x8B],                          ext: ".gz" },
  { magic: [0x04, 0x22, 0x4D, 0x18],              ext: ".lz4" },
  { magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],  ext: ".xz" },
  { magic: [0x5D, 0x00, 0x00],                    ext: ".lzma" },
  { magic: [0x28, 0xB5, 0x2F, 0xFD],              ext: ".zst" },
  { magic: [0x1F, 0x9D],                          ext: ".z" },   // compress (.Z)
  { magic: [0x42, 0x5A, 0x68],                    ext: ".bz2" },
];

export function detectComponentFormat(bytes, offset, size) {
  if (!(bytes instanceof Uint8Array) || size < 2) return ".bin";
  for (const sig of COMPRESSION_SIGNATURES) {
    if (size < sig.magic.length) continue;
    let match = true;
    for (let i = 0; i < sig.magic.length; i += 1) {
      if (bytes[offset + i] !== sig.magic[i]) { match = false; break; }
    }
    if (match) return sig.ext;
  }
  return ".bin";
}

/* ── Hex dump ─────────────────────────────────────────────── */

export function hexDump(bytes, offset, length) {
  if (!(bytes instanceof Uint8Array) || offset < 0 || offset >= bytes.length || length <= 0) return [];
  const rows = [];
  const end = Math.min(offset + length, bytes.length);
  for (let pos = offset; pos < end; pos += HEX_BYTES_PER_ROW) {
    const rowEnd = Math.min(pos + HEX_BYTES_PER_ROW, end);
    let hex = "";
    let ascii = "";
    for (let i = pos; i < rowEnd; i += 1) {
      if (i > pos) {
        hex += (i - pos) % 8 === 0 ? "  " : " ";
      }
      hex += bytes[i].toString(16).padStart(2, "0");
      const code = bytes[i];
      ascii += code >= 0x20 && code <= 0x7E ? String.fromCharCode(code) : ".";
    }
    rows.push({
      offset: pos.toString(16).padStart(8, "0"),
      hex,
      ascii,
    });
  }
  return rows;
}

/* ── CRC-32 ───────────────────────────────────────────────── */

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let crc = i;
    for (let j = 0; j < 8; j += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xEDB88320 : crc >>> 1;
    }
    table[i] = crc;
  }
  return table;
})();

function crc32(data) {
  let crc = 0xFFFFFFFF;
  for (const byte of data) crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ byte) & 0xFF];
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/* ── ZIP builder ──────────────────────────────────────────── */

export function buildZip(components, bytes, archiveName) {
  if (!(bytes instanceof Uint8Array) || !components || !components.length) return null;
  const entries = components.filter((c) => c.present && !c.truncated);
  if (!entries.length) return null;

  const encoder = new TextEncoder();
  // Use a folder prefix so all files extract into a named directory
  const folderName = (archiveName || "boot_components").replace(/\.zip$/i, "");
  const folderPrefix = `${folderName}/`;

  const localHeaders = [];
  const cdEntries = [];
  let dataOffset = 0;

  for (const comp of entries) {
    const ext = detectComponentFormat(bytes, comp.offset, comp.size);
    const path = `${folderPrefix}${comp.name}${ext}`;
    const nameBytes = encoder.encode(path);
    const data = bytes.slice(comp.offset, comp.offset + comp.size);
    const crc = crc32(data);
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lhView = new DataView(localHeader.buffer);
    let pos = 0;
    lhView.setUint32(pos, 0x04034b50, true); pos += 4;
    lhView.setUint16(pos, 20, true); pos += 2;
    lhView.setUint16(pos, 0, true); pos += 2;
    lhView.setUint16(pos, 0, true); pos += 2;
    lhView.setUint32(pos, 0, true); pos += 4;
    lhView.setUint32(pos, crc, true); pos += 4;
    lhView.setUint32(pos, data.length, true); pos += 4;
    lhView.setUint32(pos, data.length, true); pos += 4;
    lhView.setUint16(pos, nameBytes.length, true); pos += 2;
    lhView.setUint16(pos, 0, true); pos += 2;
    localHeader.set(nameBytes, pos);
    localHeaders.push({ header: localHeader, data, isDir: false });
    cdEntries.push({ name: nameBytes, crc, size: data.length, offset: dataOffset, isDir: false });
    dataOffset += localHeader.length + data.length;
  }

  // Add folder (directory) entries for the ZIP — ensures proper folder structure
  const folderNameBytes = encoder.encode(folderPrefix);
  cdEntries.unshift({ name: folderNameBytes, crc: 0, size: 0, offset: 0, isDir: true });

  // Also add subfolders if any component paths suggest them (not needed now, but extensible)

  // Total file data size (before central directory)
  let totalSize = 0;
  for (const lh of localHeaders) totalSize += lh.header.length + lh.data.length;

  // Build central directory
  let cdSize = 0;
  const cdParts = [];
  for (const cde of cdEntries) {
    const attr = cde.isDir ? 0x10 : 0;  // directory attribute
    const entry = new Uint8Array(46 + cde.name.length);
    const ev = new DataView(entry.buffer);
    let p = 0;
    ev.setUint32(p, 0x02014b50, true); p += 4;
    ev.setUint16(p, cde.isDir ? 0x0314 : 20, true); p += 2; // version: 3.20 for dirs
    ev.setUint16(p, 20, true); p += 2;
    ev.setUint16(p, 0, true); p += 2;
    ev.setUint16(p, 0, true); p += 2;
    ev.setUint32(p, 0, true); p += 4;
    ev.setUint32(p, cde.crc, true); p += 4;
    ev.setUint32(p, cde.size, true); p += 4;
    ev.setUint32(p, cde.size, true); p += 4;
    ev.setUint16(p, cde.name.length, true); p += 2;
    ev.setUint16(p, 0, true); p += 2;
    ev.setUint16(p, 0, true); p += 2;
    ev.setUint16(p, 0, true); p += 2;
    ev.setUint32(p, attr, true); p += 4;  // external attributes
    ev.setUint32(p, cde.offset, true); p += 4;
    entry.set(cde.name, p);
    cdParts.push(entry);
    cdSize += entry.length;
  }

  const totalCdEntries = cdEntries.length;

  const buf = new Uint8Array(totalSize + cdSize + 22);
  let off = 0;
  for (const lh of localHeaders) {
    buf.set(lh.header, off); off += lh.header.length;
    buf.set(lh.data, off); off += lh.data.length;
  }
  for (const cd of cdParts) { buf.set(cd, off); off += cd.length; }

  const eocd = new DataView(buf.buffer, off, 22);
  eocd.setUint32(0, 0x06054b50, true);
  eocd.setUint16(4, 0, true);
  eocd.setUint16(6, 0, true);
  eocd.setUint16(8, totalCdEntries, true);
  eocd.setUint16(10, totalCdEntries, true);
  eocd.setUint32(12, cdSize, true);
  eocd.setUint32(16, totalSize, true);
  eocd.setUint16(20, 0, true);

  return buf;
}

export function serializeBootReport(header, components, format) {
  const rows = [];
  if (header) {
    rows.push({ category: "header", version: header.version, layout: header.layout, ...header.fields });
  }
  for (const comp of (components || [])) {
    rows.push({ category: "component", ...comp });
  }
  if (header?.issues) {
    for (const iss of header.issues) rows.push({ category: "issue", ...iss });
  }
  return serializeAnalysisRows(rows, format);
}

/* ── Browser UI ───────────────────────────────────────────── */

if (typeof document !== "undefined") {
  const bootFileInput = document.querySelector("#boot-file-input");
  const bootDropZone = document.querySelector("#boot-drop-zone");
  const bootFileName = document.querySelector("#boot-file-name");
  const bootFileActions = document.querySelector("#boot-file-actions");
  const bootFileError = document.querySelector("#boot-file-error");
  const bootStatus = document.querySelector("#boot-status");
  const bootResults = document.querySelector("#boot-results");
  const bootMetadata = document.querySelector("#boot-metadata");
  const bootComponents = document.querySelector("#boot-components");
  const bootIssues = document.querySelector("#boot-issues");
  const bootDownloadAll = document.querySelector("#boot-download-all");
  const bootDownloadJson = document.querySelector("#boot-download-json");
  const bootReset = document.querySelector("#boot-reset");
  const bootReplaceFile = document.querySelector("#boot-replace-file");
  const bootRemoveFile = document.querySelector("#boot-remove-file");

  let bootFile = null;
  let bootOpId = 0;
  let bootOutput = null;
  let bootHeader = null;
  let bootComponentList = [];
  let bootBlobUrls = [];

  function revokeBootBlobs() {
    for (const url of bootBlobUrls) URL.revokeObjectURL(url);
    bootBlobUrls = [];
  }

  function setBootError(message = "") {
    bootFileError.textContent = message;
    bootFileInput.setAttribute("aria-invalid", String(Boolean(message)));
  }

  function clearBootResults() {
    revokeBootBlobs();
    bootOutput = null;
    bootHeader = null;
    bootComponentList = [];
    bootResults.hidden = true;
    bootMetadata.replaceChildren();
    bootComponents.replaceChildren();
    bootIssues.hidden = true;
  }

  function downloadBlob(content, name, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    bootBlobUrls.push(url);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
  }

  function setBootFile(file) {
    bootOpId += 1;
    clearBootResults();
    setBootError();
    bootFile = file || null;
    bootFileName.textContent = bootFile ? `${bootFile.name}（${bootFile.size.toLocaleString()} 字节）` : "尚未选择文件";
    bootFileActions.hidden = !bootFile;
    bootStatus.textContent = bootFile ? "文件已选择，正在解析..." : "选择 boot image 文件开始解析。";
  }

  async function acceptBootFile(file) {
    if (!file) return;
    if (typeof file.arrayBuffer !== "function") {
      setBootError("所选项目无法作为文件读取。");
      return;
    }
    setBootFile(file);
    const request = ++bootOpId;
    bootStatus.textContent = "正在解析 boot image...";
    try {
      const buffer = await file.arrayBuffer();
      if (request !== bootOpId) return;
      const bytes = new Uint8Array(buffer);
      bootOutput = bytes;

      const headerResult = parseBootHeader(bytes);
      if (!headerResult.ok) {
        bootStatus.textContent = headerResult.error.message;
        setBootError(headerResult.error.message);
        return;
      }
      bootHeader = headerResult.value;
      const components = enumerateComponents(bootHeader, bytes);
      bootComponentList = components;

      renderBootMetadata(bootHeader);
      renderBootComponents(components, bytes);
      renderBootIssues(bootHeader.issues);

      bootResults.hidden = false;
      const compCount = components.filter((c) => c.present).length;
      bootStatus.textContent = `解析完成。版本 ${bootHeader.version}，${compCount} 个组件。`;
    } catch (err) {
      if (request === bootOpId) {
        setBootError(`解析失败: ${err.message}`);
        bootStatus.textContent = `解析失败: ${err.message}`;
      }
    }
  }

  function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function renderBootMetadata(header) {
    bootMetadata.replaceChildren();
    const groups = [];
    const f = header.fields;

    const versionRows = [
      { label: "版本", value: header.version },
      { label: "布局", value: header.layout },
      { label: "Header 版本", value: f.headerVersion ?? "—" },
      { label: "Header 大小", value: f.headerSize !== null && f.headerSize !== undefined ? `0x${f.headerSize.toString(16)} (${f.headerSize})` : "—" },
    ];
    if (f.osVersion !== null && f.osVersion !== undefined) {
      const decoded = decodeOsVersion(f.osVersion);
      versionRows.push({ label: "OS 版本", value: decoded ? `${decoded.major}.${decoded.minor}.${decoded.patch}` : `0x${f.osVersion.toString(16)}` });
    }
    if (f.osPatchLevel) versionRows.push({ label: "安全补丁级别", value: f.osPatchLevel });
    groups.push({ title: "版本信息", rows: versionRows });

    groups.push({ title: "分页", rows: [{ label: "Page Size", value: f.pageSize ? `${f.pageSize} (0x${f.pageSize.toString(16)})` : "—" }] });

    const kernelRows = [
      { label: "Kernel 大小", value: f.kernelSize !== null ? `${formatSize(f.kernelSize)} (0x${f.kernelSize?.toString(16)})` : "—" },
      { label: "Kernel 地址", value: f.kernelAddr !== null ? `0x${f.kernelAddr?.toString(16)}` : "—" },
    ];
    groups.push({ title: "内核", rows: kernelRows });

    const ramdiskRows = [
      { label: "Ramdisk 大小", value: f.ramdiskSize !== null ? `${formatSize(f.ramdiskSize)} (0x${f.ramdiskSize?.toString(16)})` : "—" },
      { label: "Ramdisk 地址", value: f.ramdiskAddr !== null ? `0x${f.ramdiskAddr?.toString(16)}` : "—" },
    ];
    groups.push({ title: "内存盘", rows: ramdiskRows });

    if (f.secondSize !== null) {
      groups.push({ title: "二级引导", rows: [
        { label: "Second 大小", value: f.secondSize ? `${formatSize(f.secondSize)} (0x${f.secondSize.toString(16)})` : "0" },
        { label: "Second 地址", value: f.secondAddr !== null ? `0x${f.secondAddr?.toString(16)}` : "—" },
      ]});
    }

    groups.push({ title: "Tags", rows: [{ label: "Tags 地址", value: f.tagsAddr !== null ? `0x${f.tagsAddr?.toString(16)}` : "—" }] });

    if (f.name) groups.push({ title: "名称", rows: [{ label: "Name", value: f.name }] });

    if (f.cmdline) {
      const escaped = formatCmdline(f.cmdline);
      groups.push({ title: "命令行", rows: [{ label: "Cmdline", value: escaped || "(空)" }] });
    }

    if (f.recoveryDtboSize !== null) {
      groups.push({ title: "Recovery DTBO", rows: [
        { label: "大小", value: f.recoveryDtboSize ? `${formatSize(f.recoveryDtboSize)} (0x${f.recoveryDtboSize.toString(16)})` : "0" },
        { label: "偏移", value: f.recoveryDtboOffset !== null ? `0x${f.recoveryDtboOffset?.toString(16)}` : "—" },
      ]});
    }

    if (f.dtbSize !== null) {
      groups.push({ title: "DTB", rows: [
        { label: "大小", value: f.dtbSize ? `${formatSize(f.dtbSize)} (0x${f.dtbSize.toString(16)})` : "0" },
        { label: "地址", value: f.dtbAddr !== null ? `0x${f.dtbAddr?.toString(16)}` : "—" },
      ]});
    }

    if (f.vendorRamdiskSize !== null) {
      groups.push({ title: "Vendor Ramdisk", rows: [
        { label: "大小", value: f.vendorRamdiskSize ? `${formatSize(f.vendorRamdiskSize)} (0x${f.vendorRamdiskSize.toString(16)})` : "0" },
      ]});
    }

    if (f.signatureSize !== null && f.signatureSize !== undefined) {
      groups.push({ title: "签名", rows: [{ label: "Signature 大小", value: f.signatureSize ? `${formatSize(f.signatureSize)} (0x${f.signatureSize.toString(16)})` : "0" }] });
    }

    for (const group of groups) {
      const div = document.createElement("div");
      div.className = "field-group";
      const h3 = document.createElement("h3");
      h3.textContent = group.title;
      div.append(h3);
      for (const row of group.rows) {
        const rowDiv = document.createElement("div");
        rowDiv.className = "field-row";
        const label = document.createElement("span");
        label.className = "field-label";
        label.textContent = row.label;
        const value = document.createElement("span");
        value.className = "field-value";
        value.textContent = row.value;
        rowDiv.append(label, value);
        div.append(rowDiv);
      }
      bootMetadata.append(div);
    }
  }

  function renderBootComponents(components, bytes) {
    bootComponents.replaceChildren();

    if (!components.length) {
      const p = document.createElement("p");
      p.textContent = "未检测到组件。";
      bootComponents.append(p);
      return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "table-scroll";
    const table = document.createElement("table");
    table.className = "boot-component-table";
    table.style.cssText = "width:100%;border-collapse:collapse;font-size:13px;white-space:nowrap;";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    for (const col of ["组件名称", "起始偏移", "结束偏移", "大小", "状态", "操作"]) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = col;
      headRow.append(th);
    }
    thead.append(headRow);
    table.append(thead);

    const tbody = document.createElement("tbody");
    for (const comp of components) {
      const tr = document.createElement("tr");
      const tdName = document.createElement("td");
      tdName.textContent = comp.label;
      tr.append(tdName);

      if (comp.warning) {
        tr.className = "boot-comp-warning";
        tdName.textContent = "⚠ " + tdName.textContent;
      }

      const tdStart = document.createElement("td");
      tdStart.textContent = comp.present ? `0x${comp.offset.toString(16)}` : "—";
      tr.append(tdStart);

      const tdEnd = document.createElement("td");
      tdEnd.textContent = comp.present ? `0x${comp.end.toString(16)}` : "—";
      tr.append(tdEnd);

      const tdSize = document.createElement("td");
      tdSize.textContent = comp.present ? `${formatSize(comp.size)} (0x${comp.size.toString(16)})` : "0";
      tr.append(tdSize);

      const tdStatus = document.createElement("td");
      if (comp.truncated) {
        tdStatus.textContent = "⚠ 已截断";
        tdStatus.style.color = "var(--color-warning-text)";
      } else if (!comp.present) {
        tdStatus.textContent = "不存在";
        tdStatus.style.color = "var(--color-muted)";
      } else {
        tdStatus.textContent = "有效";
      }
      tr.append(tdStatus);

      const tdActions = document.createElement("td");
      tdActions.style.cssText = "display:flex;gap:var(--space-1);flex-wrap:wrap;";
      if (comp.present && !comp.truncated) {
        const dlBtn = document.createElement("button");
        dlBtn.type = "button";
        dlBtn.textContent = "下载";
        dlBtn.style.cssText = "min-height:32px;font-size:12px;padding:2px 8px;";
        dlBtn.addEventListener("click", () => {
          const ext = detectComponentFormat(bytes, comp.offset, comp.size);
          downloadBlob(bytes.slice(comp.offset, comp.end), `${comp.name}${ext}`, "application/octet-stream");
        });
        tdActions.append(dlBtn);

        if (comp.size <= HEX_PAGE_SIZE * 16) {
          const hexBtn = document.createElement("button");
          hexBtn.type = "button";
          hexBtn.textContent = "Hex";
          hexBtn.style.cssText = "min-height:32px;font-size:12px;padding:2px 8px;";
          hexBtn.addEventListener("click", (e) => handleBootHexToggle(comp, bytes, e));
          tdActions.append(hexBtn);
        }
      }
      tr.append(tdActions);

      tbody.append(tr);
    }
    table.append(tbody);
    wrapper.append(table);
    bootComponents.append(wrapper);
  }

  function renderBootIssues(issues) {
    bootIssues.replaceChildren();
    if (!issues || !issues.length) {
      bootIssues.hidden = true;
      return;
    }
    bootIssues.hidden = false;
    const title = document.createElement("p");
    title.textContent = `结构问题（${issues.length} 项）：`;
    title.style.fontWeight = "600";
    bootIssues.append(title);
    for (const entry of issues) {
      const line = document.createElement("p");
      line.textContent = `[${entry.severity === "error" ? "错误" : "警告"}] ${entry.region}: ${entry.message}`;
      line.style.color = entry.severity === "error" ? "var(--color-error)" : "var(--color-muted)";
      bootIssues.append(line);
    }
  }

  function handleBootHexToggle(comp, bytes, event) {
    const btn = (event && event.currentTarget) || document.activeElement;
    const tr = btn ? btn.closest("tr") : null;
    if (!tr) return;

    const existing = tr.nextElementSibling;
    if (existing && existing.classList.contains("boot-hex-row")) {
      existing.remove();
      return;
    }

    for (const row of bootComponents.querySelectorAll(".boot-hex-row")) {
      row.remove();
    }

    const hexRow = document.createElement("tr");
    hexRow.className = "boot-hex-row";
    const hexTd = document.createElement("td");
    hexTd.colSpan = 6;
    hexTd.style.cssText = "padding:0;";

    const container = document.createElement("div");
    container.style.cssText = "margin:var(--space-2) 0;";

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "collapsible-toggle";
    toggle.setAttribute("aria-expanded", "true");
    toggle.innerHTML = '<span class="collapsible-caret"></span> Hex 预览';
    container.append(toggle);

    const content = document.createElement("div");
    content.className = "collapsible-content";
    content.setAttribute("aria-hidden", "false");

    const inner = document.createElement("div");
    const hexViewer = document.createElement("div");
    hexViewer.className = "hex-viewer";

    const dumpLength = Math.min(comp.size, HEX_PAGE_SIZE);
    const rows = hexDump(bytes, comp.offset, dumpLength);
    for (const row of rows) {
      const rowDiv = document.createElement("div");
      rowDiv.className = "hex-row";
      const off = document.createElement("span");
      off.className = "hex-offset";
      off.textContent = row.offset;
      const bytesSpan = document.createElement("span");
      bytesSpan.className = "hex-bytes";
      bytesSpan.textContent = row.hex;
      const asciiSpan = document.createElement("span");
      asciiSpan.className = "hex-ascii";
      asciiSpan.textContent = row.ascii;
      rowDiv.append(off, bytesSpan, asciiSpan);
      hexViewer.append(rowDiv);
    }
    inner.append(hexViewer);

    if (comp.size > HEX_PAGE_SIZE) {
      const note = document.createElement("p");
      note.style.cssText = "font-size:12px;color:var(--color-muted);margin-top:var(--space-1);";
      note.textContent = `仅显示前 ${formatSize(HEX_PAGE_SIZE)}，共 ${formatSize(comp.size)}。`;
      inner.append(note);
    }

    content.append(inner);
    container.append(content);

    toggle.addEventListener("click", () => {
      const expanded = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!expanded));
      content.setAttribute("aria-hidden", String(expanded));
    });

    hexTd.append(container);
    hexRow.append(hexTd);
    tr.after(hexRow);
  }

  // Event listeners
  bootFileInput.addEventListener("change", () => acceptBootFile(bootFileInput.files?.[0]));
  bootReplaceFile.addEventListener("click", () => bootFileInput.click());
  bootRemoveFile.addEventListener("click", () => {
    bootFileInput.value = "";
    setBootFile(null);
    bootStatus.textContent = "选择 boot image 文件开始解析。";
  });
  bootReset.addEventListener("click", () => {
    bootFileInput.value = "";
    setBootFile(null);
    bootStatus.textContent = "选择 boot image 文件开始解析。";
  });

  ["dragenter", "dragover"].forEach((eventName) => bootDropZone.addEventListener(eventName, (event) => { event.preventDefault(); bootDropZone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((eventName) => bootDropZone.addEventListener(eventName, (event) => { event.preventDefault(); bootDropZone.classList.remove("dragging"); }));
  bootDropZone.addEventListener("drop", (event) => acceptBootFile(event.dataTransfer?.files?.[0]));

  bootDownloadAll.addEventListener("click", () => {
    if (!bootOutput || !bootComponentList.length) return;
    const zip = buildZip(bootComponentList, bootOutput, "boot_components.zip");
    if (zip) downloadBlob(zip, "boot_components.zip", "application/zip");
  });

  bootDownloadJson.addEventListener("click", () => {
    if (!bootHeader) return;
    const json = serializeBootReport(bootHeader, bootComponentList, "json");
    downloadBlob(json, "boot-analysis.json", "application/json");
  });

  window.addEventListener("pagehide", revokeBootBlobs, { once: true });
}
