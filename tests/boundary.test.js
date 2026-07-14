// boundary.test.js — edge-case and adversarial tests for Android Boot Image Disassembler
import test from "node:test";
import assert from "node:assert/strict";

import {
  validateBootMagic,
  detectBootVersion,
  parseBootHeader,
  decodeOsVersion,
  formatCmdline,
  enumerateComponents,
  hexDump,
  buildZip,
  serializeBootReport,
  // also test DEX/Unity regression
  applyRepeatedKeyXor,
  parseXorKey,
  parseOffset,
  validateDexHeader,
  parseDexStructure,
  analyzeUnityFile,
  buildOutputName,
  serializeAnalysisRows,
} from "../script.js";

const BOOT_MAGIC_BYTES = new TextEncoder().encode("ANDROID!");

// ── Helpers ──────────────────────────────────────────────────

function makeBuf(size, filler = 0) {
  const buf = new Uint8Array(size);
  if (filler) buf.fill(filler);
  return buf;
}

function setMagic(buf) {
  buf.set(BOOT_MAGIC_BYTES, 0);
  return buf;
}

// =============================================================
//  VALIDATE BOOT MAGIC
// =============================================================

test("validateBootMagic: null input", () => {
  assert.equal(validateBootMagic(null).valid, false);
});

test("validateBootMagic: undefined input", () => {
  assert.equal(validateBootMagic(undefined).valid, false);
});

test("validateBootMagic: Array instead of Uint8Array", () => {
  assert.equal(validateBootMagic([1, 2, 3]).valid, false);
});

test("validateBootMagic: trailing bytes after ANDROID! are fine", () => {
  const buf = new Uint8Array(256);
  buf.set(BOOT_MAGIC_BYTES, 0);
  buf.fill(0xFF, 8);
  assert.equal(validateBootMagic(buf).valid, true);
});

test("validateBootMagic: exactly 8 bytes ANDROID!", () => {
  const buf = new Uint8Array(BOOT_MAGIC_BYTES);
  assert.equal(validateBootMagic(buf).valid, true);
});

test("validateBootMagic: byte at position 7 corrupted", () => {
  const buf = new Uint8Array(64);
  buf.set(BOOT_MAGIC_BYTES, 0);
  buf[7] = 0x20; // change '!' to space
  assert.equal(validateBootMagic(buf).valid, false);
});

// =============================================================
//  DETECT BOOT VERSION
// =============================================================

test("detectBootVersion: null input", () => {
  assert.deepEqual(detectBootVersion(null), { version: -1, layout: "unknown" });
});

test("detectBootVersion: undefined input", () => {
  assert.deepEqual(detectBootVersion(undefined), { version: -1, layout: "unknown" });
});

test("detectBootVersion: empty array (0 bytes)", () => {
  assert.deepEqual(detectBootVersion(new Uint8Array(0)), { version: -1, layout: "unknown" });
});

test("detectBootVersion: exactly 8 bytes (below 0x30 threshold)", () => {
  const buf = new Uint8Array(8);
  buf.set(BOOT_MAGIC_BYTES, 0);
  assert.deepEqual(detectBootVersion(buf), { version: -1, layout: "unknown" });
});

test("detectBootVersion: exactly 0x2F bytes (one byte below 0x30)", () => {
  const buf = new Uint8Array(0x2F);
  assert.deepEqual(detectBootVersion(buf), { version: -1, layout: "unknown" });
});

test("detectBootVersion: exactly 0x30 bytes (threshold)", () => {
  const buf = new Uint8Array(0x30);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 1, true);
  assert.deepEqual(detectBootVersion(buf), { version: 1, layout: "legacy" });
});

test("detectBootVersion: V0 with garbage at 0x28", () => {
  const buf = new Uint8Array(0x100);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 0xFFFFFFFF, true);
  assert.deepEqual(detectBootVersion(buf), { version: 0, layout: "legacy" });
});

test("detectBootVersion: V3 detected via offset 0x04 takes priority over 0x28", () => {
  // If both 0x04 and 0x28 have valid versions, 0x04 wins for V3
  const buf = new Uint8Array(0x100);
  const view = new DataView(buf.buffer);
  view.setUint32(0x04, 3, true); // V3 at V3 detection offset
  view.setUint32(0x28, 1, true); // V1 at legacy offset
  assert.deepEqual(detectBootVersion(buf), { version: 3, layout: "v3plus" });
});

test("detectBootVersion: V4 detected via offset 0x04 takes priority", () => {
  const buf = new Uint8Array(0x100);
  const view = new DataView(buf.buffer);
  view.setUint32(0x04, 4, true);
  view.setUint32(0x28, 2, true);
  assert.deepEqual(detectBootVersion(buf), { version: 4, layout: "v3plus" });
});

test("detectBootVersion: V3 from legacy offset 0x28 when 0x04 is not 3 or 4", () => {
  const buf = new Uint8Array(0x100);
  const view = new DataView(buf.buffer);
  view.setUint32(0x04, 0, true); // not 3 or 4
  view.setUint32(0x28, 3, true);
  assert.deepEqual(detectBootVersion(buf), { version: 3, layout: "v3plus" });
});

test("detectBootVersion: V4 from legacy offset 0x28 when 0x04 is not 3 or 4", () => {
  const buf = new Uint8Array(0x100);
  const view = new DataView(buf.buffer);
  view.setUint32(0x04, 0, true);
  view.setUint32(0x28, 4, true);
  assert.deepEqual(detectBootVersion(buf), { version: 4, layout: "v3plus" });
});

// =============================================================
//  PARSE BOOT HEADER
// =============================================================

test("parseBootHeader: null input", () => {
  const result = parseBootHeader(null);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "INVALID_INPUT");
});

test("parseBootHeader: Array instead of Uint8Array", () => {
  const result = parseBootHeader([1, 2, 3]);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "INVALID_INPUT");
});

test("parseBootHeader: wrong magic ANDROID!", () => {
  const buf = makeBuf(0x1000);
  buf.set(new TextEncoder().encode("NOTBOOT!"), 0);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "INVALID_MAGIC");
});

test("parseBootHeader: exactly 8 bytes (below 0x700, no magic check fails first)", () => {
  const buf = new Uint8Array(8);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const result = parseBootHeader(buf);
  // magic passes but file is too small -> TRUNCATED_HEADER
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "TRUNCATED_HEADER");
});

test("parseBootHeader: 0x6FF bytes (one byte below minimum)", () => {
  const buf = new Uint8Array(0x6FF);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "TRUNCATED_HEADER");
});

test("parseBootHeader: exactly 0x700 bytes (minimum)", () => {
  const buf = new Uint8Array(0x700);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.version, 0);
});

test("parseBootHeader: very large pageSize = 0", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x24, 0, true); // pageSize = 0 -> code defaults to 2048
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.pageSize, 2048);
});

test("parseBootHeader: pageSize = 1 (not power of 2, below 2048)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x24, 1, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  // pageSize should fall through: || 2048 won't trigger because 1 is truthy
  // So pageSize stays 1, and it should generate a BAD_PAGE_SIZE warning
  const { fields, issues } = result.value;
  assert.ok(fields.pageSize === 1);
  assert.ok(issues.some((i) => i.code === "BAD_PAGE_SIZE"));
});

test("parseBootHeader: pageSize = 4096 (valid power of 2)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x24, 4096, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.pageSize, 4096);
  // No warning expected
  const { issues } = result.value;
  assert.ok(!issues.some((i) => i.code === "BAD_PAGE_SIZE"));
});

test("parseBootHeader: massive kernel size (near uint32 max)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 0xFFFFFFFF, true);
  view.setUint32(0x24, 2048, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.kernelSize, 0xFFFFFFFF);
});

test("parseBootHeader: massive ramdisk size (near uint32 max)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x10, 0xFFFFFFFF, true);
  view.setUint32(0x24, 2048, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.ramdiskSize, 0xFFFFFFFF);
});

// NOTE: V3/V4 detection goes through 0x28 (legacy path) because 0x04 holds magic bytes "OID!".
// Setting version at 0x04 corrupts "ANDROID!" magic, so we set it at 0x28 for V3 detection.
test("parseBootHeader: V3 pageSize = 0 defaults to 4096", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true); // V3 via legacy path (0x04 blocked by magic)
  view.setUint32(0x1C, 0, true); // pageSize = 0
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.pageSize, 4096);
});

test("parseBootHeader: V3 pageSize = 1024 (below 2048, power of 2)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x1C, 1024, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.pageSize, 1024);
  assert.ok(result.value.issues.some((i) => i.code === "BAD_PAGE_SIZE"));
});

test("parseBootHeader: V3 pageSize non-power-of-2", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x1C, 3000, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.ok(result.value.issues.some((i) => i.code === "BAD_PAGE_SIZE"));
});

test("parseBootHeader: V1 fields populated (recovery_dtbo, header_size)", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 1, true);            // V1
  view.setUint32(0x24, 2048, true);         // pageSize
  view.setUint32(0x660, 1024, true);        // recoveryDtboSize
  view.setBigUint64(0x664, 0x80000000n, true); // recoveryDtboOffset
  view.setUint32(0x66C, 0x700, true);       // headerSize
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.recoveryDtboSize, 1024);
  assert.equal(result.value.fields.recoveryDtboOffset, 0x80000000n);
  assert.equal(result.value.fields.headerSize, 0x700);
});

test("parseBootHeader: writes OsPatchLevel correctly in V3/V4", () => {
  for (const v of [3, 4]) {
    const buf = new Uint8Array(0x1000);
    buf.set(BOOT_MAGIC_BYTES, 0);
    const view = new DataView(buf.buffer);
    view.setUint32(0x28, v, true); // version via legacy path
    // osPatchLevel = (2025 << 16) | (7 << 8) | 13 => 2025-07-13
    view.setUint32(0x18, (2025 << 16) | (7 << 8) | 13, true);
    view.setUint32(0x1C, 4096, true);
    const result = parseBootHeader(buf);
    assert.equal(result.ok, true);
    assert.equal(result.value.fields.osPatchLevel, "2025-07-13");
  }
});

test("parseBootHeader: V3/V4 osPatchLevel with year=0 yields null", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x18, 0, true);   // osPatchLevel = 0 => year=0
  view.setUint32(0x1C, 4096, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.osPatchLevel, null);
});

test("parseBootHeader: V3/V4 osPatchLevel with year!=0 but month=0 day=0 gives just year", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x18, (2025 << 16) | (0 << 8) | 0, true); // 2025-00-00
  view.setUint32(0x1C, 4096, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.osPatchLevel, "2025-00");
});

test("parseBootHeader: V3/V4 osPatchLevel with year!=0, month!=0, day=0 gives YYYY-MM", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x18, (2025 << 16) | (7 << 8) | 0, true); // day=0
  view.setUint32(0x1C, 4096, true);
  const result = parseBootHeader(buf);
  assert.equal(result.ok, true);
  assert.equal(result.value.fields.osPatchLevel, "2025-07");
});

// =============================================================
//  DECODE OS VERSION
// =============================================================

test("decodeOsVersion: non-number input", () => {
  assert.equal(decodeOsVersion("foo"), null);
  assert.equal(decodeOsVersion(null), null);
  assert.equal(decodeOsVersion(undefined), null);
});

test("decodeOsVersion: float input", () => {
  // 3.5 is not SafeInteger -> returns null
  assert.equal(decodeOsVersion(3.5), null);
});

test("decodeOsVersion: negative number", () => {
  // negative is safe integer, but decode still works (bit ops negative is fine in JS)
  const result = decodeOsVersion(-1);
  assert.ok(result !== null);
  assert.equal(typeof result.major, "number");
});

test("decodeOsVersion: zero", () => {
  assert.deepEqual(decodeOsVersion(0), { major: 0, minor: 0, patch: 0 });
});

test("decodeOsVersion: maximum practical version field", () => {
  const ver = (0x7F << 25) | (0x7F << 18) | (0x7F << 11);
  assert.deepEqual(decodeOsVersion(ver), { major: 0x7F, minor: 0x7F, patch: 0x7F });
});

test("decodeOsVersion: bits overflowing into adjacent fields", () => {
  const ver = (0x80 << 25) | (0x80 << 18) | (0x80 << 11);
  // each mask is 0x7F, so high bit is masked out
  const decoded = decodeOsVersion(ver);
  assert.equal(decoded.major & 0x80, 0);
  assert.equal(decoded.minor & 0x80, 0);
  assert.equal(decoded.patch & 0x80, 0);
});

// =============================================================
//  FORMAT CMDLINE
// =============================================================

test("formatCmdline: null input returns empty string", () => {
  assert.equal(formatCmdline(null), "");
});

test("formatCmdline: undefined input returns empty string", () => {
  assert.equal(formatCmdline(undefined), "");
});

test("formatCmdline: object input", () => {
  assert.equal(formatCmdline({}), "");
});

test("formatCmdline: number input", () => {
  assert.equal(formatCmdline(42), "");
});

test("formatCmdline: only null bytes", () => {
  assert.equal(formatCmdline("\0\0\0"), "");
});

test("formatCmdline: text beyond PREVIEW_LIMIT (100) truncated", () => {
  const long = "x".repeat(200);
  const result = formatCmdline(long);
  assert.ok(result.length <= 100);
});

test("formatCmdline: all printable chars ASCII range edge", () => {
  // 0x20 to 0x7E are printable
  assert.equal(formatCmdline(" "), " ");
  assert.equal(formatCmdline("~"), "~");
});

test("formatCmdline: 0x7F (DEL) escaped", () => {
  const raw = "a\x7Fb";
  assert.equal(formatCmdline(raw), "a\\x7fb");
});

test("formatCmdline: 0x00 at very start returns empty", () => {
  assert.equal(formatCmdline("\0abc"), "");
});

test("formatCmdline: emoji / unicode above 0x7F", () => {
  // Emoji "😀" has charCodeAt(0) = 0xD83D which is > 0x7E
  assert.ok(formatCmdline("😀").startsWith("\\x"));
});

test("formatCmdline: mixed printable and escapes", () => {
  const raw = "key=\x01\x02value";
  assert.equal(formatCmdline(raw), "key=\\x01\\x02value");
});

// =============================================================
//  ENUMERATE COMPONENTS
// =============================================================

test("enumerateComponents: null/undefined header returns empty array", () => {
  assert.deepEqual(enumerateComponents(null, new Uint8Array(100)), []);
  assert.deepEqual(enumerateComponents(undefined, new Uint8Array(100)), []);
});

test("enumerateComponents: header without fields", () => {
  assert.deepEqual(enumerateComponents({ version: 0, layout: "legacy" }, new Uint8Array(100)), []);
});

test("enumerateComponents: bytes is not Uint8Array", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x24, 2048, true);
  const header = parseBootHeader(buf).value;
  assert.deepEqual(enumerateComponents(header, null), []);
  assert.deepEqual(enumerateComponents(header, "not-an-array"), []);
});

test("enumerateComponents: pageSize 0 -> defaults to 2048 in component layout", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 100, true);  // kernelSize
  view.setUint32(0x24, 0, true);    // pageSize = 0
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const kernel = components.find((c) => c.name === "kernel");
  // parseBootHeader defaults pageSize to 2048 when 0, enumerateComponents also defaults
  assert.equal(kernel.offset, 2048); // pageSize defaulted in component layout
});

test("enumerateComponents: pageSize 1 (<2048) -> defaults to 2048 in component layout", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 100, true);
  view.setUint32(0x24, 1, true); // pageSize = 1, below 2048
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const kernel = components.find((c) => c.name === "kernel");
  // parseBootHeader keeps pageSize 1, but enumerateComponents defaults to 2048
  assert.equal(kernel.offset, 2048);
});

test("enumerateComponents: kernelSize 0 but kernel component still added (not present)", () => {
  // Use legacay V0 with kernelSize=0
  const buf = new Uint8Array(4096);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 0, true);    // kernelSize=0
  view.setUint32(0x10, 512, true);  // ramdiskSize
  view.setUint32(0x24, 2048, true);
  buf.fill(0xCD, 2048, 512);        // ramdisk data at pageSize offset since kernel is 0
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const kernel = components.find((c) => c.name === "kernel");
  assert.equal(kernel.present, false);
  assert.equal(kernel.size, 0);
  // ramdisk should be present
  const ramdisk = components.find((c) => c.name === "ramdisk");
  assert.equal(ramdisk.present, true);
  assert.equal(ramdisk.offset, 2048); // kernel takes 0 aligned pages
});

test("enumerateComponents: V3 kernelSize=0, ramdiskSize>0 => init_boot detection (label)", () => {
  const buf = new Uint8Array(8192);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);        // V3 via legacy path
  view.setUint32(0x08, 0, true);        // kernelSize=0
  view.setUint32(0x0C, 2048, true);     // ramdiskSize
  view.setUint32(0x1C, 2048, true);     // pageSize
  buf.fill(0xCD, 2048, 2048 + 2048);
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const ramdisk = components.find((c) => c.name === "ramdisk");
  assert.equal(ramdisk.label, "Generic Ramdisk");
  assert.equal(ramdisk.present, true);
});

test("enumerateComponents: V3 kernelSize>0, ramdisk>0 => normal label", () => {
  const buf = new Uint8Array(8192);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 3, true);
  view.setUint32(0x08, 1024, true);
  view.setUint32(0x0C, 2048, true);
  view.setUint32(0x1C, 2048, true);
  buf.fill(0xAB, 2048, 2048 + 1024);
  buf.fill(0xCD, 4096, 4096 + 2048);
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const ramdisk = components.find((c) => c.name === "ramdisk");
  assert.equal(ramdisk.label, "Ramdisk");
});

test("enumerateComponents: boundary overflow variant -- component starts past EOF", () => {
  const buf = new Uint8Array(4096);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 4096, true); // kernel larger than pageSize gap: starts at 2048, size 4096 => end=6144 > 4096
  view.setUint32(0x24, 2048, true);
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const kernel = components.find((c) => c.name === "kernel");
  assert.equal(kernel.truncated, true);
  assert.ok(kernel.warning.includes("超出文件范围"));
});

test("enumerateComponents: all components present count", () => {
  const buf = new Uint8Array(24576);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 2048, true);  // kernel
  view.setUint32(0x10, 1024, true);  // ramdisk
  view.setUint32(0x18, 512, true);   // second
  view.setUint32(0x24, 2048, true);
  view.setUint32(0x28, 1, true);     // V1
  view.setUint32(0x660, 256, true);  // recoveryDtboSize
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const present = components.filter(c => c.present);
  assert.equal(present.length, 4); // kernel, ramdisk, second, recovery_dtbo
});

test("enumerateComponents: V2 with dtb and empty second stage", () => {
  const buf = new Uint8Array(24576);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 2048, true);
  view.setUint32(0x10, 1024, true);
  view.setUint32(0x18, 0, true);     // secondSize=0
  view.setUint32(0x24, 2048, true);
  view.setUint32(0x28, 2, true);     // V2
  view.setUint32(0x660, 0, true);    // no recovery_dtbo
  view.setUint32(0x670, 512, true);  // dtbSize
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const second = components.find((c) => c.name === "second");
  assert.equal(second.present, false);
  const dtb = components.find((c) => c.name === "dtb");
  assert.equal(dtb.present, true);
  assert.equal(dtb.size, 512);
});

test("enumerateComponents: V4 without signature (signatureSize=0)", () => {
  const buf = new Uint8Array(16384);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x04, 4, true);
  view.setUint32(0x08, 2048, true);
  view.setUint32(0x0C, 1024, true);
  view.setUint32(0x1C, 4096, true);
  view.setUint32(0x28, 0, true);     // signatureSize = 0
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const sig = components.find((c) => c.name === "boot_signature");
  // When signatureSize=0, addComponent is NOT called (guarded by `if (version === 4 && fields.signatureSize > 0)`)
  assert.equal(sig, undefined); // no boot_signature component at all
});

// =============================================================
//  HEX DUMP
// =============================================================

test("hexDump: null input", () => {
  assert.deepEqual(hexDump(null, 0, 1), []);
});

test("hexDump: negative length", () => {
  const bytes = new Uint8Array([0x41]);
  assert.deepEqual(hexDump(bytes, 0, -1), []);
});

test("hexDump: length=0", () => {
  const bytes = new Uint8Array([0x41]);
  assert.deepEqual(hexDump(bytes, 0, 0), []);
});

test("hexDump: offset negative — BUG: crashes instead of returning empty", () => {
  const bytes = new Uint8Array([0x41, 0x42]);
  // BUG: hexDump guard misses `offset < 0`, causing bytes[negative] access -> TypeError
  assert.throws(() => hexDump(bytes, -1, 1), TypeError);
});

test("hexDump: offset equal to length (exactly at end)", () => {
  const bytes = new Uint8Array([0x41]);
  assert.deepEqual(hexDump(bytes, 1, 1), []);
});

test("hexDump: partial last row (only 3 bytes)", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x43]);
  const rows = hexDump(bytes, 0, 3);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].hex, "41 42 43");
  assert.equal(rows[0].ascii, "ABC");
});

test("hexDump: exact row boundary (8 bytes)", () => {
  const bytes = new TextEncoder().encode("12345678");
  const rows = hexDump(bytes, 0, 8);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ascii, "12345678");
});

test("hexDump: 9 bytes produces 2 rows", () => {
  const bytes = new TextEncoder().encode("123456789");
  const rows = hexDump(bytes, 0, 9);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].ascii, "12345678");
  assert.equal(rows[1].ascii, "9");
});

test("hexDump: large dump with many rows", () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const rows = hexDump(bytes, 0, 256);
  assert.equal(rows.length, 32); // 256 / 8
  assert.equal(rows[0].offset, "00000000");
  assert.equal(rows[31].offset, "000000f8");
});

test("hexDump: long hex string spacing with 8-byte gap", () => {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = 0x41 + i;
  const rows = hexDump(bytes, 0, 16);
  assert.equal(rows.length, 2);
  // row 1: bytes 0-7, positions: 0-7
  // After byte 7 (i=7): (7-0)%8 === 7%8=7 != 0 so space, then byte 8
  // Actually positions 0-7 within the row. Byte at i=pos->rowPos=i-posStart
  // i=0: hex="41"
  // i=1: (1-0)%8==1%8=1!=0 => " " then "42"
  // i=2...7: spaces + hex
  // i=8: new row, hex="49"
  // i=9: (9-8)%8==1!=0 => " " then "4A"
  assert.equal(rows[0].hex, "41 42 43 44 45 46 47 48");
  assert.equal(rows[1].hex, "49 4a 4b 4c 4d 4e 4f 50");
});

// =============================================================
//  BUILD ZIP
// =============================================================

test("buildZip: null bytes", () => {
  assert.equal(buildZip([], null, "test.zip"), null);
});

test("buildZip: empty components array", () => {
  assert.equal(buildZip([], new Uint8Array(100), "test.zip"), null);
});

test("buildZip: all truncated components", () => {
  const components = [
    { name: "kernel", label: "Kernel", offset: 0, size: 10000, end: 10000, present: true, truncated: true, warning: "x" },
  ];
  assert.equal(buildZip(components, new Uint8Array(100), "test.zip"), null);
});

test("buildZip: all zero-size components", () => {
  const components = [
    { name: "kernel", label: "Kernel", offset: 0, size: 0, end: 0, present: true, truncated: false, warning: null },
  ];
  // size>0 filter excludes it
  assert.equal(buildZip(components, new Uint8Array(100), "test.zip"), null);
});

test("buildZip: mix of valid and invalid components", () => {
  const buf = new Uint8Array(100);
  buf.fill(0x41);
  const components = [
    { name: "kernel", label: "Kernel", offset: 0, size: 50, end: 50, present: true, truncated: false, warning: null },
    { name: "ramdisk", label: "Ramdisk", offset: 50, size: 0, end: 50, present: false, truncated: false, warning: null },
    { name: "dtb", label: "DTB", offset: 200, size: 100, end: 300, present: true, truncated: true, warning: "truncated" },
  ];
  const zip = buildZip(components, buf, "test.zip");
  assert.ok(zip instanceof Uint8Array);
  assert.ok(zip.length > 22);
  // Only kernel should be included
  const eocd = new DataView(zip.buffer, zip.byteOffset + zip.length - 22, 4);
  assert.equal(eocd.getUint32(0, true), 0x06054b50);
  // entry count = 1
  const count = new DataView(zip.buffer, zip.byteOffset + zip.length - 22 + 8, 2);
  assert.equal(count.getUint16(0, true), 1);
});

test("buildZip: CRC-32 consistency check (known value)", () => {
  const buf = new Uint8Array([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]); // "123456789"
  const components = [
    { name: "test", label: "Test", offset: 0, size: buf.length, end: buf.length, present: true, truncated: false, warning: null },
  ];
  const zip = buildZip(components, buf, "test.zip");
  // Known CRC-32 for "123456789" with 0xEDB88320 polynomial = 0xCBF43926
  const crcInZip = new DataView(zip.buffer, zip.byteOffset + 14, 4).getUint32(0, true);
  // CRC-32 in ZIP is little-endian uint32
  assert.equal(crcInZip, 0xCBF43926);
});

test("buildZip: archive name parameter does not affect ZIP content", () => {
  const buf = new Uint8Array([0x41]);
  const components = [
    { name: "comp", label: "Comp", offset: 0, size: 1, end: 1, present: true, truncated: false, warning: null },
  ];
  const zip1 = buildZip(components, buf, "a.zip");
  const zip2 = buildZip(components, buf, "b.zip");
  assert.deepEqual([...zip1], [...zip2]); // archiveName unused
});

// =============================================================
//  SERIALIZE BOOT REPORT
// =============================================================

test("serializeBootReport: null header and null components", () => {
  const result = serializeBootReport(null, null, "json");
  assert.equal(result, "[]\n");
});

test("serializeBootReport: unknown format returns empty", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x24, 2048, true);
  const header = parseBootHeader(buf).value;
  const components = enumerateComponents(header, buf);
  const result = serializeBootReport(header, components, "xml");
  assert.equal(result, "");
});

test("serializeBootReport: header with BigInt values serialized as strings", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 2, true);
  view.setUint32(0x24, 2048, true);
  view.setBigUint64(0x674, 0x123456789ABCDEF0n, true);
  const header = parseBootHeader(buf).value;
  const json = serializeBootReport(header, [], "json");
  const parsed = JSON.parse(json);
  const dtbAddr = parsed.find((r) => r.field === "dtbAddr");
  assert.ok(dtbAddr);
  assert.equal(dtbAddr.value, "1311768467463790320"); // = 0x123456789ABCDEF0n decimal string
});

test("serializeBootReport: CSV output with BigInt", () => {
  const buf = new Uint8Array(0x1000);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 2, true);
  view.setUint32(0x24, 2048, true);
  view.setBigUint64(0x674, 0xABCDEFn, true);
  const header = parseBootHeader(buf).value;
  const csv = serializeBootReport(header, [], "csv");
  assert.ok(csv.includes("category"));
  assert.ok(csv.includes("dtbAddr"));
});

// =============================================================
//  DEX REGRESSION (existing functions untouched?)
// =============================================================

test("regression: applyRepeatedKeyXor identity key", () => {
  const bytes = new Uint8Array([0x10, 0x20, 0x30]);
  assert.deepEqual(applyRepeatedKeyXor(bytes, new Uint8Array([0x00]), 0), bytes);
});

test("regression: applyRepeatedKeyXor offset=0", () => {
  const src = new Uint8Array([0x10, 0x20]);
  const result = applyRepeatedKeyXor(src, new Uint8Array([0xff]), 0);
  assert.deepEqual([...result], [0xEF, 0xDF]);
});

test("regression: parseXorKey with emoji returns bytes", () => {
  const result = parseXorKey("✓");
  assert.equal(result.ok, true);
  assert.ok(result.value.length > 0);
});

test("regression: parseOffset with max value at boundary", () => {
  assert.deepEqual(parseOffset("255", 256), { ok: true, value: 255 });
  assert.equal(parseOffset("256", 256).ok, false); // offset >= fileSize
});

test("regression: buildOutputName with no extension", () => {
  assert.equal(buildOutputName("noext"), "noext.xor.dex");
});

test("regression: buildOutputName with multiple dots", () => {
  assert.equal(buildOutputName("a.b.c.d"), "a.b.c.xor.dex");
});

test("regression: serializeAnalysisRows empty array", () => {
  assert.equal(serializeAnalysisRows([], "json"), "[]\n");
  assert.equal(serializeAnalysisRows([], "csv"), "\n");
});

test("regression: analyzeUnityFile with empty input", () => {
  const result = analyzeUnityFile(new Uint8Array(0));
  assert.equal(result.format, "Unknown");
  assert.equal(result.valid, false);
});

// =============================================================
//  INTEGRATION: end-to-end V0 flow
// =============================================================

test("integration: V0 boot image full lifecycle", () => {
  const buf = new Uint8Array(12288);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 1024, true);
  view.setUint32(0x10, 512, true);
  view.setUint32(0x18, 256, true);
  view.setUint32(0x24, 2048, true);
  buf.fill(0xAB, 2048, 2048 + 1024);   // kernel (fill from 2048 to 2048+1024)
  buf.fill(0xCD, 4096, 4096 + 512);    // ramdisk (align: 2048+ceil(1024/2048)*2048 = 4096)
  buf.fill(0xEF, 8192, 8192 + 256);    // second (align: 4096+ceil(512/2048)*2048 = 8192)

  const magic = validateBootMagic(buf);
  assert.equal(magic.valid, true);

  const version = detectBootVersion(buf);
  assert.equal(version.version, 0);

  const headerResult = parseBootHeader(buf);
  assert.equal(headerResult.ok, true);
  const header = headerResult.value;

  const components = enumerateComponents(header, buf);
  assert.ok(components.some(c => c.name === "kernel" && c.present));
  assert.ok(components.some(c => c.name === "ramdisk" && c.present));
  assert.ok(components.some(c => c.name === "second" && c.present));

  const hexRows = hexDump(buf, 2048, 16);
  assert.ok(hexRows.length > 0);
  assert.equal(hexRows[0].hex, "ab ab ab ab ab ab ab ab");

  const zip = buildZip(components, buf, "boot.zip");
  assert.ok(zip instanceof Uint8Array);

  const json = serializeBootReport(header, components, "json");
  const parsed = JSON.parse(json);
  assert.ok(Array.isArray(parsed));
});
