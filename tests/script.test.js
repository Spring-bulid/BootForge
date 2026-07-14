import assert from "node:assert/strict";
import { test, describe } from "node:test";
import {
  validateBootMagic, detectBootVersion, parseBootHeader,
  decodeOsVersion, formatCmdline, enumerateComponents,
  hexDump, buildZip, serializeBootReport, serializeAnalysisRows,
  detectComponentFormat,
  findKernelVersion, parseCpioListing, parseDtbInfo, decompressGzip,
} from "../script.js";

const BOOT_MAGIC_BYTES = new TextEncoder().encode("ANDROID!");

/* ── Fixture builders ─────────────────────────────────────── */

function createBootFixture(overrides = {}) {
  const buf = new Uint8Array(8192);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  const defaults = {
    kernelSize: 512, kernelAddr: 0x10008000,
    ramdiskSize: 256, ramdiskAddr: 0x11000000,
    secondSize: 0, secondAddr: 0,
    tagsAddr: 0x10000100, pageSize: 2048,
  };
  const opts = { ...defaults, ...overrides };
  view.setUint32(0x08, opts.kernelSize, true);
  view.setUint32(0x0C, opts.kernelAddr, true);
  view.setUint32(0x10, opts.ramdiskSize, true);
  view.setUint32(0x14, opts.ramdiskAddr, true);
  view.setUint32(0x18, opts.secondSize, true);
  view.setUint32(0x1C, opts.secondAddr, true);
  view.setUint32(0x20, opts.tagsAddr, true);
  view.setUint32(0x24, opts.pageSize, true);
  const kernelOff = opts.pageSize;
  if (opts.kernelSize) buf.fill(0xAB, kernelOff, kernelOff + opts.kernelSize);
  const ramdiskOff = kernelOff + Math.ceil(opts.kernelSize / opts.pageSize) * opts.pageSize;
  if (opts.ramdiskSize) buf.fill(0xCD, ramdiskOff, ramdiskOff + opts.ramdiskSize);
  return buf;
}

function createV2BootFixture() {
  const buf = createBootFixture({ kernelSize: 512, ramdiskSize: 256, pageSize: 2048 });
  const view = new DataView(buf.buffer);
  view.setUint32(0x28, 2, true);           // header_version=2
  view.setUint32(0x2C, 0x000A0000, true);  // osVersion
  view.setUint32(0x660, 128, true);        // recoveryDtboSize
  view.setBigUint64(0x664, 0x2000n, true); // recoveryDtboOffset
  view.setUint32(0x66C, 48, true);         // headerSize
  view.setUint32(0x670, 64, true);         // dtbSize
  view.setBigUint64(0x674, 0x3000n, true); // dtbAddr
  const ps = 2048;
  const ro = ps + Math.ceil(512 / ps) * ps + Math.ceil(256 / ps) * ps;
  buf.fill(0x33, ro, ro + 128);           // recovery dtbo data
  buf.fill(0x22, 0x3000, 0x3000 + 64);    // dtb data
  return buf;
}

function createV4BootFixture() {
  // AOSP boot_img_hdr_v4
  const buf = new Uint8Array(16384);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 4096, true);       // kernelSize
  view.setUint32(0x0C, 2048, true);       // ramdiskSize
  view.setUint32(0x10, 0x000D0000, true); // osVersion
  view.setUint32(0x14, 48, true);         // headerSize
  view.setUint32(0x28, 4, true);          // header_version=4
  view.setUint32(0x2C, 512, true);        // signatureSize
  const ps = 4096;
  buf.fill(0xAB, ps, ps + 4096);
  buf.fill(0xCD, ps + 4096, ps + 4096 + 2048);
  buf.fill(0x55, ps + 4096 + 4096, ps + 4096 + 4096 + 512);
  return buf;
}

/* ── validateBootMagic ────────────────────────────────────── */

test("validateBootMagic: valid magic", () => {
  const buf = new Uint8Array(BOOT_MAGIC_BYTES);
  assert.equal(validateBootMagic(buf).valid, true);
});

test("validateBootMagic: wrong magic", () => {
  const buf = new Uint8Array([0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x00]);
  assert.equal(validateBootMagic(buf).valid, false);
});

test("validateBootMagic: empty and too short", () => {
  assert.equal(validateBootMagic(new Uint8Array(0)).valid, false);
  assert.equal(validateBootMagic(new Uint8Array(7)).valid, false);
});

test("validateBootMagic: case sensitivity", () => {
  const buf = new TextEncoder().encode("android!");
  assert.equal(validateBootMagic(buf).valid, false);
});

/* ── detectBootVersion ────────────────────────────────────── */

test("detectBootVersion: V0 detection", () => {
  const buf = createBootFixture();
  assert.equal(detectBootVersion(buf).version, 0);
});

test("detectBootVersion: V1 detection", () => {
  const buf = createBootFixture();
  new DataView(buf.buffer).setUint32(0x28, 1, true);
  assert.equal(detectBootVersion(buf).version, 1);
});

test("detectBootVersion: V2 detection", () => {
  const buf = createBootFixture();
  new DataView(buf.buffer).setUint32(0x28, 2, true);
  assert.equal(detectBootVersion(buf).version, 2);
});

test("detectBootVersion: V3 detection", () => {
  const buf = createBootFixture();
  new DataView(buf.buffer).setUint32(0x28, 3, true);
  assert.equal(detectBootVersion(buf).version, 3);
});

test("detectBootVersion: V4 detection", () => {
  const buf = createBootFixture();
  new DataView(buf.buffer).setUint32(0x28, 4, true);
  assert.equal(detectBootVersion(buf).version, 4);
});

/* ── parseBootHeader ──────────────────────────────────────── */

test("parseBootHeader: V0 fields", () => {
  const buf = createBootFixture({ kernelSize: 512, ramdiskSize: 256, pageSize: 2048 });
  const r = parseBootHeader(buf);
  assert.equal(r.ok, true);
  assert.equal(r.value.version, 0);
  assert.equal(r.value.layout, "legacy");
  assert.equal(r.value.fields.kernelSize, 512);
  assert.equal(r.value.fields.ramdiskSize, 256);
  assert.equal(r.value.fields.pageSize, 2048);
});

test("parseBootHeader: V2 fields", () => {
  const buf = createV2BootFixture();
  const r = parseBootHeader(buf);
  assert.equal(r.ok, true);
  assert.equal(r.value.version, 2);
  assert.equal(r.value.fields.dtbSize, 64);
  assert.equal(r.value.fields.recoveryDtboSize, 128);
});

test("parseBootHeader: V4 fields", () => {
  const buf = createV4BootFixture();
  const r = parseBootHeader(buf);
  assert.equal(r.ok, true);
  assert.equal(r.value.version, 4);
  assert.equal(r.value.layout, "v3plus");
  assert.equal(r.value.fields.kernelSize, 4096);
  assert.equal(r.value.fields.ramdiskSize, 2048);
  assert.equal(r.value.fields.headerSize, 48);
  assert.equal(r.value.fields.signatureSize, 512);
});

test("parseBootHeader: truncated file", () => {
  const buf = new Uint8Array(32);
  buf.set(BOOT_MAGIC_BYTES, 0);
  assert.equal(parseBootHeader(buf).ok, false);
});

test("parseBootHeader: handles unknown header_version gracefully", () => {
  const buf = createBootFixture();
  new DataView(buf.buffer).setUint32(0x28, 99, true);
  const r = parseBootHeader(buf);
  assert.equal(r.ok, true);
  assert.equal(r.value.version, 0);
});

/* ── decodeOsVersion ──────────────────────────────────────── */

test("decodeOsVersion: known value", () => {
  const ver = (13 << 25) | (0 << 18) | (0 << 11);
  const d = decodeOsVersion(ver);
  assert.equal(d.major, 13);
  assert.equal(d.minor, 0);
  assert.equal(d.patch, 0);
});

test("decodeOsVersion: non-number returns null", () => {
  assert.equal(decodeOsVersion(null), null);
  assert.equal(decodeOsVersion("abc"), null);
});

/* ── formatCmdline ────────────────────────────────────────── */

test("formatCmdline: printable", () => {
  assert.equal(formatCmdline("console=tty0"), "console=tty0");
});

test("formatCmdline: null bytes", () => {
  assert.equal(formatCmdline("hello\0world"), "hello");
});

test("formatCmdline: non-printable chars", () => {
  const s = formatCmdline("\x01\x02");
  assert.ok(s.includes("\\x01"));
  assert.ok(s.includes("\\x02"));
});

test("formatCmdline: empty and non-string", () => {
  assert.equal(formatCmdline(""), "");
  assert.equal(formatCmdline(null), "");
});

/* ── enumerateComponents ──────────────────────────────────── */

test("enumerateComponents: V0 components", () => {
  const buf = createBootFixture({ kernelSize: 512, ramdiskSize: 256 });
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const kernel = c.find((x) => x.name === "kernel");
  assert.equal(kernel.present, true);
  assert.equal(kernel.size, 512);
  const ramdisk = c.find((x) => x.name === "ramdisk");
  assert.equal(ramdisk.present, true);
  assert.equal(ramdisk.size, 256);
});

test("enumerateComponents: V2 with dtb", () => {
  const buf = createV2BootFixture();
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const dtb = c.find((x) => x.name === "dtb");
  assert.ok(dtb);
  assert.equal(dtb.size, 64);
});

test("enumerateComponents: V4 boot image", () => {
  const buf = createV4BootFixture();
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const kernel = c.find((x) => x.name === "kernel");
  assert.equal(kernel.present, true);
  assert.equal(kernel.size, 4096);
  const sig = c.find((x) => x.name === "boot_signature");
  assert.ok(sig);
  assert.equal(sig.size, 512);
});

test("enumerateComponents: boundary overflow", () => {
  const buf = new Uint8Array(4096);
  buf.set(BOOT_MAGIC_BYTES, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 8192, true);
  view.setUint32(0x24, 2048, true);
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const kernel = c.find((x) => x.name === "kernel");
  assert.equal(kernel.truncated, true);
  assert.ok(kernel.warning);
});

test("enumerateComponents: zero-size components", () => {
  const buf = createBootFixture({ kernelSize: 0, ramdiskSize: 0 });
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  assert.equal(c.every((x) => !x.present), true);
});

/* ── detectComponentFormat ────────────────────────────────── */

test("detectComponentFormat: gzip", () => {
  const buf = new Uint8Array([0x1F, 0x8B, 0x08, 0x00]);
  assert.equal(detectComponentFormat(buf, 0, 4), ".gz");
});

test("detectComponentFormat: lz4", () => {
  const buf = new Uint8Array([0x04, 0x22, 0x4D, 0x18]);
  assert.equal(detectComponentFormat(buf, 0, 4), ".lz4");
});

test("detectComponentFormat: xz", () => {
  const buf = new Uint8Array([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
  assert.equal(detectComponentFormat(buf, 0, 6), ".xz");
});

test("detectComponentFormat: unknown", () => {
  const buf = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
  assert.equal(detectComponentFormat(buf, 0, 4), ".bin");
});

test("detectComponentFormat: too small", () => {
  assert.equal(detectComponentFormat(new Uint8Array(1), 0, 1), ".bin");
});

/* ── hexDump ──────────────────────────────────────────────── */

test("hexDump: standard rows", () => {
  const buf = new Uint8Array(24).fill(0x41);
  const rows = hexDump(buf, 0, 24);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].offset, "00000000");
  assert.ok(rows[0].hex.includes("41"));
});

test("hexDump: single byte", () => {
  const rows = hexDump(new Uint8Array([0xFF]), 0, 1);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ascii, ".");
});

test("hexDump: printable ASCII", () => {
  const rows = hexDump(new TextEncoder().encode("ABCD"), 0, 4);
  assert.equal(rows[0].ascii, "ABCD");
});

test("hexDump: non-printable chars", () => {
  const rows = hexDump(new Uint8Array([0x00, 0x01, 0x7F]), 0, 3);
  assert.equal(rows[0].ascii, "...");
});

test("hexDump: empty for out-of-bounds", () => {
  assert.equal(hexDump(new Uint8Array(10), 20, 5).length, 0);
  assert.equal(hexDump(new Uint8Array(10), -1, 5).length, 0);
});

/* ── buildZip ─────────────────────────────────────────────── */

test("buildZip: valid ZIP with components", () => {
  const buf = createBootFixture({ kernelSize: 512, ramdiskSize: 256 });
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const zip = buildZip(c, buf, "test.zip");
  assert.ok(zip instanceof Uint8Array);
  assert.ok(zip.length > 0);
  // Check EOCD signature at end
  const view = new DataView(zip.buffer, zip.byteOffset + zip.length - 22, 4);
  assert.equal(view.getUint32(0, true), 0x06054b50);
});

test("buildZip: single component", () => {
  const buf = createBootFixture({ kernelSize: 128, ramdiskSize: 0 });
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const zip = buildZip(c, buf, "test.zip");
  assert.ok(zip instanceof Uint8Array);
});

test("buildZip: no valid components returns null", () => {
  assert.equal(buildZip([], null, "test.zip"), null);
});

/* ── serializeBootReport ──────────────────────────────────── */

test("serializeBootReport: JSON output", () => {
  const buf = createBootFixture();
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const json = serializeBootReport(h, c, "json");
  assert.ok(typeof json === "string");
  JSON.parse(json);
});

test("serializeBootReport: CSV output", () => {
  const buf = createBootFixture();
  const h = parseBootHeader(buf).value;
  const c = enumerateComponents(h, buf);
  const csv = serializeBootReport(h, c, "csv");
  assert.ok(typeof csv === "string");
  assert.ok(csv.includes("category"));
});

/* ── findKernelVersion ────────────────────────────────────── */

test("findKernelVersion: finds Linux version", () => {
  const s = "some data Linux version 5.10.157-android13 (build@host) (clang) #1 SMP PREEMPT Tue Jan 1 00:00:00 CST 2023\nmore data";
  const buf = new TextEncoder().encode(s);
  const v = findKernelVersion(buf);
  assert.ok(v.includes("Linux version"));
  assert.ok(v.includes("5.10.157"));
});

test("findKernelVersion: not found", () => {
  const buf = new Uint8Array(100).fill(0);
  assert.equal(findKernelVersion(buf), null);
});

test("findKernelVersion: non-array", () => {
  assert.equal(findKernelVersion(null), null);
});

/* ── parseCpioListing ─────────────────────────────────────── */

test("parseCpioListing: non-array", () => {
  assert.deepEqual(parseCpioListing(null), []);
});

test("parseCpioListing: too short", () => {
  assert.deepEqual(parseCpioListing(new Uint8Array(10)), []);
});

/* ── parseDtbInfo ─────────────────────────────────────────── */

test("parseDtbInfo: null for non-dtb", () => {
  assert.equal(parseDtbInfo(new Uint8Array(100)), null);
});

test("parseDtbInfo: too small", () => {
  assert.equal(parseDtbInfo(new Uint8Array(10)), null);
});
