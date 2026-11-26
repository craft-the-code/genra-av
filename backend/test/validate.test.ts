import { test } from "node:test";
import assert from "node:assert/strict";
import { checkSampleBody, parseReport, parseSampleMeta, MAX_SAMPLE_BYTES } from "../src/validate.ts";

const base = {
  kind: "bug",
  app_version: "0.1.0",
  os: "windows",
  install_id: "3f1c2a7e-9b4d-4c1a-8e2f-0a1b2c3d4e5f",
};
const sha = "a".repeat(64);

test("accepts a minimal bug report", () => {
  const r = parseReport(base);
  assert.equal(r.ok, true);
});

test("false positive needs the file hash", () => {
  assert.deepEqual(parseReport({ ...base, kind: "false_positive" }), { ok: false, error: "false_positive needs sha256" });
  assert.equal(parseReport({ ...base, kind: "false_positive", sha256: sha }).ok, true);
});

test("rejects unknown kind, bad version, bad os, bad install id", () => {
  for (const bad of [{ kind: "spam" }, { app_version: "latest" }, { os: "android" }, { install_id: "1234" }]) {
    assert.equal(parseReport({ ...base, ...bad }).ok, false, JSON.stringify(bad));
  }
});

test("caps the note and checks optional fields", () => {
  assert.equal(parseReport({ ...base, note: "x".repeat(2001) }).ok, false);
  assert.equal(parseReport({ ...base, email: "not-an-email" }).ok, false);
  assert.equal(parseReport({ ...base, sha256: "ABC" }).ok, false);
  assert.equal(parseReport({ ...base, rule_id: "GENRA.Office.Kangatang.A", email: "a@b.vn", note: " hi " }).ok, true);
});

test("rejects non-objects", () => {
  for (const bad of [null, [], "x", 1]) assert.equal(parseReport(bad).ok, false);
});

const headers = (extra: Record<string, string> = {}) =>
  new Headers({
    "x-genra-consent": "yes",
    "x-genra-version": "0.1.0",
    "x-genra-os": "windows",
    "x-genra-install": base.install_id,
    "x-genra-doc-sha256": sha,
    ...extra,
  });

test("sample metadata needs consent and valid fields", () => {
  assert.equal(parseSampleMeta(headers()).ok, true);
  assert.equal(parseSampleMeta(headers({ "x-genra-consent": "no" })).ok, false);
  assert.equal(parseSampleMeta(headers({ "x-genra-doc-sha256": "zz" })).ok, false);
});

test("sample body must be a small OLE2 file", () => {
  const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0]);
  assert.equal(checkSampleBody(ole).ok, true);
  assert.equal(checkSampleBody(new Uint8Array([0x50, 0x4b, 3, 4])).ok, false, "zip (whole .xlsx) refused");
  assert.equal(checkSampleBody(new Uint8Array()).ok, false);
  const big = new Uint8Array(MAX_SAMPLE_BYTES + 1);
  big.set(ole);
  assert.equal(checkSampleBody(big).ok, false);
});
