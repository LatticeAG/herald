/** TV-H--01..05, 49 — parser, JCS canonicalization, bit ordering. */

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, parseJsonStrict, b64uDecode, digest } from "@latticeag/herald-core";
import { FX, bits, enc, worldAt } from "./harness.ts";
import { handleRequest, Metrics, RateLimiter } from "../../packages/worker/src/http.ts";

test("TV-H--01 canonical object ordering", () => {
  const out = canonicalize(JSON.parse('{"b":2,"a":1}'));
  assert.equal(Buffer.from(out).toString(), '{"a":1,"b":2}');
});

test("TV-H--02 duplicate-key parser differential over HTTP", () => {
  const w = worldAt(2);
  const metrics = new Metrics();
  const res = handleRequest({
    method: "POST", path: `/v1/roots/${FX.R}/commands`, query: new Map(),
    headers: new Map(), body: new TextEncoder().encode('{"v":1,"v":1}'), ip: "t",
  }, {
    registry: { lookup: () => w.d, all: () => [w.d] }, metrics, limiter: new RateLimiter(),
    limits: { publicGetPerMin: 120, publicFreshPerMin: 120, writePerActorPerMin: 30, revocationReservePerMin: 60 },
  });
  assert.equal(res.status, 400);
  const body = JSON.parse(Buffer.from(res.body).toString());
  assert.equal(body.error.code, "DUPLICATE_KEY");
  assert.equal(body.error.retryable, false);
  assert.equal(String(w.db.get("SELECT seq FROM root_state WHERE singleton=1")!["seq"]), "3");
});

test("TV-H--03 unsafe numeric value", () => {
  const p = parseJsonStrict(new TextEncoder().encode('{"n":9007199254740992}'));
  assert.equal(p.ok, false);
  if (!p.ok) assert.equal(p.code, "NUMBER_INVALID");
});

test("TV-H--04 negative zero and exponent rejection", () => {
  for (const s of ['{"n":-0}', '{"n":1e0}']) {
    const p = parseJsonStrict(new TextEncoder().encode(s));
    assert.equal(p.ok, false, s);
    if (!p.ok) assert.equal(p.code, "NUMBER_INVALID", s);
  }
});

test("TV-H--05 unicode is not normalized", () => {
  const a = canonicalize({ s: "é" });
  const b = canonicalize({ s: "é" });
  assert.equal(Buffer.from(a).toString("hex"), "7b2273223a22c3a9227d");
  assert.equal(Buffer.from(b).toString("hex"), "7b2273223a2265cc81227d");
  assert.notEqual(digest("EVIDENCE", { x: "é" }), digest("EVIDENCE", { x: "é" }));
});

test("TV-H--49 bit ordering", () => {
  const raw = b64uDecode(bits(0, 7, 8, 17))!;
  assert.equal(raw.length, 16384);
  assert.equal(raw[0], 0x81);
  assert.equal(raw[1], 0x01);
  assert.equal(raw[2], 0x02);
  for (let i = 3; i < raw.length; i++) assert.equal(raw[i], 0);
});
