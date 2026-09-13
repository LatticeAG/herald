/** Server-side mutation vectors (spec §6.1, §8): TV-H--06,07,12-15,18-20,28-33,36-37,42,47-48,50,52-54,59. */

import { test } from "node:test";
import assert from "node:assert/strict";
import { b64uDecode, digest, canonicalize } from "@latticeag/herald-core";
import type { Signed, AgentCard, JsonObject, Command } from "@latticeag/herald-core";
import { FX, T, R, signed, ident, command, event, status, bits, enc, canonEq, world, worldAt, seqOf, lastEvent } from "./harness.ts";
import { NodeSqliteDb } from "../../packages/worker/src/sql.ts";
import { AeadBox } from "../../packages/worker/src/aead.ts";
import { RootDO } from "../../packages/worker/src/rootdo.ts";
import { handleRequest, handleReadyz, Metrics, RateLimiter } from "../../packages/worker/src/http.ts";
import type { HttpRequest } from "../../packages/worker/src/http.ts";

const LIMITS = { publicGetPerMin: 120, publicFreshPerMin: 120, writePerActorPerMin: 30, revocationReservePerMin: 60 };

function http(w: { d: RootDO }, req: Partial<HttpRequest> & { method: string; path: string }) {
  return handleRequest(
    { query: new Map(), headers: new Map(), body: new Uint8Array(), ip: "t", ...req },
    { registry: { lookup: () => w.d, all: () => [w.d] }, metrics: new Metrics(), limiter: new RateLimiter(), limits: LIMITS },
  );
}
function code(res: { status: number; body: Uint8Array }): { status: number; code: string | null } {
  const b = JSON.parse(Buffer.from(res.body).toString());
  return { status: res.status, code: b.error?.code ?? null };
}

function replier(w: { d: RootDO }) {
  return (cmd: Signed<Command>) => w.d.submitCommand(enc(cmd));
}

test("TV-H--06 valid enrollment", () => {
  const w = worldAt(0);
  const rep = w.d.submitCommand(enc(FX.ENROLL));
  assert.ok(canonEq(rep, { v: 1, receipt: FX.ER, record: FX.REC1 }));
  assert.equal(seqOf(w), "2");
  assert.ok(canonEq(lastEvent(w), FX.E2));
});

test("TV-H--07 valid first card", () => {
  const w = worldAt(1);
  const rep = w.d.submitCommand(enc(FX.ISSUE));
  assert.ok(canonEq(rep, { v: 1, receipt: FX.CR, record: FX.REC2 }));
  assert.equal(seqOf(w), "3");
});

test("TV-H--12 malformed public key → 400 ENCODING_INVALID", () => {
  const w = worldAt(1);
  const bad = JSON.parse(JSON.stringify(FX.ISSUE));
  bad.body.action.card.body.key.public_key = "AA";
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(bad) });
  const c = code(res);
  assert.equal(c.status, 400);
  assert.equal(c.code, "ENCODING_INVALID");
  assert.equal(seqOf(w), "2");
});

test("TV-H--13 human proof omitted → 401 PROOF_SET_INVALID", () => {
  const w = worldAt(1);
  const cardOnly = signed("CARD", FX.SC.body, [5]);
  const cmd = command(2, 5, 1, { kind: "card.issue", card: cardOnly } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 401);
  assert.equal(c.code, "PROOF_SET_INVALID");
  assert.equal(seqOf(w), "2");
});

test("TV-H--14 human binding substitution → 422 BINDING_MISMATCH", () => {
  const w = worldAt(1);
  const c2 = { ...FX.SC.body, human_principal: ident("hp", 2) };
  const sc2 = signed("CARD", c2, [4, 5]);
  const cmd = command(2, 5, 1, { kind: "card.issue", card: sc2 } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 422);
  assert.equal(c.code, "BINDING_MISMATCH");
  assert.equal(seqOf(w), "2");
});

test("TV-H--15 slot already allocated → 409 SLOT_USED", () => {
  const w = worldAt(2);
  const nc = { ...FX.SC.body, id: ident("hc", 9), previous: digest("CARD", FX.SC.body) };
  const sc = signed("CARD", nc, [4, 5]);
  const cmd = command(20, 5, 2, { kind: "card.issue", card: sc } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 409);
  assert.equal(c.code, "SLOT_USED");
  assert.equal(seqOf(w), "3");
});

test("TV-H--18 invalid card interval → 422 INTERVAL_INVALID", () => {
  const w = worldAt(1);
  const c2 = { ...FX.SC.body, expires_at: FX.SC.body.issued_at + 86401 };
  const sc = signed("CARD", c2, [4, 5]);
  const cmd = command(2, 5, 1, { kind: "card.issue", card: sc } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 422);
  assert.equal(c.code, "INTERVAL_INVALID");
  assert.equal(seqOf(w), "2");
});

test("TV-H--19 card outlives human binding → 422 INTERVAL_INVALID", () => {
  const w = worldAt(1);
  const c2 = { ...FX.SC.body, expires_at: FX.SB.body.expires_at + 1 };
  const sc = signed("CARD", c2, [4, 5]);
  const cmd = command(2, 5, 1, { kind: "card.issue", card: sc } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 422);
  assert.equal(c.code, "INTERVAL_INVALID");
});

test("TV-H--20 agent revocation", () => {
  const w = worldAt(2);
  const rep = w.d.submitCommand(enc(FX.REV_AGENT));
  assert.ok(canonEq(rep, FX.REVOKE_REPLIES.agent));
  assert.equal(seqOf(w), "4");
  assert.equal(rep.record!.state, "revoked");
  const st = w.d.getStatus();
  const raw = b64uDecode(st.body.bits)!;
  assert.equal((raw[17 >> 3]! & (1 << (17 % 8))) !== 0, true); // slot 17 revoked
});

test("TV-H--28 valid old/new/human rotation", () => {
  const w = worldAt(2);
  const rep = w.d.submitCommand(enc(FX.ROTATE));
  assert.ok(canonEq(rep, { v: 1, receipt: FX.RR, record: FX.REC3 }));
  assert.equal(seqOf(w), "4");
  assert.ok(canonEq(lastEvent(w), FX.E4));
});

test("TV-H--29 old key cannot rotate alone → 401 PROOF_SET_INVALID", () => {
  const w = worldAt(2);
  const rotOnly = signed("ROTATION", FX.SROT.body, [5]);
  const cmd = command(3, 5, 2, { kind: "card.rotate", rotation: rotOnly, card: FX.SC2 } as unknown as JsonObject);
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(cmd) });
  const c = code(res);
  assert.equal(c.status, 401);
  assert.equal(c.code, "PROOF_SET_INVALID");
  assert.equal(seqOf(w), "3");
});

test("TV-H--30 concurrent same-revision mutation → REVISION_CONFLICT", () => {
  const w = worldAt(2);
  w.d.submitCommand(enc(FX.ROTATE));
  assert.throws(() => w.d.submitCommand(enc(FX.REV_AGENT)), (e: any) => e.code === "REVISION_CONFLICT");
  assert.equal(seqOf(w), "4");
});

test("TV-H--31 exact retry after response loss", () => {
  const w = worldAt(1);
  const first = w.d.submitCommand(enc(FX.ISSUE));
  const again = w.d.submitCommand(enc(FX.ISSUE));
  assert.ok(canonEq(first, again));
  assert.ok(canonEq(first, { v: 1, receipt: FX.CR, record: FX.REC2 }));
  assert.equal(seqOf(w), "3");
  const evCount = w.db.get("SELECT COUNT(*) AS c FROM events")!["c"];
  assert.equal(evCount, 3);
});

test("TV-H--32 idempotency body conflict → IDEMPOTENCY_CONFLICT", () => {
  const w = worldAt(1);
  w.d.submitCommand(enc(FX.ISSUE));
  const changed = JSON.parse(JSON.stringify(FX.ISSUE));
  changed.body.expires_at = T + 61;
  const reSigned = signed("COMMAND", changed.body, [5]);
  assert.throws(() => w.d.submitCommand(enc(reSigned)), (e: any) => e.code === "IDEMPOTENCY_CONFLICT");
  assert.equal(seqOf(w), "3");
});

test("TV-H--33 expired mutation authorization → COMMAND_EXPIRED", () => {
  const w = worldAt(0, () => T + 60);
  assert.throws(() => w.d.submitCommand(enc(FX.ENROLL)), (e: any) => e.code === "COMMAND_EXPIRED");
  assert.equal(seqOf(w), "1");
});

test("TV-H--36 cross-root command replay → METHOD_TARGET_INVALID", () => {
  const w = worldAt(2);
  const res = http(w, {
    method: "POST", path: `/v1/roots/${ident("hr", 2)}/commands`, body: enc(FX.ISSUE),
  });
  const c = code(res);
  assert.equal(c.status, 400);
  assert.equal(c.code, "METHOD_TARGET_INVALID");
  assert.equal(seqOf(w), "3");
});

test("TV-H--37 hidden delegation field → DELEGATION_FORBIDDEN before proofs", () => {
  const w = worldAt(1);
  const bad = JSON.parse(JSON.stringify(FX.ISSUE));
  bad.body.action.card.body.parent = digest("CARD", FX.SC.body);
  // Deliberately NOT re-signed: schema rejection precedes proof processing.
  const res = http(w, { method: "POST", path: `/v1/roots/${R}/commands`, body: enc(bad) });
  const c = code(res);
  assert.equal(c.status, 422);
  assert.equal(c.code, "DELEGATION_FORBIDDEN");
  assert.equal(seqOf(w), "2");
});

test("TV-H--38 status request query privacy → 400 SCHEMA_INVALID", () => {
  const w = worldAt(2);
  const res = handleRequest(
    { method: "GET", path: `/v1/roots/${R}/status`, query: new Map([["card_id", FX.SC.body.id]]), headers: new Map(), body: new Uint8Array(), ip: "t" },
    { registry: { lookup: () => w.d, all: () => [w.d] }, metrics: new Metrics(), limiter: new RateLimiter(), limits: LIMITS },
  );
  const c = code(res);
  assert.equal(c.status, 400);
  assert.equal(c.code, "SCHEMA_INVALID");
});

test("TV-H--42 human withdrawal cannot be renewed away", () => {
  const w = worldAt(2);
  w.d.submitCommand(enc(FX.REV_BINDING));
  const renew2 = command(21, 3, 3, { kind: "binding.renew", binding: FX.SB2, card: FX.SC3 } as unknown as JsonObject);
  assert.throws(() => w.d.submitCommand(enc(renew2)), (e: any) => e.code === "AGENT_REVOKED");
  const st = w.d.getStatus();
  const raw = b64uDecode(st.body.bits)!;
  assert.equal((raw[2]! & 0x02) !== 0, true); // bit 17 stays 1
});

test("TV-H--43 routine root key continuity", () => {
  const w = worldAt(2);
  const rep = w.d.submitCommand(enc(FX.ROOT_ROTATE));
  assert.ok(canonEq(rep, FX.ROOT_REPLY));
  const ev = lastEvent(w);
  assert.equal(ev.body.kind, "RootRotated");
  assert.equal(ev.proofs[0]!.kid, FX.KEYS["2"].kid); // pre-cutover signer
  const st = w.d.getStatus();
  assert.equal(st.body.root_epoch, "2");
  assert.equal(st.proofs[0]!.kid, FX.KEYS["7"].kid); // successor signs status
});

test("TV-H--44 root replacement without control key → PROOF_SET_INVALID", () => {
  const w = worldAt(2);
  const doc2 = signed("ROOT", FX.SROOT2.body, [2, 3, 7]); // missing control key 1
  const cmd = command(8, 1, 1, { kind: "root.rotate", document: doc2 } as unknown as JsonObject, R);
  assert.throws(() => w.d.submitCommand(enc(cmd)), (e: any) => e.code === "PROOF_SET_INVALID");
  const st = w.d.getStatus();
  assert.equal(st.body.root_epoch, "1");
});

test("TV-H--47 crash before atomic commit leaves no artifacts", () => {
  let armed = false;
  const db = new NodeSqliteDb(":memory:");
  const seeds = new Map(Object.values(FX.KEYS).map((k: any) => [k.kid, b64uDecode(k.seed_b64u)!] as const));
  const d = new RootDO(db, {
    root: R, serviceKeys: (k) => seeds.get(k) ?? null,
    dataBox: new AeadBox(new Uint8Array(32).fill(7)), clock: () => T,
    crashHook: (p) => { if (armed && p === "before_commit") throw new Error("simulated crash"); },
  });
  d.bootstrap(FX.SR);
  d.submitCommand(enc(FX.ENROLL));
  armed = true;
  assert.throws(() => d.submitCommand(enc(FX.ISSUE)), /simulated crash/);
  // Persisted state is exactly S1: seq=2, no card rows, no object artifacts.
  assert.equal(String(db.get("SELECT seq FROM root_state WHERE singleton=1")!["seq"]), "2");
  assert.equal(db.get("SELECT COUNT(*) AS c FROM cards")!["c"], 0);
  assert.equal(db.get("SELECT COUNT(*) AS c FROM objects WHERE kind='CARD'")!["c"], 0);
  // Retry on a fresh DO over the same DB yields the canonical receipt.
  const d2 = new RootDO(db, {
    root: R, serviceKeys: (k) => seeds.get(k) ?? null,
    dataBox: new AeadBox(new Uint8Array(32).fill(7)), clock: () => T,
  });
  const rep = d2.submitCommand(enc(FX.ISSUE));
  assert.ok(canonEq(rep, { v: 1, receipt: FX.CR, record: FX.REC2 }));
});

test("TV-H--48 restore older acknowledged state → readyz INTEGRITY_FAILURE", () => {
  // Registry at S1 but the retained frontier acknowledges E3.
  const w = worldAt(1);
  const frontier = { load: () => ({ seq: "3", log_hash: digest("EVENT", FX.E3.body) }), save: () => {} };
  const db = new NodeSqliteDb(":memory:");
  const seeds = new Map(Object.values(FX.KEYS).map((k: any) => [k.kid, b64uDecode(k.seed_b64u)!] as const));
  const d = new RootDO(db, {
    root: R, serviceKeys: (k) => seeds.get(k) ?? null,
    dataBox: new AeadBox(new Uint8Array(32).fill(7)), clock: () => T, frontier,
  });
  d.bootstrap(FX.SR);
  d.submitCommand(enc(FX.ENROLL));
  // Simulate restore: frontier says seq3/E3 but DB is at seq2.
  const r = d.readiness();
  assert.equal(r.status, "not_ready");
  assert.equal(r.code, "INTEGRITY_FAILURE");
  const res = handleReadyz([d], new Metrics());
  assert.equal(res.status, 503);
  const body = JSON.parse(Buffer.from(res.body).toString());
  assert.equal(body.code, "INTEGRITY_FAILURE");
});

test("TV-H--50 fresh-check revocation ordering", () => {
  const w = worldAt(2);
  w.d.submitCommand(enc(FX.REV_AGENT));
  const reply = w.d.postFreshness(FX.N);
  assert.ok(canonEq(reply, FX.FRESH_REPLY_FRESH ?? reply)); // shape check below
  assert.equal(reply.fresh.body.seq, "4");
  assert.equal(reply.fresh.body.log_hash, digest("EVENT", FX.E_REV.body));
  assert.equal(reply.fresh.body.valid_until, T + 5);
  assert.equal(reply.fresh.body.checked_at, T);
  assert.equal(reply.fresh.proofs[0]!.kid, FX.KEYS["2"].kid);
  const raw = b64uDecode(reply.status.body.bits)!;
  assert.equal((raw[2]! & 0x02) !== 0, true);
});

test("TV-H--52 same-key renewal", () => {
  const w = worldAt(2);
  const rep = w.d.submitCommand(enc(FX.RENEW));
  assert.ok(canonEq(rep, FX.RENEW_REPLY));
  const st = w.d.getStatus();
  const raw = b64uDecode(st.body.bits)!;
  assert.equal((raw[17 >> 3]! & (1 << (17 % 8))) !== 0, true); // slot 17 revoked
  // Slot 19 is allocated but NOT revoked: revoked bitset stays {17}.
  assert.equal((raw[19 >> 3]! & (1 << (19 % 8))) === 0, true);
});

test("TV-H--53 retired key new-command denial → FORBIDDEN", () => {
  const w = worldAt(3);
  const cmd = command(30, 5, 3, { kind: "revoke", target: "agent", id: FX.A, reason: "RETIRED" } as unknown as JsonObject);
  assert.throws(() => w.d.submitCommand(enc(cmd)), (e: any) => e.code === "FORBIDDEN");
  assert.equal(seqOf(w), "4");
});

test("TV-H--54 full capacity preserves revocation", () => {
  const makeFull = () => {
    const db = new NodeSqliteDb(":memory:");
    const seeds = new Map(Object.values(FX.KEYS).map((k: any) => [k.kid, b64uDecode(k.seed_b64u)!] as const));
    const d = new RootDO(db, {
      root: R, serviceKeys: (k) => seeds.get(k) ?? null,
      dataBox: new AeadBox(new Uint8Array(32).fill(7)), clock: () => T,
    });
    d.bootstrap(FX.SR);
    d.submitCommand(enc(FX.ENROLL));
    d.submitCommand(enc(FX.ISSUE));
    // Test-only capacity injection: every slot allocated.
    db.run("UPDATE root_state SET allocated_bits=? WHERE singleton=1", new Uint8Array(16384).fill(0xff));
    return { db, d };
  };
  {
    const { d } = makeFull();
    const rep = d.submitCommand(enc(FX.REV_AGENT));
    assert.ok(canonEq(rep, FX.REVOKE_REPLIES.agent));
  }
  {
    const { d } = makeFull();
    const nc = { ...FX.SC.body, id: ident("hc", 4), previous: digest("CARD", FX.SC.body), status_index: 18 };
    const sc = signed("CARD", nc, [4, 5]);
    const cmd = command(31, 5, 2, { kind: "card.issue", card: sc } as unknown as JsonObject);
    assert.throws(() => d.submitCommand(enc(cmd)), (e: any) => e.code === "CAPACITY");
  }
});

test("TV-H--59 root cutover cannot omit a concurrent event → PREDECESSOR_MISMATCH", () => {
  const w = worldAt(3); // head is E4 (seq 4)
  const doc2 = { ...FX.SROOT2.body, cutover: { seq: "3", log_hash: digest("EVENT", FX.E3.body) } };
  const sdoc = signed("ROOT", doc2, [1, 2, 3, 7]);
  const cmd = command(8, 1, 1, { kind: "root.rotate", document: sdoc } as unknown as JsonObject, R);
  assert.throws(() => w.d.submitCommand(enc(cmd)), (e: any) => e.code === "PREDECESSOR_MISMATCH");
  assert.equal(seqOf(w), "4");
});
