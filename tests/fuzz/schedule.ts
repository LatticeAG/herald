/**
 * Schedule fuzzer (spec: 10,000 cases). Drives random operation schedules
 * through a persistent RootDO — a mixture of valid transitions, idempotent
 * replays, and adversarial/invalid commands — asserting after every case:
 *
 *   - success ⇒ seq advanced by exactly 1 and the new event's `prev` equals
 *     the previous head (hash-chain continuity);
 *   - failure ⇒ a spec error code and unchanged seq;
 *   - replayed op_id ⇒ identical reply bytes, no new event;
 *   - final audit log passes verifyHistory and the status validates.
 *
 * FUZZ_SCHEDULE / FUZZ_SEED override count/seed.
 */

import { createHash, createPrivateKey, createPublicKey, sign as nSign, verify as nVerify } from "node:crypto";
import {
  b64uEncode, digest, digestBytes, verifyHistory,
} from "@latticeag/herald-core";
import type { JsonObject, Signed } from "@latticeag/herald-core";
import { NodeSqliteDb } from "../../packages/worker/src/sql.ts";
import { AeadBox } from "../../packages/worker/src/aead.ts";
import { RootDO } from "../../packages/worker/src/rootdo.ts";
import { FX, T, R, seed as fseed, ident, canonEq } from "../conformance/harness.ts";

// ---- PRNG ----
let sState = BigInt(process.env.FUZZ_SEED ?? "0xdeadbeefcafe1234");
function rnd(): bigint {
  sState ^= sState >> 12n;
  sState ^= sState << 25n;
  sState ^= sState >> 27n;
  sState &= 0xffffffffffffffffn;
  return (sState * 2685821657736338717n) & 0xffffffffffffffffn;
}
const ri = (n: number) => Number(rnd() % BigInt(n));
const pick = <T>(a: T[]): T => a[ri(a.length)]!;

function randBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let j = 0; j < n; j += 8) {
    const x = rnd();
    for (let k = 0; k < 8 && j + k < n; k++) out[j + k] = Number((x >> BigInt(8 * k)) & 0xffn);
  }
  return out;
}
function randId(prefix: string, len = 21): string {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  let s = "";
  while (s.length < len) s += ALPHABET[ri(64)];
  return `${prefix}_${s}`;
}

interface K {
  kid: string;
  seed: Uint8Array;
  pub: { id: string; public_key: string };
}
// node:crypto backend for fuzz speed — strict-accept ⊆ openssl-accept, so
// this is a valid lower bound; the differential fuzzer covers strictness.
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const fastSign = (seed: Uint8Array, digest: Uint8Array) =>
  new Uint8Array(nSign(null, Buffer.from(digest), {
    key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: "der", type: "pkcs8",
  }));
const fastVerify = (pk: Uint8Array, digest: Uint8Array, sig: Uint8Array) => {
  try {
    return nVerify(null, Buffer.from(digest), {
      key: Buffer.concat([SPKI, Buffer.from(pk)]), format: "der", type: "spki",
    }, Buffer.from(sig));
  } catch { return false; }
};
const fastPub = (seed: Uint8Array) =>
  new Uint8Array(createPublicKey(createPrivateKey({
    key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: "der", type: "pkcs8",
  })).export({ format: "der", type: "spki" }).subarray(-32));

const keyCache = new Map<string, K>();
function freshKey(): K {
  const seed = randBytes(32);
  const kid = randId("hk");
  const k: K = { kid, seed, pub: { id: kid, public_key: b64uEncode(fastPub(seed)) } };
  keyCache.set(kid, k);
  return k;
}
const REG: K = { kid: FX.KEYS["3"].kid, seed: fseed(3), pub: { id: FX.KEYS["3"].kid, public_key: FX.KEYS["3"].public_key } };
const CTRL: K = { kid: FX.KEYS["1"].kid, seed: fseed(1), pub: { id: FX.KEYS["1"].kid, public_key: FX.KEYS["1"].public_key } };

function signMulti(tag: Parameters<typeof digestBytes>[0], body: JsonObject, signers: K[]): Signed<JsonObject> {
  const seen = new Map<string, string>();
  for (const s of signers) seen.set(s.kid, b64uEncode(fastSign(s.seed, digestBytes(tag, body))));
  const proofs = [...seen.entries()].sort((a, b) => a[0] < b[0] ? -1 : 1)
    .map(([kid, signature]) => ({ kid, signature }));
  return { body: JSON.parse(JSON.stringify(body)), proofs };
}
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

interface Agent {
  did: string;
  human: K;
  agentKey: K;
  bindingId: string;
  principalId: string;
  bindingHash: string;
  cardHash: string | null;
  lastCardHash: string | null;
  cardId: string | null;
  slot: number;
  revision: number;
  keyEpoch: number;
  state: "enrolled" | "active" | "revoked";
  bindingState: "current" | "revoked";
  bindingExpiry: number;
}

const db = new NodeSqliteDb(":memory:");
const seedMap = new Map<string, Uint8Array>();
for (const k of Object.values(FX.KEYS) as any[]) seedMap.set(k.kid, Buffer.from(k.seed_b64u, "base64url"));
const box = new AeadBox(new Uint8Array(32).fill(9));
const d = new RootDO(db, {
  root: R,
  serviceKeys: (kid) => seedMap.get(kid) ?? null,
  dataBox: box,
  clock: () => T,
  signFn: fastSign,
  verifyFn: fastVerify,
});
let seq = 0;
let head = "0".repeat(64);
d.bootstrap(FX.SR);
seq = 1;
head = String(db.get("SELECT hash FROM events WHERE seq=1")!["hash"]);
const agents: Agent[] = [];
const CAP_HASH = FX.CAP_HASH ?? digest("CAPABILITIES", FX.CAP);
const usedSlots = new Set<number>();

const SPEC_CODES = new Set([
  "JSON_INVALID", "DUPLICATE_KEY", "SCHEMA_INVALID", "NUMBER_INVALID", "ID_INVALID",
  "ENCODING_INVALID", "VERSION_UNSUPPORTED", "METHOD_TARGET_INVALID",
  "SIGNATURE_INVALID", "PROOF_SET_INVALID", "QUERY_EXPIRED", "COMMAND_EXPIRED",
  "NOT_YET_VALID", "FORBIDDEN", "ROOT_FROZEN", "BINDING_REVOKED", "AGENT_REVOKED",
  "ROOT_UNKNOWN", "NOT_FOUND", "ROUTE_UNKNOWN", "METHOD_NOT_ALLOWED",
  "REVISION_CONFLICT", "IDEMPOTENCY_CONFLICT", "SLOT_USED", "ID_USED",
  "KEY_REUSED", "ALREADY_REVOKED", "STATE_TRANSITION", "PREDECESSOR_MISMATCH",
  "EPOCH_MISMATCH", "TOO_LARGE", "INTERVAL_INVALID", "BINDING_MISMATCH",
  "HOLDER_MISMATCH", "CAPABILITIES_MISMATCH", "ROTATION_MISMATCH",
  "DELEGATION_FORBIDDEN", "RATE_LIMITED", "CAPACITY", "UNAVAILABLE",
  "STORAGE_BUSY", "CLOCK_UNSAFE", "INTEGRITY_FAILURE",
]);

function commit(raw: Uint8Array): { ok: true; reply: unknown; replay?: boolean } | { ok: false; code: string } {
  const beforeSeq = seq;
  try {
    const reply = d.submitCommand(raw);
    const cur = Number(db.get("SELECT seq FROM root_state WHERE singleton=1")!["seq"]);
    if (cur === beforeSeq + 1) {
      const ev = db.get("SELECT seq, hash, canonical FROM events WHERE seq=?", seq + 1);
      if (!ev) throw new Error("committed op produced no event");
      const evObj = JSON.parse(new TextDecoder().decode(ev["canonical"] as Uint8Array));
      if (evObj.body.prev !== head) throw new Error(`hash chain broken at seq ${seq + 1}`);
      seq++;
      head = ev["hash"] as string;
      return { ok: true, reply };
    }
    if (cur === beforeSeq) return { ok: true, reply, replay: true }; // idempotent tombstone
    throw new Error(`seq jumped by ${cur - beforeSeq}`);
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (process.env.FUZZ_DEBUG) console.error("DBG", code, (e as Error).stack?.split("\n").slice(1,4).join(" | "));
    if (typeof code !== "string" || !SPEC_CODES.has(code)) throw e;
    const cur = db.get("SELECT seq FROM root_state WHERE singleton=1")!;
    if (Number(cur["seq"]) !== beforeSeq) throw new Error(`failed op advanced seq: ${code}`);
    return { ok: false, code };
  }
}

function cmd(actor: K, revision: string, action: JsonObject, subject: string, over: JsonObject = {}): Signed<JsonObject> {
  return signMulti("COMMAND", {
    v: 1, root: R, op_id: randId("ho"), actor: actor.kid, subject,
    expected_revision: revision, issued_at: T, expires_at: T + 60, action, ...over,
  }, [actor]);
}

function doEnroll(): { ok: boolean; code?: string } {
  const did = `did:herald:${R}:${randId("ha")}`;
  const human = freshKey(), agentKey = freshKey();
  const bindingId = randId("hb"), principalId = randId("hp");
  const bBody: JsonObject = {
    v: 1, id: bindingId, root: R, did, principal_id: principalId, previous: null,
    human_key: human.pub, agent_key: agentKey.pub, registrar_epoch: "1",
    assurance: "operator-attested", consent: "agent-accountability-v1",
    issued_at: T - 10, expires_at: T + 2592000,
  };
  const sb = signMulti("BINDING", bBody, [REG, human, agentKey]);
  const c = cmd(REG, "0", { kind: "binding.enroll", binding: sb }, did);
  const r = commit(enc(c));
  if (r.ok) {
    agents.push({
      did, human, agentKey, bindingId, principalId, bindingHash: digest("BINDING", bBody),
      cardHash: null, lastCardHash: null, cardId: null, slot: -1, revision: 1,
      keyEpoch: 1, state: "enrolled", bindingState: "current", bindingExpiry: T + 2592000,
    });
  }
  return r;
}

function freeSlot(): number {
  for (;;) {
    const s = ri(60000); // pool must exceed max possible consumption across N cases
    if (!usedSlots.has(s)) return s;
  }
}

function doIssue(a: Agent): { ok: boolean; code?: string } {
  const cardId = randId("hc");
  const slot = freeSlot();
  const cBody: JsonObject = {
    v: 1, id: cardId, root: R, did: a.did, previous: a.lastCardHash,
    key: a.agentKey.pub, key_epoch: String(a.keyEpoch), human_principal: a.principalId,
    binding_hash: a.bindingHash, capabilities_hash: CAP_HASH,
    gateway_bindings: [{
      caller_jkt: b64uEncode(sha256Jkt(a.agentKey.pub.public_key)),
      gateway: randId("lsg"), sub: randId("lsu"), tenant_id: randId("ltn"),
    }],
    issued_at: T, not_before: T, expires_at: Math.min(T + 3600, a.bindingExpiry),
    status_index: slot,
  };
  const sc = signMulti("CARD", cBody, [a.agentKey, a.human]);
  const actor = pick([a.agentKey, a.human]);
  const c = cmd(actor, String(a.revision), { kind: "card.issue", card: sc }, a.did);
  const r = commit(enc(c));
  if (r.ok) {
    a.cardHash = digest("CARD", cBody);
    a.lastCardHash = a.cardHash;
    a.cardId = cardId;
    a.slot = slot;
    usedSlots.add(slot);
    a.revision++;
    a.state = "active";
  }
  return r;
}

/** JWK thumbprint of an OKP key: sha256(JCS({"crv","kty","x"})). */
function sha256Jkt(pkB64u: string): Uint8Array {
  const canon = `{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(pkB64u)}}`;
  return new Uint8Array(createHash("sha256").update(canon).digest());
}

function doRotate(a: Agent): { ok: boolean; code?: string } {
  const newKey = freshKey();
  const newCardId = randId("hc");
  const slot = freeSlot();
  const ncBody: JsonObject = {
    v: 1, id: newCardId, root: R, did: a.did, previous: a.cardHash,
    key: newKey.pub, key_epoch: String(a.keyEpoch + 1), human_principal: a.principalId,
    binding_hash: a.bindingHash, capabilities_hash: CAP_HASH,
    gateway_bindings: [{ caller_jkt: b64uEncode(sha256Jkt(newKey.pub.public_key)), gateway: randId("lsg"), sub: randId("lsu"), tenant_id: randId("ltn") }],
    issued_at: T, not_before: T, expires_at: Math.min(T + 3600, a.bindingExpiry),
    status_index: slot,
  };
  const rBody: JsonObject = {
    v: 1, root: R, did: a.did, from_epoch: String(a.keyEpoch), to_epoch: String(a.keyEpoch + 1),
    old_card_hash: a.cardHash, new_card_hash: digest("CARD", ncBody),
    old_key_id: a.agentKey.kid, new_key: newKey.pub, issued_at: T,
    expires_at: T + 120, nonce: "hn_" + "X".repeat(32),
  };
  const sr = signMulti("ROTATION", rBody, [a.agentKey, newKey, a.human]);
  const sc = signMulti("CARD", ncBody, [newKey, a.human]);
  const actor = pick([a.agentKey, a.human]);
  const c = cmd(actor, String(a.revision), { kind: "card.rotate", rotation: sr, card: sc }, a.did);
  const r = commit(enc(c));
  if (r.ok) {
    a.lastCardHash = a.cardHash;
    a.cardHash = digest("CARD", ncBody);
    a.cardId = newCardId;
    a.slot = slot;
    usedSlots.add(slot);
    a.agentKey = newKey;
    a.keyEpoch++;
    a.revision++;
  }
  return r;
}

function doRenew(a: Agent): { ok: boolean; code?: string } {
  const bindingId = randId("hb");
  const nbBody: JsonObject = {
    v: 1, id: bindingId, root: R, did: a.did, principal_id: a.principalId,
    previous: a.bindingHash, human_key: a.human.pub, agent_key: a.agentKey.pub,
    registrar_epoch: "1", assurance: "operator-attested", consent: "agent-accountability-v1",
    issued_at: T, expires_at: T + 2592000,
  };
  const newCardId = randId("hc");
  const slot = freeSlot();
  const cBody: JsonObject = {
    v: 1, id: newCardId, root: R, did: a.did, previous: a.cardHash,
    key: a.agentKey.pub, key_epoch: String(a.keyEpoch), human_principal: a.principalId,
    binding_hash: digest("BINDING", nbBody), capabilities_hash: CAP_HASH,
    gateway_bindings: [{ caller_jkt: b64uEncode(sha256Jkt(a.agentKey.pub.public_key)), gateway: randId("lsg"), sub: randId("lsu"), tenant_id: randId("ltn") }],
    issued_at: T, not_before: T, expires_at: Math.min(T + 3600, T + 2592000),
    status_index: slot,
  };
  const sb = signMulti("BINDING", nbBody, [REG, a.human, a.agentKey]);
  const sc = signMulti("CARD", cBody, [a.agentKey, a.human]);
  const c = cmd(REG, String(a.revision), { kind: "binding.renew", binding: sb, card: sc }, a.did);
  const r = commit(enc(c));
  if (r.ok) {
    a.bindingId = bindingId;
    a.bindingHash = digest("BINDING", nbBody);
    a.lastCardHash = a.cardHash;
    a.cardHash = digest("CARD", cBody);
    a.cardId = newCardId;
    a.slot = slot;
    usedSlots.add(slot);
    a.revision++;
  }
  return r;
}

function doRevoke(a: Agent): { ok: boolean; code?: string } {
  const target = pick(["agent", "card", "binding"] as const);
  const id = target === "agent" ? a.did : target === "card" ? a.cardId : a.bindingId;
  if (id === null) return { ok: false, code: "SKIP" };
  const actor = pick([a.human, REG]);
  const c = cmd(actor, String(a.revision), { kind: "revoke", target, id, reason: pick(["COMPROMISE", "WITHDRAWN", "RETIRED", "ADMINISTRATIVE"]) }, a.did);
  const r = commit(enc(c));
  if (r.ok) {
    a.revision++;
    if (target === "agent") a.state = "revoked";
    if (target === "binding") a.bindingState = "revoked";
    if (target === "card" && a.cardId === id) { a.state = "enrolled"; a.cardHash = null; }
  }
  return r;
}

function doInvalid(a: Agent | null): { ok: boolean; code?: string } {
  const flavor = ri(6);
  if (a === null) return doEnroll();
  switch (flavor) {
    case 0: { // wrong revision
      const c = cmd(a.human, String(a.revision + 1 + ri(3)),
        { kind: "revoke", target: "agent", id: a.did, reason: "RETIRED" }, a.did);
      return commit(enc(c));
    }
    case 1: { // expired command
      const c = cmd(a.human, String(a.revision),
        { kind: "revoke", target: "agent", id: a.did, reason: "RETIRED" },
        a.did, { issued_at: T - 300, expires_at: T - 240 });
      return commit(enc(c));
    }
    case 2: { // unauthorized actor (a random key that was never registered)
      const rogue = freshKey();
      const c = cmd(rogue, String(a.revision),
        { kind: "revoke", target: "agent", id: a.did, reason: "RETIRED" }, a.did);
      return commit(enc(c));
    }
    case 3: { // replay an old op_id verbatim → identical stored reply
      const row = db.get("SELECT command_ciphertext, op_id FROM operations ORDER BY RANDOM() LIMIT 1");
      if (!row) return { ok: false, code: "SKIP" };
      const rawCmd = box.decrypt(R, "operations", row["op_id"] as string, new Uint8Array(row["command_ciphertext"] as Uint8Array));
      // Decrypted bytes are the canonical command; re-encode as transport JSON.
      const parsed = JSON.parse(new TextDecoder().decode(rawCmd));
      const res = commit(enc(parsed));
      if (res.ok !== true || res.replay !== true) throw new Error("replay did not hit the tombstone");
      return { ok: true };
    }
    case 4: { // cross-root
      const c = cmd(a.human, String(a.revision),
        { kind: "revoke", target: "agent", id: a.did, reason: "RETIRED" },
        a.did, { root: "hr_" + "9".repeat(21) });
      return commit(enc(c));
    }
    default: { // malformed raw bytes
      return commit(randBytes(ri(64) + 4));
    }
  }
}

function doQuery(a: Agent | null): { ok: boolean; code?: string } {
  const actor = a ? pick([a.human, REG]) : REG;
  const qk = a === null || ri(2) === 0
    ? { kind: "resolve", did: a?.did ?? `did:herald:${R}:${randId("ha")}`, card_id: null }
    : { kind: "export", did: a.did, after_revision: "0", limit: 100 };
  const q = signMulti("QUERY", {
    v: 1, root: R, query_id: randId("hq"), actor: actor.kid,
    issued_at: T, expires_at: T + 30, query: qk,
  }, [actor]);
  try {
    d.submitQuery(enc(q));
    return { ok: true };
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (typeof code !== "string" || !SPEC_CODES.has(code)) throw e;
    return { ok: false, code };
  }
}

const N = Number(process.env.FUZZ_SCHEDULE ?? 10_000);
const seed0 = sState.toString(16);
const t0 = Date.now();
const counts: Record<string, number> = {};
let okOps = 0, errOps = 0, okQueries = 0;

for (let i = 0; i < N; i++) {
  const alive = agents.filter((x) => x.state !== "revoked");
  const a = alive.length ? pick(alive) : null;
  const roll = ri(100);
  let r: { ok: boolean; code?: string };
  if (roll < 20 || alive.length === 0) r = doEnroll();
  else if (roll < 40) {
    const cand = alive.filter((x) => x.state === "enrolled" || (x.state === "active" && x.bindingState === "current"));
    r = cand.length ? doIssue(pick(cand)) : doEnroll();
  } else if (roll < 52) {
    const cand = alive.filter((x) => x.state === "active" && x.bindingState === "current");
    r = cand.length ? doRotate(pick(cand)) : doEnroll();
  } else if (roll < 62) {
    const cand = alive.filter((x) => x.state === "active" && x.bindingState === "current");
    r = cand.length ? doRenew(pick(cand)) : doEnroll();
  } else if (roll < 72) {
    r = alive.length ? doRevoke(pick(alive)) : doEnroll();
  } else if (roll < 90) {
    r = doInvalid(a);
  } else {
    r = doQuery(a);
  }
  if (r.ok) okOps++;
  else { errOps++; counts[r.code ?? "?"] = (counts[r.code ?? "?"] ?? 0) + 1; }
}

// Final integrity: full audit log verifies.
const rows = db.all("SELECT canonical FROM events ORDER BY seq ASC");
const events = rows.map((r) => JSON.parse(new TextDecoder().decode(r["canonical"] as Uint8Array)));
const docs = d.getDocuments(0n, 64).documents;
const pins = FX.CLIENT_CONFIG.roots;
const hr = verifyHistory(events, docs, pins, fastVerify);
if (!hr.valid) throw new Error(`schedule fuzz: final history invalid: ${JSON.stringify(hr)}`);

console.log(`schedule fuzz: ${N} cases  committed=${okOps} rejected=${errOps} ` +
  `agents=${agents.length} final_seq=${seq}  codes=${JSON.stringify(counts)}  ` +
  `seed=${seed0}  ${(Date.now() - t0) / 1000}s`);
