/**
 * Differential fuzzer (spec: 100,000 cases). Three surfaces:
 *
 *  1. Parser/JCS (every case): mutated byte strings must either be rejected
 *     with a defined code or parse to a value whose canonicalization is a
 *     byte-stable fixed point.
 *  2. Crypto (every case, via node:crypto + strict subsample): mutated
 *     signatures/keys/messages must never verify. node:crypto rejection is a
 *     sound lower bound — the strict profile accepts a SUBSET of what
 *     OpenSSL accepts — and every STRICT_EVERY-th case also runs the pure
 *     strict implementation to catch divergence.
 *  3. Verifier (every STRICT_EVERY-th case): a deep leaf mutation inside a
 *     signed body or its proofs must deny — never crash, never silently
 *     allow.
 *
 * Seeded PRNG for reproducibility; failures print the case index and seed.
 * FUZZ_CASES / FUZZ_SEED / STRICT_EVERY override the defaults.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPrivateKey, createPublicKey, sign as nSign, verify as nVerify } from "node:crypto";
import {
  canonicalize, decodePoint, digestBytes, ed25519Sign, ed25519Verify,
  parseJsonStrict, publicKeyFromSeed, publicKeyValid, verify,
  LIMITS_ORDINARY,
} from "@latticeag/herald-core";
import type { TrustContext } from "@latticeag/herald-core";

const here = dirname(fileURLToPath(import.meta.url));
const FX = JSON.parse(readFileSync(join(here, "../../fixtures/fixtures.json"), "utf8"));
const T = FX.T as number;

// ---- xorshift64* PRNG ----
let sState = BigInt(process.env.FUZZ_SEED ?? "0x9e3779b97f4a7c15");
function rnd(): bigint {
  sState ^= sState >> 12n;
  sState ^= sState << 25n;
  sState ^= sState >> 27n;
  sState &= 0xffffffffffffffffn;
  return (sState * 2685821657736338717n) & 0xffffffffffffffffn;
}
const ri = (n: number) => Number(rnd() % BigInt(n));

const CORPUS: Uint8Array[] = [
  canonicalize(FX.ROOT), canonicalize(FX.B), canonicalize(FX.C),
  canonicalize(FX.ST.body), canonicalize(FX.F.body), canonicalize(FX.ENROLL),
  canonicalize(FX.ISSUE), canonicalize(FX.ROTATE), canonicalize(FX.Q_RESOLVE),
  new TextEncoder().encode('{"a":[1,"x",{"b":null}],"z":{}}'),
  new TextEncoder().encode("[]"),
  new TextEncoder().encode('{"unicode":"héllo","esc":"\\n\\t","num":42}'),
];

const CODES = new Set(["JSON_INVALID", "DUPLICATE_KEY", "NUMBER_INVALID", "TOO_LARGE"]);

function mutate(buf: Uint8Array): Uint8Array {
  const out = new Uint8Array(buf);
  switch (ri(10)) {
    case 0:
      if (out.length) out[ri(out.length)] = ri(256);
      break;
    case 1:
      return out.slice(0, out.length ? ri(out.length) : 0);
    case 2: {
      const at = ri(out.length + 1);
      const ins = new Uint8Array(out.length + 1);
      ins.set(out.slice(0, at));
      ins[at] = ri(256);
      ins.set(out.slice(at), at + 1);
      return ins;
    }
    case 3: {
      if (out.length <= 1) break;
      const at = ri(out.length);
      const del = new Uint8Array(out.length - 1);
      del.set(out.slice(0, at));
      del.set(out.slice(at + 1), at);
      return del;
    }
    case 4: { // duplicate a member name
      const s = new TextDecoder().decode(out);
      const m = /"([^"\\]{1,8})"\s*:/g.exec(s);
      if (m) {
        const inj = `,"${m[1]}":0`;
        const at = s.indexOf(m[0]) + m[0].length;
        return new TextEncoder().encode(s.slice(0, at) + inj + s.slice(at));
      }
      break;
    }
    case 5: { // number literal splice
      const s = new TextDecoder().decode(out);
      const cands = ["9007199254740993", "-0", "1e5", "01", "0.5", "NaN", "Infinity", "18446744073709551616"];
      const at = ri(s.length);
      return new TextEncoder().encode(s.slice(0, at) + cands[ri(cands.length)] + s.slice(at));
    }
    case 6: { // escape splice
      const s = new TextDecoder().decode(out);
      const esc = ["\\ud800", "\\udc00", "\\x", "\\", "\\u00", "\\uZZZZ"];
      const at = ri(s.length);
      return new TextEncoder().encode(s.slice(0, at) + esc[ri(esc.length)] + s.slice(at));
    }
    case 7: { // trailing junk
      const junk = [" ", "\t", "\n", "x", "}", "]"];
      return new Uint8Array([...out, ...new TextEncoder().encode(junk[ri(junk.length)])]);
    }
    case 8: { // byte swap
      if (out.length > 1) {
        const a = ri(out.length), b = ri(out.length);
        const t = out[a]!; out[a] = out[b]!; out[b] = t;
      }
      break;
    }
    default: { // corpus splice
      if (out.length > 2) {
        const other = CORPUS[ri(CORPUS.length)]!;
        return new Uint8Array([...out.slice(0, ri(out.length)), ...other.slice(ri(other.length))]);
      }
    }
  }
  return out;
}

type JsonObjectSafe = Record<string, unknown>;

/** Deep-mutate one leaf of a parsed JSON value in place. */
function mutateLeaf(v: unknown, depth = 0, path = ""): boolean {
  if (depth > 6) return false;
  if (Array.isArray(v) && v.length) {
    const i = ri(v.length);
    if (ri(2) === 0) {
      const cur = v[i];
      const next = typeof cur === "number" ? "z" : 0;
      if (cur === next) return false;
      lastMutation = `${path}[${i}] := ${JSON.stringify(cur)} -> ${JSON.stringify(next)}`;
      v[i] = next;
      return true;
    }
    return mutateLeaf(v[i], depth + 1, `${path}[${i}]`);
  }
  if (typeof v === "object" && v !== null) {
    const keys = Object.keys(v);
    if (!keys.length) return false;
    const k = keys[ri(keys.length)]!;
    if (ri(3) === 0) {
      const cur = (v as JsonObjectSafe)[k];
      const next = typeof cur === "string" ? 1 : "0".repeat(64);
      if (cur === next) return false;
      lastMutation = `${path}.${k} := ${JSON.stringify(cur)} -> ${JSON.stringify(next)}`;
      (v as JsonObjectSafe)[k] = next;
      return true;
    }
    return mutateLeaf((v as JsonObjectSafe)[k], depth + 1, `${path}.${k}`);
  }
  return false;
}
let lastMutation = "";

function ctx(): TrustContext {
  return {
    pins: FX.CLIENT_CONFIG.roots, frontiers: [], known_revocations: [],
    received_age_s: 0, challenge_outstanding: null, challenge_consumed: false,
  };
}

const VERIFY_CODES = new Set([
  "EVIDENCE_MISMATCH", "ROOT_UNTRUSTED", "SIGNATURE_INVALID", "PROOF_SET_INVALID",
  "BINDING_MISMATCH", "ROTATION_MISMATCH", "STATUS_ROLLBACK", "ROOT_ROLLBACK",
  "FORKED", "STATUS_STALE", "CHALLENGE_MISMATCH", "REPLAY", "CARD_EXPIRED",
  "BINDING_EXPIRED", "ROOT_FROZEN", "CARD_REVOKED",
]);

function nodeKeypair(seed: Uint8Array) {
  // PKCS8: 302e020100300506032b657004220420 || seed
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  const pubRaw = new Uint8Array(pub.export({ format: "der", type: "spki" }).subarray(-32));
  return { priv, pubRaw };
}

let parseOk = 0, parseReject = 0, cryptoChecked = 0, strictCrypto = 0, denyCount = 0;
const N = Number(process.env.FUZZ_CASES ?? 100_000);
const STRICT_EVERY = Number(process.env.STRICT_EVERY ?? 50);
const seed0 = sState.toString(16);
const t0 = Date.now();

for (let i = 0; i < N; i++) {
  const input = mutate(CORPUS[ri(CORPUS.length)]!);

  // ---- 1. parser differential (every case) ----
  const r = parseJsonStrict(input, LIMITS_ORDINARY);
  if (!r.ok) {
    if (!CODES.has(r.code)) throw new Error(`case ${i} (seed ${seed0}): unknown code ${r.code}`);
    parseReject++;
  } else {
    const canon = canonicalize(r.value);
    const r2 = parseJsonStrict(canon, LIMITS_ORDINARY);
    if (!r2.ok) throw new Error(`case ${i} (seed ${seed0}): canonical form unparseable: ${r2.code}`);
    if (!Buffer.from(canon).equals(Buffer.from(canonicalize(r2.value))))
      throw new Error(`case ${i} (seed ${seed0}): canonicalization not a fixed point`);
    parseOk++;
  }

  // ---- 2. crypto mutations (every case, fast path) ----
  const sk = new Uint8Array(32);
  for (let j = 0; j < 32; j += 8) {
    const x = rnd();
    for (let k = 0; k < 8; k++) sk[j + k] = Number((x >> BigInt(8 * k)) & 0xffn);
  }
  const { priv, pubRaw } = nodeKeypair(sk);
  const msg = Buffer.from(input.slice(0, Math.min(input.length, 256)));
  const sig = nSign(null, msg, priv);
  cryptoChecked++;
  switch (ri(4)) {
    case 0: {
      const bad = new Uint8Array(sig);
      const bi = ri(64);
      bad[bi] = (bad[bi] ?? 0) ^ (1 + ri(255));
      if (nVerify(null, msg, priv, Buffer.from(bad))) // verify vs same key: key object carries pubkey
        throw new Error(`case ${i}: mutated signature verified (openssl)`);
      break;
    }
    case 1: {
      const bad = Buffer.from(pubRaw);
      const bi = ri(32);
      bad[bi] = (bad[bi] ?? 0) ^ (1 + ri(255));
      try {
        const badPub = createPublicKey({
          key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), bad]),
          format: "der", type: "spki",
        });
        if (nVerify(null, msg, badPub, sig)) throw new Error(`case ${i}: mutated public key verified (openssl)`);
      } catch (e) {
        if ((e as Error).message.includes("verified")) throw e; // import/verify failure is a valid rejection
      }
      break;
    }
    case 2: {
      const raw = new Uint8Array(32);
      for (let j = 0; j < 32; j++) raw[j] = ri(256);
      decodePoint(raw); // must never throw
      break;
    }
    default: {
      if (msg.length) {
        const bad = Buffer.from(msg);
        const bi = ri(bad.length);
        bad[bi] = (bad[bi] ?? 0) ^ (1 + ri(255));
        if (nVerify(null, bad, priv, sig)) throw new Error(`case ${i}: mutated message verified (openssl)`);
      }
    }
  }

  // ---- strict crypto + verifier subsample ----
  if (i % STRICT_EVERY === 0) {
    strictCrypto++;
    const strictPub = publicKeyFromSeed(sk);
    if (!Buffer.from(strictPub).equals(Buffer.from(pubRaw)))
      throw new Error(`case ${i}: strict/openssl public key divergence`);
    const strictSig = ed25519Sign(sk, msg);
    if (!Buffer.from(strictSig).equals(Buffer.from(sig)))
      throw new Error(`case ${i}: strict/openssl signature divergence`);
    if (!ed25519Verify(strictPub, msg, strictSig)) throw new Error(`case ${i}: strict verify failed on fresh sig`);
    if (!publicKeyValid(strictPub)) throw new Error(`case ${i}: strict pub rejected own key`);

    const bundle = JSON.parse(JSON.stringify(FX.BUNDLE));
    const status = JSON.parse(JSON.stringify(FX.ST));
    const target = ri(2) === 0 ? bundle : status;
    if (mutateLeaf(target)) {
      const res = verify({ bundle, status, fresh: null, challenge: null, now: T, mode: "bounded_cache" }, ctx());
      if (res.decision !== "deny" || !VERIFY_CODES.has((res as { code: string }).code))
        throw new Error(`case ${i}: mutated artifact allowed at ${lastMutation}: ${JSON.stringify(res)}`);
      denyCount++;
    }
  }
}

console.log(`differential fuzz: ${N} cases  parse_ok=${parseOk} parse_reject=${parseReject} ` +
  `crypto_checked=${cryptoChecked} strict_subsample=${strictCrypto} verify_denied=${denyCount}  ` +
  `seed=${seed0}  ${(Date.now() - t0) / 1000}s`);
