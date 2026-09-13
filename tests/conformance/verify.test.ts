/** Verifier/cache-side vectors: TV-H--08-11,16-17,21-27,34-35,45-46,51,56-58,60. */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  b64uDecode, digest, digestBytes, ed25519Sign, b64uEncode, verify, verifyWithContext,
  verifyHistory,
} from "@latticeag/herald-core";
import type { TrustContext, VerifyInput, Signed, Status, Fresh } from "@latticeag/herald-core";
import { FX, T, R, signed, seed, pub, bits, canonEq } from "./harness.ts";

function ctx(over: Partial<TrustContext> = {}): TrustContext {
  return {
    pins: FX.CLIENT_CONFIG.roots, frontiers: [], known_revocations: [],
    received_age_s: 0, challenge_outstanding: null, challenge_consumed: false,
    ...over,
  };
}

function v(bundle: any, status: any, fresh: any = null, challenge: string | null = null,
           now = T, mode: "fresh" | "bounded_cache" = "bounded_cache", c: TrustContext = ctx()) {
  return verify({ bundle, status, fresh, challenge, now, mode }, c);
}

test("TV-H--08 offline bounded live verification", () => {
  const r = v(FX.BUNDLE, FX.ST);
  assert.ok(canonEq(r, FX.ALLOW));
});

test("TV-H--09 fresh challenge-bound verification", () => {
  const c = ctx({ challenge_outstanding: FX.N });
  const r = verifyWithContext(
    { bundle: FX.BUNDLE, status: FX.ST, fresh: FX.F, challenge: FX.N, now: T, mode: "fresh" }, c);
  assert.ok(canonEq(r, FX.ALLOW_FRESH));
  assert.equal(c.challenge_consumed, true);
});

test("TV-H--10 wrong cryptographic domain", () => {
  // Card proof signs D(BINDING,C) instead of D(CARD,C).
  const badCard = {
    body: FX.SC.body,
    proofs: [
      { kid: FX.KEYS["4"].kid, signature: b64uEncode(ed25519Sign(seed(4), digestBytes("BINDING", FX.SC.body))) },
      { kid: FX.KEYS["5"].kid, signature: b64uEncode(ed25519Sign(seed(5), digestBytes("BINDING", FX.SC.body))) },
    ],
  };
  const bundle = { ...FX.BUNDLE, card: badCard };
  const r = v(bundle, FX.ST);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "SIGNATURE_INVALID");
});

test("TV-H--11 tampered signed capabilities hash", () => {
  const card = { ...FX.SC.body, capabilities_hash: "0".repeat(64) };
  const bundle = { ...FX.BUNDLE, card: { body: card, proofs: FX.SC.proofs } };
  const r = v(bundle, FX.ST);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "SIGNATURE_INVALID");
});

test("TV-H--16 card expiry boundary", () => {
  const st = signed("STATUS", { ...FX.ST.body, issued_at: T + 3600, expires_at: T + 3660 }, [2]);
  const r = v(FX.BUNDLE, st, null, null, T + 3600);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "CARD_EXPIRED");
});

test("TV-H--17 human-binding expiry and error precedence", () => {
  const st = signed("STATUS", { ...FX.ST.body, issued_at: FX.SB.body.expires_at, expires_at: FX.SB.body.expires_at + 60 }, [2]);
  const r = v(FX.BUNDLE, st, null, null, FX.SB.body.expires_at);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "CARD_EXPIRED"); // card check precedes binding
});

test("TV-H--21 revoked card denies offline use", () => {
  const r = v(FX.BUNDLE, FX.ST_REV);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "CARD_REVOKED");
});

test("TV-H--22 stale status is not a soft allow", () => {
  const r = v(FX.BUNDLE, FX.ST, null, null, T + 60);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "STATUS_STALE");
});

test("TV-H--23 wrong freshness challenge", () => {
  const wrong = "hn_" + "C".repeat(32);
  const c = ctx({ challenge_outstanding: wrong });
  const r = v(FX.BUNDLE, FX.ST, FX.F, wrong, T, "fresh", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "CHALLENGE_MISMATCH");
});

test("TV-H--24 five-second exact cutoff", () => {
  const c = ctx({ challenge_outstanding: FX.N });
  const r = v(FX.BUNDLE, FX.ST, FX.F, FX.N, T + 5, "fresh", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "STATUS_STALE");
});

test("TV-H--25 snapshot rollback", () => {
  const c = ctx({ frontiers: [{ root: R, seq: "4", log_hash: digest("EVENT", FX.E4.body), root_epoch: "1" }] });
  const r = v(FX.BUNDLE, FX.ST, null, null, T, "bounded_cache", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "STATUS_ROLLBACK");
});

test("TV-H--26 authentic fork at equal sequence", () => {
  const c = ctx({ frontiers: [{ root: R, seq: "3", log_hash: digest("EVENT", FX.E3.body), root_epoch: "1" }] });
  const forked = signed("STATUS", { ...FX.ST.body, log_hash: "f".repeat(64) }, [2]);
  const r = v(FX.BUNDLE, forked, null, null, T, "bounded_cache", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "FORKED");
});

test("TV-H--27 clearing a learned revoked bit", () => {
  const c = ctx({
    frontiers: [{ root: R, seq: "4", log_hash: digest("EVENT", FX.E4.body), root_epoch: "1" }],
    known_revocations: [{ root: R, bits: bits(17) }],
  });
  const st = signed("STATUS", { ...FX.ST.body, seq: "5", log_hash: "e".repeat(64), bits: bits() }, [2]);
  const r = v(FX.BUNDLE, st, null, null, T, "bounded_cache", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "STATUS_ROLLBACK");
});

test("TV-H--34 frozen root denies active-looking card", () => {
  const r = v(FX.BUNDLE, FX.status_frozen);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "ROOT_FROZEN");
});

test("TV-H--35 untrusted federation root", () => {
  const r = v(FX.BUNDLE, FX.ST, null, null, T, "bounded_cache", ctx({ pins: [] }));
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "ROOT_UNTRUSTED");
});

test("TV-H--45 event chain tampering", () => {
  const e3 = { ...FX.E3.body, prev: "0".repeat(64) };
  const se3 = signed("EVENT", e3, [2]);
  const r = verifyHistory([FX.E1, FX.E2, se3], [FX.SR], FX.CLIENT_CONFIG.roots);
  assert.deepEqual(r, { v: 1, valid: false, live: false, code: "EVIDENCE_MISMATCH" });
});

test("TV-H--46 historical evidence is not live permission", () => {
  const r = verifyHistory([FX.E1, FX.E2, FX.E3], [FX.SR], FX.CLIENT_CONFIG.roots);
  assert.deepEqual(r, {
    v: 1, valid: true, live: false, last_seq: "3", last_hash: digest("EVENT", FX.E3.body),
  });
});

test("TV-H--51 no global retroactive kill claim", () => {
  // Observation issued at T remains within its bound at T+2 even though
  // REV_AGENT committed at T+1: consumer may admit; this is the documented
  // post-check race, not a freshness guarantee.
  const c1 = ctx({ challenge_outstanding: FX.N });
  const r1 = verifyWithContext(
    { bundle: FX.BUNDLE, status: FX.ST, fresh: FX.F, challenge: FX.N, now: T, mode: "fresh" }, c1);
  assert.equal(r1.decision, "allow");
  assert.ok(r1.decision === "allow" && r1.valid_until === T + 5);
  // A NEW check at T+2 sees the revocation.
  const c2 = ctx({ challenge_outstanding: FX.N });
  const r2 = v(FX.BUNDLE, FX.ST_REV, FX.F_REV, FX.N, T + 2, "fresh", c2);
  assert.equal(r2.decision, "deny");
  assert.equal((r2 as any).code, "CARD_REVOKED");
});

test("TV-H--56 fresh challenge cannot authorize twice", () => {
  const c = ctx({ challenge_outstanding: FX.N });
  const first = verifyWithContext(
    { bundle: FX.BUNDLE, status: FX.ST, fresh: FX.F, challenge: FX.N, now: T, mode: "fresh" }, c);
  assert.ok(canonEq(first, FX.ALLOW_FRESH));
  const second = verifyWithContext(
    { bundle: FX.BUNDLE, status: FX.ST, fresh: FX.F, challenge: FX.N, now: T, mode: "fresh" }, c);
  assert.equal(second.decision, "deny");
  assert.equal((second as any).code, "REPLAY");
});

test("TV-H--57 rotated card is independently usable", () => {
  const r = v(FX.BUNDLE_ROTATED, FX.ST_ROTATED);
  assert.ok(canonEq(r, FX.ALLOW_ROTATED));
  const r2 = v(FX.BUNDLE, FX.ST_ROTATED);
  assert.equal(r2.decision, "deny");
  assert.equal((r2 as any).code, "CARD_REVOKED");
});

test("TV-H--58 rotation proof omission cannot masquerade as renewal", () => {
  const bundle = { ...FX.BUNDLE_ROTATED, rotation: null, prior_card: null };
  const r = v(bundle, FX.ST_ROTATED);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "EVIDENCE_MISMATCH");
});

test("TV-H--60 retired service key cannot mint new status", () => {
  const stRootWrongSigner = signed("STATUS", FX.ST_ROOT.body, [2]);
  const pin = { ...FX.CLIENT_CONFIG.roots[0], min_epoch: "2" };
  const c = ctx({
    pins: [pin],
    frontiers: [{ root: R, seq: "4", log_hash: digest("EVENT", FX.E_ROOT.body), root_epoch: "2" }],
  });
  const bundle = { ...FX.BUNDLE, roots: [FX.SR, FX.SROOT2] };
  const r = v(bundle, stRootWrongSigner, null, null, T, "bounded_cache", c);
  assert.equal(r.decision, "deny");
  assert.equal((r as any).code, "SIGNATURE_INVALID");
});
