/**
 * Offline verifier (spec §7.1) — pure function plus the context wrapper that
 * applies durable frontier/challenge state transitions.
 *
 * Verification order: syntax/version, trusted root, root continuity and
 * signatures, binding/card/receipt signatures, object cross-links, status
 * authenticity, frontier, freshness, time intervals, root state, then bit.
 */

import { b64uDecode } from "./base64url.ts";
import { digest, digestBytes, sha256Hex } from "./digest.ts";
import { deny } from "./errors.ts";
import { ed25519Verify as edVerify } from "./ed25519.ts";
import { verifyProofSet } from "./proofs.ts";
import {
  validate, MAX_ROOT_EPOCHS,
} from "./schema.ts";
import type {
  AgentCard, Fresh, Frontier, HumanBinding, IdentityBundle, Receipt,
  RootDocument, RootPin, Signed, Status, TrustContext, VerifyInput, VerifyResult,
} from "./types.ts";
import type { JsonObject } from "./json.ts";

const ZERO_HASH = "0".repeat(64);

function denyR(code: string): VerifyResult {
  return deny(code) as VerifyResult;
}

/**
 * Service key authorized for EVENTS/RECEIPTS at seq. Doc_e's event range is
 * [cutover_e + 2, cutover_{e+1} + 1]: the RootRotated event at cutover+1 is
 * still signed by the pre-cutover (prior epoch) service key. Genesis covers
 * seqs from 1.
 */
function eventSignerAtSeq(docs: Signed<RootDocument>[], seq: bigint): { id: string; public_key: string; epoch: string } | null {
  let lower = 1n; // first seq covered by docs[i]
  for (let i = 0; i < docs.length; i++) {
    const d = docs[i]!.body;
    const next = docs[i + 1]?.body;
    const upper = next === undefined || next.cutover === null ? null : BigInt(next.cutover.seq) + 1n;
    if (seq >= lower && (upper === null || seq <= upper)) {
      return { id: d.service_key.id, public_key: d.service_key.public_key, epoch: d.epoch };
    }
    if (upper === null) return null;
    lower = upper + 1n;
  }
  return null;
}

/**
 * Service key authorized for STATUS/FRESH at seq. New live status at the
 * cutover uses the successor: doc_e covers seqs [cutover_e + 1, cutover_{e+1}]
 * (genesis: [1, cutover_2]).
 */
function statusSignerAtSeq(docs: Signed<RootDocument>[], seq: bigint): { id: string; public_key: string; epoch: string } | null {
  for (let i = 0; i < docs.length; i++) {
    const d = docs[i]!.body;
    const lower = i === 0 ? 1n : BigInt(d.cutover!.seq) + 1n;
    const next = docs[i + 1]?.body;
    const upper = next === undefined || next.cutover === null ? null : BigInt(next.cutover.seq);
    if (seq >= lower && (upper === null || seq <= upper)) {
      return { id: d.service_key.id, public_key: d.service_key.public_key, epoch: d.epoch };
    }
  }
  return null;
}

function docForEpoch(docs: Signed<RootDocument>[], epoch: string): Signed<RootDocument> | null {
  return docs.find((d) => d.body.epoch === epoch) ?? null;
}

function pubBytes(pk: { id: string; public_key: string }): Uint8Array | null {
  return b64uDecode(pk.public_key);
}

/** Verify the full roots array: pinning, continuity, epoch links, proof sets. */
function verifyRootChain(
  docs: Signed<RootDocument>[],
  pin: RootPin,
): string | null {
  if (docs.length < 1 || docs.length > MAX_ROOT_EPOCHS) return "EVIDENCE_MISMATCH";
  const genesis = docs[0]!.body;
  if (genesis.epoch !== "1" || genesis.previous !== null || genesis.cutover !== null) return "EVIDENCE_MISMATCH";
  if (digest("ROOT", genesis) !== pin.genesis_hash) return "ROOT_UNTRUSTED";
  const ctrl = pubBytes(genesis.control_key);
  if (ctrl === null || sha256Hex(ctrl) !== pin.control_fingerprint) return "ROOT_UNTRUSTED";
  let r = verifyProofSet("ROOT", docs[0]!, [genesis.control_key.id, genesis.service_key.id, genesis.registrar_key.id], (kid) =>
    [genesis.control_key, genesis.service_key, genesis.registrar_key].find((k) => k.id === kid)
      ? pubBytes([genesis.control_key, genesis.service_key, genesis.registrar_key].find((k) => k.id === kid)!)
      : null,
  );
  if (r !== null) return r;
  for (let i = 1; i < docs.length; i++) {
    const prev = docs[i - 1]!.body;
    const doc = docs[i]!.body;
    if (doc.root !== prev.root) return "EVIDENCE_MISMATCH";
    if (BigInt(doc.epoch) !== BigInt(prev.epoch) + 1n) return "EVIDENCE_MISMATCH";
    if (doc.previous !== digest("ROOT", prev)) return "EVIDENCE_MISMATCH";
    if (doc.control_key.id !== prev.control_key.id || doc.control_key.public_key !== prev.control_key.public_key)
      return "EVIDENCE_MISMATCH";
    if (doc.status_slots !== prev.status_slots) return "EVIDENCE_MISMATCH";
    if (doc.cutover === null) return "EVIDENCE_MISMATCH"; // only the latest may omit cutover... actually a successor must pin cutover
    // Successor proof set: control + old service + new service + new registrar (deduped).
    const expected = [doc.control_key.id, prev.service_key.id, doc.service_key.id, doc.registrar_key.id];
    const keys = new Map<string, { id: string; public_key: string }>();
    for (const k of [doc.control_key, prev.control_key, doc.service_key, prev.service_key, doc.registrar_key, prev.registrar_key])
      keys.set(k.id, k);
    r = verifyProofSet("ROOT", docs[i]!, expected, (kid) => {
      const k = keys.get(kid);
      return k ? pubBytes(k) : null;
    });
    if (r !== null) return r;
  }
  return null;
}

/** Single-signer object check: exactly one proof signing under `key`. */
function verifySingle(tag: Parameters<typeof digestBytes>[0], env: { body: JsonObject; proofs: { kid: string; signature: string }[] }, key: { id: string; public_key: string }): string | null {
  if (env.proofs.length !== 1) return "SIGNATURE_INVALID";
  const p = env.proofs[0]!;
  if (p.kid !== key.id) return "SIGNATURE_INVALID";
  const pk = pubBytes(key);
  const sig = b64uDecode(p.signature);
  if (pk === null || sig === null) return "SIGNATURE_INVALID";
  if (!edVerify(pk, digestBytes(tag, env.body), sig)) return "SIGNATURE_INVALID";
  return null;
}

export function verify(input: VerifyInput, ctx: TrustContext): VerifyResult {
  const b = input.bundle;
  // ---- 1. syntax/version (closed-schema validation of every artifact)
  for (const [t, v] of [
    ["IdentityBundle", b],
    ["Status", input.status],
  ] as const) {
    if (validate(t, v as unknown as JsonObject) !== null) return denyR("EVIDENCE_MISMATCH");
  }
  if (input.fresh !== null && validate("Fresh", input.fresh as unknown as JsonObject) !== null)
    return denyR("EVIDENCE_MISMATCH");
  for (const d of b.roots) if (validate("RootDocument", d.body) !== null) return denyR("EVIDENCE_MISMATCH");
  if (validate("HumanBinding", b.binding.body) !== null) return denyR("EVIDENCE_MISMATCH");
  if (validate("AgentCard", b.card.body) !== null) return denyR("EVIDENCE_MISMATCH");
  if (validate("Receipt", b.receipt as unknown as JsonObject) !== null) return denyR("EVIDENCE_MISMATCH");
  if (b.prior_card !== null && validate("AgentCard", b.prior_card.body) !== null) return denyR("EVIDENCE_MISMATCH");
  if (b.rotation !== null && validate("Rotation", b.rotation.body) !== null) return denyR("EVIDENCE_MISMATCH");

  // ---- 2. trusted root
  const root = b.roots[0]?.body.root;
  if (!root) return denyR("ROOT_UNTRUSTED");
  if (ctx.cache_state === "DISABLED" || ctx.cache_state === "FORKED")
    return denyR(ctx.cache_state === "FORKED" ? "FORKED" : "ROOT_UNTRUSTED");
  const pin = ctx.pins.find((p) => p.root === root);
  if (!pin || !pin.enabled) return denyR("ROOT_UNTRUSTED");

  // ---- 3. root continuity / signatures
  const chainErr = verifyRootChain(b.roots, pin);
  if (chainErr !== null) return denyR(chainErr);

  const binding: HumanBinding = b.binding.body;
  const card: AgentCard = b.card.body;
  const receipt: Receipt = b.receipt.body;

  // Every artifact is anchored to the same root.
  for (const r of [binding.root, card.root, receipt.root, input.status.body.root]) {
    if (r !== root) return denyR("EVIDENCE_MISMATCH");
  }
  if (input.fresh !== null && input.fresh.body.root !== root) return denyR("EVIDENCE_MISMATCH");

  // ---- 4. binding/card/receipt signatures
  // Binding: registrar (at binding.registrar_epoch) + human + bound agent key.
  const regDoc = docForEpoch(b.roots, binding.registrar_epoch);
  if (regDoc === null) return denyR("EVIDENCE_MISMATCH");
  {
    const keys = new Map<string, { id: string; public_key: string }>();
    for (const k of [regDoc.body.registrar_key, binding.human_key, binding.agent_key]) keys.set(k.id, k);
    const r = verifyProofSet(
      "BINDING", b.binding,
      [regDoc.body.registrar_key.id, binding.human_key.id, binding.agent_key.id],
      (kid) => (keys.has(kid) ? pubBytes(keys.get(kid)!) : null),
    );
    if (r !== null) return denyR(r);
  }
  // Card: card key + binding human key.
  {
    const keys = new Map<string, { id: string; public_key: string }>();
    for (const k of [card.key, binding.human_key]) keys.set(k.id, k);
    const r = verifyProofSet("CARD", b.card, [card.key.id, binding.human_key.id], (kid) =>
      keys.has(kid) ? pubBytes(keys.get(kid)!) : null,
    );
    if (r !== null) return denyR(r);
  }
  // Receipt: service key authorized at receipt.seq (event mapping — the
  // RootRotated receipt is still signed by the pre-cutover service key).
  {
    const svc = eventSignerAtSeq(b.roots, BigInt(receipt.seq));
    if (svc === null) return denyR("EVIDENCE_MISMATCH");
    const r = verifySingle("RECEIPT", b.receipt, svc);
    if (r !== null) return denyR(r);
  }
  if (b.prior_card !== null) {
    const keys = new Map<string, { id: string; public_key: string }>();
    for (const k of [b.prior_card.body.key, binding.human_key]) keys.set(k.id, k);
    const r = verifyProofSet("CARD", b.prior_card, [b.prior_card.body.key.id, binding.human_key.id], (kid) =>
      keys.has(kid) ? pubBytes(keys.get(kid)!) : null,
    );
    if (r !== null) return denyR(r);
  }

  // ---- 5. object cross-links (binding_hash precedes human_principal)
  const bindingHash = digest("BINDING", binding);
  if (card.binding_hash !== bindingHash) return denyR("BINDING_MISMATCH");
  if (card.human_principal !== binding.principal_id) return denyR("BINDING_MISMATCH");
  if (card.did !== binding.did) return denyR("BINDING_MISMATCH");
  const cardHash = digest("CARD", card);
  if (!receipt.objects.includes(cardHash)) return denyR("EVIDENCE_MISMATCH");
  if (receipt.allocated !== card.status_index) return denyR("EVIDENCE_MISMATCH");
  if (receipt.root !== root) return denyR("EVIDENCE_MISMATCH");

  if (receipt.kind === "CardRotated") {
    if (b.prior_card === null || b.rotation === null) return denyR("EVIDENCE_MISMATCH");
    const prior: AgentCard = b.prior_card.body;
    const rot = b.rotation.body;
    if (!receipt.objects.includes(digest("ROTATION", rot))) return denyR("EVIDENCE_MISMATCH");
    if (rot.root !== root || rot.did !== card.did) return denyR("EVIDENCE_MISMATCH");
    if (rot.old_card_hash !== digest("CARD", prior)) return denyR("ROTATION_MISMATCH");
    if (rot.new_card_hash !== cardHash) return denyR("ROTATION_MISMATCH");
    if (rot.old_key_id !== prior.key.id) return denyR("ROTATION_MISMATCH");
    if (rot.new_key.id !== card.key.id || rot.new_key.public_key !== card.key.public_key)
      return denyR("ROTATION_MISMATCH");
    if (rot.from_epoch !== prior.key_epoch) return denyR("ROTATION_MISMATCH");
    if (rot.to_epoch !== card.key_epoch) return denyR("ROTATION_MISMATCH");
    if (BigInt(rot.to_epoch) !== BigInt(rot.from_epoch) + 1n) return denyR("ROTATION_MISMATCH");
    if (card.previous !== digest("CARD", prior)) return denyR("BINDING_MISMATCH");
    if (prior.did !== card.did || prior.human_principal !== card.human_principal)
      return denyR("BINDING_MISMATCH");
    // Rotation proofs: old agent key + new agent key + current human key.
    const keys = new Map<string, { id: string; public_key: string }>();
    for (const k of [prior.key, card.key, binding.human_key]) keys.set(k.id, k);
    const r = verifyProofSet(
      "ROTATION", b.rotation, [prior.key.id, card.key.id, binding.human_key.id],
      (kid) => (keys.has(kid) ? pubBytes(keys.get(kid)!) : null),
    );
    if (r !== null) return denyR(r);
  } else if (receipt.kind === "CardIssued" || receipt.kind === "BindingRenewed") {
    if (b.prior_card !== null || b.rotation !== null) return denyR("EVIDENCE_MISMATCH");
  } else {
    return denyR("EVIDENCE_MISMATCH");
  }

  // ---- 6. status authenticity
  const status: Status = input.status.body;
  if (status.slots !== 131072) return denyR("EVIDENCE_MISMATCH");
  const svcStatus = statusSignerAtSeq(b.roots, BigInt(status.seq));
  if (svcStatus === null || svcStatus.epoch !== status.root_epoch) return denyR("EVIDENCE_MISMATCH");
  {
    const r = verifySingle("STATUS", input.status, svcStatus);
    if (r !== null) return denyR(r);
  }
  if (BigInt(status.seq) < BigInt(receipt.seq)) return denyR("STATUS_ROLLBACK");

  // ---- 7. frontier
  const frontier: Frontier | undefined = ctx.frontiers.find((f) => f.root === root);
  if (frontier) {
    if (BigInt(status.root_epoch) < BigInt(frontier.root_epoch)) return denyR("ROOT_ROLLBACK");
    if (BigInt(status.seq) < BigInt(frontier.seq)) return denyR("STATUS_ROLLBACK");
    if (status.seq === frontier.seq) {
      if (status.log_hash !== frontier.log_hash) return denyR("FORKED");
      const learned = ctx.known_revocations.find((k) => k.root === root);
      if (learned && learned.bits !== status.bits) return denyR("FORKED");
    }
  }
  if (BigInt(status.root_epoch) < BigInt(pin.min_epoch)) return denyR("ROOT_ROLLBACK");
  // Monotonic known bits: every previously learned revoked bit stays set.
  const learned = ctx.known_revocations.find((k) => k.root === root);
  if (learned) {
    const lb = b64uDecode(learned.bits);
    const nb = b64uDecode(status.bits);
    if (lb === null || nb === null) return denyR("EVIDENCE_MISMATCH");
    for (let i = 0; i < lb.length; i++) {
      if ((lb[i]! & ~nb[i]!) !== 0) return denyR("STATUS_ROLLBACK");
    }
  }

  // ---- 8. freshness
  let checkedAt: number;
  let freshDeadline: number | null = null;
  if (input.mode === "bounded_cache") {
    if (status.issued_at > input.now || input.now >= status.expires_at) return denyR("STATUS_STALE");
    if (status.expires_at - status.issued_at > 60) return denyR("STATUS_STALE");
    if (ctx.received_age_s > 60 || ctx.received_age_s < 0 || !Number.isInteger(ctx.received_age_s))
      return denyR("STATUS_STALE");
    checkedAt = status.issued_at;
  } else {
    const fresh: Fresh | null = input.fresh?.body ?? null;
    if (fresh === null || input.fresh === null) return denyR("STATUS_STALE");
    if (ctx.challenge_consumed) return denyR("REPLAY");
    if (
      ctx.challenge_outstanding === null ||
      input.challenge === null ||
      fresh.challenge !== ctx.challenge_outstanding ||
      input.challenge !== ctx.challenge_outstanding
    )
      return denyR("CHALLENGE_MISMATCH");
    if (fresh.status_hash !== digest("STATUS", status)) return denyR("EVIDENCE_MISMATCH");
    if (fresh.seq !== status.seq || fresh.log_hash !== status.log_hash) return denyR("EVIDENCE_MISMATCH");
    if (fresh.checked_at !== status.issued_at) return denyR("EVIDENCE_MISMATCH");
    {
      const svcFresh = statusSignerAtSeq(b.roots, BigInt(fresh.seq));
      if (svcFresh === null || svcFresh.epoch !== status.root_epoch) return denyR("EVIDENCE_MISMATCH");
      const r = verifySingle("FRESH", input.fresh, svcFresh);
      if (r !== null) return denyR(r);
    }
    if (fresh.checked_at > input.now || input.now >= fresh.valid_until) return denyR("STATUS_STALE");
    if (fresh.valid_until - fresh.checked_at > 5) return denyR("STATUS_STALE");
    checkedAt = fresh.checked_at;
    freshDeadline = fresh.valid_until;
  }

  // ---- 9. time intervals (card evaluated before binding)
  if (input.now < card.not_before || input.now >= card.expires_at) return denyR("CARD_EXPIRED");
  if (input.now < binding.issued_at || input.now >= binding.expires_at) return denyR("BINDING_EXPIRED");

  // ---- 10. root state
  if (status.state === "frozen") return denyR("ROOT_FROZEN");

  // ---- 11. bit
  const bitsBytes = b64uDecode(status.bits);
  if (bitsBytes === null || bitsBytes.length !== 16384) return denyR("EVIDENCE_MISMATCH");
  const idx = card.status_index;
  if (((bitsBytes[idx >> 3]! >> (idx % 8)) & 1) === 1) return denyR("CARD_REVOKED");

  const validUntil = Math.min(
    status.expires_at,
    freshDeadline ?? Number.MAX_SAFE_INTEGER,
    card.expires_at,
    binding.expires_at,
  );

  return {
    v: 1,
    decision: "allow",
    code: "ACTIVE",
    did: card.did,
    card_hash: cardHash,
    principal_id: card.human_principal,
    key_epoch: card.key_epoch,
    root,
    status_seq: status.seq,
    checked_at: checkedAt,
    valid_until: validUntil,
    evidence_hash: digest("EVIDENCE", {
      bundle: b,
      status: input.status,
      fresh: input.fresh,
    } as unknown as JsonObject),
  };
}

/**
 * Wrapper (§7.1): applies durable frontier advance, known-bit accumulation,
 * and one-time challenge consumption around the pure verify. Mutates ctx.
 * In a lock-holding SDK this runs under the per-root serialization lock.
 */
export function verifyWithContext(input: VerifyInput, ctx: TrustContext): VerifyResult {
  const result = verify(input, ctx);
  const root = input.bundle.roots[0]?.body.root;
  if (!root) return result;

  if (result.decision === "deny" && result.code === "FORKED") {
    ctx.cache_state = "FORKED"; // retain both signed artifacts (caller stores them)
    return result;
  }
  if (result.decision === "deny" && ["ROOT_UNTRUSTED", "EVIDENCE_MISMATCH", "SIGNATURE_INVALID", "PROOF_SET_INVALID"].includes(result.code)) {
    return result; // inauthentic evidence never poisons frontier
  }

  // Status was authentic and ordered: advance frontier and accumulate bits.
  const status = input.status.body;
  const frontier = ctx.frontiers.find((f) => f.root === root);
  const newFrontier: Frontier = {
    root,
    seq: status.seq,
    log_hash: status.log_hash,
    root_epoch: status.root_epoch,
  };
  if (!frontier) ctx.frontiers.push(newFrontier);
  else if (BigInt(status.seq) >= BigInt(frontier.seq)) {
    frontier.seq = status.seq;
    frontier.log_hash = status.log_hash;
    frontier.root_epoch = status.root_epoch;
  }
  const known = ctx.known_revocations.find((k) => k.root === root);
  if (!known) ctx.known_revocations.push({ root, bits: status.bits });
  else if (BigInt(status.seq) >= 0n) {
    // Merge learned bits: known |= new (never clear).
    const lb = b64uDecode(known.bits)!;
    const nb = b64uDecode(status.bits)!;
    const merged = new Uint8Array(16384);
    for (let i = 0; i < 16384; i++) merged[i] = lb[i]! | nb[i]!;
    let bin = "";
    for (const x of merged) bin += String.fromCharCode(x);
    known.bits = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  if (input.mode === "fresh" && input.fresh !== null) {
    ctx.challenge_consumed = true;
  }
  ctx.cache_state = "USABLE";
  return result;
}
