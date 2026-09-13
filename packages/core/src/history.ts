/**
 * verifyHistory (spec §7, §9): check a root-document chain and a signed audit
 * event chain. Never returns live=true; historical verification is evidence,
 * not authorization.
 */

import { b64uDecode } from "./base64url.ts";
import { digest, digestBytes, sha256Hex } from "./digest.ts";
import { ed25519Verify as edVerify } from "./ed25519.ts";
import { verifyProofSet } from "./proofs.ts";
import { validate, MAX_ROOT_EPOCHS } from "./schema.ts";
import type {
  AuditEvent, HistoryResult, RootDocument, RootPin, Signed,
} from "./types.ts";
import type { JsonObject } from "./json.ts";

const ZERO_HASH = "0".repeat(64);

export function verifyHistory(
  events: Signed<AuditEvent>[],
  rootDocs: Signed<RootDocument>[],
  pins: RootPin[],
  verifyFn: (pk: Uint8Array, digest: Uint8Array, sig: Uint8Array) => boolean = edVerify,
): HistoryResult {
  const bad = (code: string): HistoryResult => ({ v: 1, valid: false, live: false, code });
  if (rootDocs.length < 1 || rootDocs.length > MAX_ROOT_EPOCHS) return bad("EVIDENCE_MISMATCH");
  const root = rootDocs[0]!.body.root;
  const pin = pins.find((p) => p.root === root);
  if (!pin || !pin.enabled) return bad("ROOT_UNTRUSTED");
  const ctrl = b64uDecode(rootDocs[0]!.body.control_key.public_key);
  if (ctrl === null || sha256Hex(ctrl) !== pin.control_fingerprint) return bad("ROOT_UNTRUSTED");
  if (digest("ROOT", rootDocs[0]!.body) !== pin.genesis_hash) return bad("ROOT_UNTRUSTED");

  // Root chain: schema, continuity, epoch increments, proof sets.
  for (let i = 0; i < rootDocs.length; i++) {
    const d = rootDocs[i]!;
    if (validate("RootDocument", d.body) !== null) return bad("EVIDENCE_MISMATCH");
    if (d.body.root !== root) return bad("EVIDENCE_MISMATCH");
    if (BigInt(d.body.epoch) !== BigInt(i + 1)) return bad("EVIDENCE_MISMATCH");
    if (i === 0) {
      if (d.body.previous !== null || d.body.cutover !== null) return bad("EVIDENCE_MISMATCH");
      const g = d.body;
      const keys = new Map<string, Uint8Array | null>();
      for (const k of [g.control_key, g.service_key, g.registrar_key]) keys.set(k.id, b64uDecode(k.public_key));
      const r = verifyProofSet("ROOT", d, [g.control_key.id, g.service_key.id, g.registrar_key.id], (kid) => keys.get(kid) ?? null, verifyFn);
      if (r !== null) return bad(r === "PROOF_SET_INVALID" ? "PROOF_SET_INVALID" : "SIGNATURE_INVALID");
    } else {
      const prev = rootDocs[i - 1]!.body;
      const doc = d.body;
      if (doc.previous !== digest("ROOT", prev)) return bad("EVIDENCE_MISMATCH");
      if (doc.control_key.id !== prev.control_key.id || doc.control_key.public_key !== prev.control_key.public_key)
        return bad("EVIDENCE_MISMATCH");
      if (doc.status_slots !== prev.status_slots) return bad("EVIDENCE_MISMATCH");
      if (doc.cutover === null) return bad("EVIDENCE_MISMATCH");
      const expected = [doc.control_key.id, prev.service_key.id, doc.service_key.id, doc.registrar_key.id];
      const keys = new Map<string, Uint8Array | null>();
      for (const k of [doc.control_key, prev.service_key, doc.service_key, doc.registrar_key, prev.registrar_key, prev.control_key])
        keys.set(k.id, b64uDecode(k.public_key));
      const r = verifyProofSet("ROOT", d, expected, (kid) => keys.get(kid) ?? null, verifyFn);
      if (r !== null) return bad(r === "PROOF_SET_INVALID" ? "PROOF_SET_INVALID" : "SIGNATURE_INVALID");
    }
  }

  // Event chain: consecutive seqs from 1, prev links, epoch-consistent signing.
  let prevHash = ZERO_HASH;
  let state: "active" | "frozen" = "active";
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (validate("AuditEvent", e as unknown as JsonObject) !== null) return bad("EVIDENCE_MISMATCH");
    const b = e.body;
    if (b.root !== root) return bad("EVIDENCE_MISMATCH");
    if (BigInt(b.seq) !== BigInt(i + 1)) return bad("EVIDENCE_MISMATCH");
    if (b.prev !== prevHash) return bad("EVIDENCE_MISMATCH");
    const expectedState: "active" | "frozen" = state === "frozen" || b.kind === "RootFrozen" ? "frozen" : "active";
    if (b.root_state !== expectedState) return bad("EVIDENCE_MISMATCH");
    // Event signer: the epoch doc whose event range covers seq (the RootRotated
    // event at cutover+1 is still signed by the pre-cutover service key).
    const seq = BigInt(b.seq);
    let signer: { kid: string; public_key: string; epoch: string } | null = null;
    let lower = 1n;
    for (let j = 0; j < rootDocs.length; j++) {
      const d = rootDocs[j]!.body;
      const next = rootDocs[j + 1]?.body;
      const upper = next === undefined || next.cutover === null ? null : BigInt(next.cutover.seq) + 1n;
      if (seq >= lower && (upper === null || seq <= upper)) {
        signer = { kid: d.service_key.id, public_key: d.service_key.public_key, epoch: d.epoch };
        break;
      }
      if (upper === null) break;
      lower = upper + 1n;
    }
    if (signer === null) return bad("EVIDENCE_MISMATCH");
    if (b.root_epoch !== signer.epoch) return bad("EVIDENCE_MISMATCH");
    const pk = b64uDecode(signer.public_key);
    const p0 = e.proofs.length === 1 ? e.proofs[0]! : null;
    if (p0 === null || p0.kid !== signer.kid || pk === null) return bad("SIGNATURE_INVALID");
    const sig = b64uDecode(p0.signature);
    if (sig === null || !verifyFn(pk, digestBytes("EVENT", b), sig)) return bad("SIGNATURE_INVALID");
    prevHash = digest("EVENT", b);
    if (b.kind === "RootRotated") {
      // The successor document must be in the supplied history and named in
      // this event's objects.
      const successor = rootDocs.find((d) => BigInt(d.body.epoch) === BigInt(b.root_epoch) + 1n);
      if (!successor || !b.objects.includes(digest("ROOT", successor.body))) return bad("EVIDENCE_MISMATCH");
    }
    state = b.root_state;
  }
  const last = events[events.length - 1];
  return {
    v: 1,
    valid: true,
    live: false,
    last_seq: last ? last.body.seq : "0",
    last_hash: last ? digest("EVENT", last.body) : ZERO_HASH,
  };
}
