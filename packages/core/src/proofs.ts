/**
 * Proof-set verification (spec §3, §5): proofs are sorted ascending by kid,
 * unique, and must equal exactly the required signer set. Each proof signs
 * the 32 raw bytes of D(tag, body).
 */

import { b64uDecode } from "./base64url.ts";
import { digest, digestBytes, type Tag } from "./digest.ts";
import { ed25519Verify as edVerify } from "./ed25519.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { ed25519Sign as edSign } from "./ed25519.ts";

export interface SignedEnvelope {
  body: JsonObject;
  proofs: { kid: string; signature: string }[];
}

/**
 * Check the proof set equals expectedKids (distinct, compared as a set after
 * dedup of expected values), then verify every signature.
 * Returns null on success, or "PROOF_SET_INVALID" / "SIGNATURE_INVALID".
 */
export function verifyProofSet(
  tag: Tag,
  env: SignedEnvelope,
  expectedKids: string[],
  keyBytes: (kid: string) => Uint8Array | null,
  verifyFn: (pk: Uint8Array, digest: Uint8Array, sig: Uint8Array) => boolean = edVerify,
): string | null {
  const expected = [...new Set(expectedKids)].sort();
  const actual = env.proofs.map((p) => p.kid);
  const actualSorted = [...actual].sort();
  if (actual.length !== actualSorted.length || actual.some((k, i) => k !== actualSorted[i]))
    return "PROOF_SET_INVALID";
  if (new Set(actual).size !== actual.length) return "PROOF_SET_INVALID";
  if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i]))
    return "PROOF_SET_INVALID";
  const digest = digestBytes(tag, env.body);
  for (const p of env.proofs) {
    const pk = keyBytes(p.kid);
    const sig = b64uDecode(p.signature);
    if (pk === null || sig === null || sig.length !== 64) return "SIGNATURE_INVALID";
    if (!verifyFn(pk, digest, sig)) return "SIGNATURE_INVALID";
  }
  return null;
}

/** Produce one proof for a body under one seed. */
export function signBody(tag: Tag, body: JsonObject, kid: string, seed: Uint8Array): { kid: string; signature: string } {
  const d = digestBytes(tag, body);
  const sig = edSign(seed, d);
  let bin = "";
  for (const b of sig) bin += String.fromCharCode(b);
  return { kid, signature: btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") };
}

/** Build a Signed<T> envelope from a body and a set of (kid, seed) signers. */
export function signed(tag: Tag, body: JsonObject, signers: { kid: string; seed: Uint8Array }[]): SignedEnvelope {
  const proofs = signers
    .map((s) => signBody(tag, body, s.kid, s.seed))
    .sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
  const seen = new Set<string>();
  const out = proofs.filter((p) => (seen.has(p.kid) ? false : (seen.add(p.kid), true)));
  return { body: JSON.parse(JSON.stringify(body)) as JsonObject, proofs: out };
}

export function signedBodyHash(tag: Tag, env: SignedEnvelope): string {
  return digest(tag, env.body);
}
