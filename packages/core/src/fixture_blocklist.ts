/**
 * Compile-time blocklist of the seven published conformance-fixture public-key
 * byte strings (spec §8.1/§9.2): any key file, root document, or pin presenting
 * a blocklisted key while production=true fails SCHEMA_INVALID and readiness
 * stays false.
 */

import { b64uEncode, b64uDecode } from "./base64url.ts";
import { publicKeyFromSeed } from "./ed25519.ts";
import { sha256Hex } from "./digest.ts";

/** The seven fixture seeds are bytes([n])*32 for n = 1..7 — public test material. */
export const FIXTURE_PUBLIC_KEYS: ReadonlySet<string> = new Set(
  Array.from({ length: 7 }, (_, i) => {
    const seed = new Uint8Array(32).fill(i + 1);
    return b64uEncode(publicKeyFromSeed(seed));
  }),
);

/** sha256 fingerprints of the fixture public keys (what RootPin pins carry). */
export const FIXTURE_FINGERPRINTS: ReadonlySet<string> = new Set(
  [...FIXTURE_PUBLIC_KEYS].map((k) => sha256Hex(b64uDecode(k)!)),
);

export function isFixturePublicKey(publicKeyB64u: string): boolean {
  return FIXTURE_PUBLIC_KEYS.has(publicKeyB64u);
}

export function isFixtureFingerprint(fingerprint: string): boolean {
  return FIXTURE_FINGERPRINTS.has(fingerprint);
}

/** Deep-scan a parsed config/document for any embedded fixture key bytes. */
export function containsFixtureKey(value: unknown): boolean {
  if (typeof value === "string") return FIXTURE_PUBLIC_KEYS.has(value);
  if (Array.isArray(value)) return value.some(containsFixtureKey);
  if (typeof value === "object" && value !== null) {
    return Object.values(value as Record<string, unknown>).some(containsFixtureKey);
  }
  return false;
}
