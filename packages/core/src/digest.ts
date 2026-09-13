/**
 * Tagged digest domain (spec §3):
 *   D(tag,x) = hex(SHA256(UTF8("HERALD/" + tag + "/1\0") || J(x)))
 * Proofs sign the 32 raw bytes decoded from D(tag, body).
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.ts";
import type { JsonValue } from "./json.ts";

export const TAGS = [
  "ROOT", "BINDING", "CARD", "ROTATION", "COMMAND", "QUERY",
  "RECEIPT", "EVENT", "STATUS", "FRESH", "CAPABILITIES", "EVIDENCE",
] as const;
export type Tag = (typeof TAGS)[number];

const TAG_SET = new Set<string>(TAGS);

export function isTag(s: string): s is Tag {
  return TAG_SET.has(s);
}

export function digest(tag: Tag, value: JsonValue): string {
  const h = createHash("sha256");
  h.update(`HERALD/${tag}/1\0`, "utf8");
  h.update(canonicalize(value));
  return h.digest("hex");
}

export const D = digest;

export function digestBytes(tag: Tag, value: JsonValue): Uint8Array {
  return Uint8Array.from(Buffer.from(digest(tag, value), "hex"));
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
