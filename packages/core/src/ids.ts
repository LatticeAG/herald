/**
 * Identifier profile (spec §3): locked prefixes + nanoid suffixes, CSPRNG.
 * Alphabet: [A-Za-z0-9_-]. No timestamps/counters/names in production IDs.
 */

import { randomInt } from "node:crypto";

export const NANOID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

export const ID_PREFIXES = {
  root: "hr",
  agent: "ha",
  card: "hc",
  principal: "hp",
  binding: "hb",
  key: "hk",
  op: "ho",
  query: "hq",
} as const;

const NANOID_RE = /^[A-Za-z0-9_-]+$/;

export function nanoid(len: number): string {
  let out = "";
  while (out.length < len) out += NANOID_ALPHABET[randomInt(0, 64)];
  return out;
}

export function newId(kind: keyof typeof ID_PREFIXES): string {
  return ID_PREFIXES[kind] + "_" + nanoid(21);
}

export function newChallenge(): string {
  return "hn_" + nanoid(32);
}

function hasSuffix(id: string, prefix: string, len: number): boolean {
  if (!id.startsWith(prefix + "_")) return false;
  const s = id.slice(prefix.length + 1);
  return s.length === len && NANOID_RE.test(s);
}

export const isRootId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hr", 21);
export const isAgentId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "ha", 21);
export const isCardId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hc", 21);
export const isPrincipalId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hp", 21);
export const isBindingId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hb", 21);
export const isKeyId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hk", 21);
export const isOpId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "ho", 21);
export const isQueryId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hq", 21);
export const isNonce = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "hn", 32);
export const isGatewayId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "lsg", 21);
export const isTenantId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "ltn", 21);
export const isSubId = (s: unknown): s is string => typeof s === "string" && hasSuffix(s, "lsu", 21);

export const HASH_RE = /^[0-9a-f]{64}$/;
export const isHash = (s: unknown): s is string => typeof s === "string" && HASH_RE.test(s);

const DID_RE = /^did:herald:hr_[A-Za-z0-9_-]{21}:ha_[A-Za-z0-9_-]{21}$/;
export function isDid(s: unknown): s is string {
  return typeof s === "string" && s.length <= 64 && DID_RE.test(s);
}

export function didParts(did: string): { root: string; agent: string } | null {
  if (!isDid(did)) return null;
  const [, , root, agent] = did.split(":");
  return { root: root!, agent: agent! };
}

export function agentIdOfDid(did: string): string | null {
  return didParts(did)?.agent ?? null;
}

/**
 * HTTPS origin per §4: no path, userinfo, fragment, query, IP literal, or
 * non-443 port. http://localhost[:port] accepted in development profiles only.
 */
export function isOrigin(s: unknown, development: boolean): s is string {
  if (typeof s !== "string") return false;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "") return false;
  if (u.pathname !== "/" || u.search !== "" || u.hash !== "") return false;
  if (/^\[.*\]$/.test(u.hostname) || /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) return false;
  if (u.protocol === "https:") return u.port === "" || u.port === "443";
  if (development && u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
  return false;
}
