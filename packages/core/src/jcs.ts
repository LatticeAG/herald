/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 *
 * Input must already be a strict protocol JSON value (see json.ts): keys sort
 * by UTF-16 code units, numbers use ECMAScript serialization (the protocol
 * only admits non-negative integers <= 2^53-1), strings use minimal escapes.
 * Output is UTF-8 without a trailing newline.
 */

import type { JsonValue } from "./json.ts";

function escapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    switch (c) {
      case 0x22: out += '\\"'; break;
      case 0x5c: out += "\\\\"; break;
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0a: out += "\\n"; break;
      case 0x0c: out += "\\f"; break;
      case 0x0d: out += "\\r"; break;
      default:
        if (c < 0x20) {
          out += "\\u" + c.toString(16).padStart(4, "0");
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

function serialize(v: JsonValue): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error("non-canonical number");
    return String(v);
  }
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(serialize).join(",") + "]";
  }
  const keys = Object.keys(v).sort(); // UTF-16 code-unit order
  const parts = keys.map((k) => escapeString(k) + ":" + serialize(v[k]!));
  return "{" + parts.join(",") + "}";
}

export function canonicalize(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

export function canonicalizeText(value: JsonValue): string {
  return serialize(value);
}
