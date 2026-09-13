/** Unpadded base64url: only [A-Za-z0-9_-], must round-trip byte-for-byte. */

const RE = /^[A-Za-z0-9_-]*$/;

export function b64uEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uEncodeText(s: string): string {
  return b64uEncode(new TextEncoder().encode(s));
}

/**
 * Strict decode. Returns null when the input is not canonical unpadded
 * base64url (padded, foreign characters, or non-round-trippable length class).
 */
export function b64uDecode(s: string): Uint8Array | null {
  if (!RE.test(s)) return null;
  if (s.length % 4 === 1) return null; // impossible base64 length class
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(padded);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // Round-trip check: re-encoding must reproduce the input exactly.
  if (b64uEncode(out) !== s) return null;
  return out;
}

export function b64uDecodeExact(s: string, len: number): Uint8Array | null {
  const b = b64uDecode(s);
  return b !== null && b.length === len ? b : null;
}
