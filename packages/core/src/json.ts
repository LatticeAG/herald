/**
 * Strict protocol JSON parser (spec §3, §6.1 step 1).
 *
 * Rejects: BOM, trailing data, duplicate keys, invalid Unicode (lone
 * surrogates), lexical negative zero, fractions, exponent notation, NaN,
 * Infinity, numbers outside [0, 2^53-1]. Enforces byte/depth/member/element
 * limits. Parsing never uses JSON.parse so no lax grammar can leak through.
 */

export interface JsonLimits {
  maxBytes: number;
  maxDepth: number;
  maxMembers: number;
  maxElements: number;
}

export const LIMITS_ORDINARY: JsonLimits = { maxBytes: 65536, maxDepth: 16, maxMembers: 128, maxElements: 256 };
export const LIMITS_RESPONSE: JsonLimits = { maxBytes: 262144, maxDepth: 16, maxMembers: 128, maxElements: 256 };
export const LIMITS_DOCUMENT_HISTORY: JsonLimits = { maxBytes: 1048576, maxDepth: 16, maxMembers: 128, maxElements: 256 };
export const LIMITS_EXPORT: JsonLimits = { maxBytes: 8388608, maxDepth: 16, maxMembers: 128, maxElements: 256 };

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };
export type JsonObject = { [k: string]: JsonValue };

export type ParseResult =
  | { ok: true; value: JsonValue }
  | { ok: false; code: "JSON_INVALID" | "DUPLICATE_KEY" | "NUMBER_INVALID" | "TOO_LARGE" };

const MAX_NUM = 9007199254740991; // 2^53 - 1
const BIGINT_MAX_COUNTER = 9223372036854775807n;

class Fail extends Error {
  code: "JSON_INVALID" | "DUPLICATE_KEY" | "NUMBER_INVALID" | "TOO_LARGE";
  constructor(code: Fail["code"]) {
    super(code);
    this.code = code;
  }
}

export function parseJsonStrict(raw: Uint8Array | string, limits: JsonLimits = LIMITS_ORDINARY): ParseResult {
  const bytes = typeof raw === "string" ? new TextEncoder().encode(raw) : raw;
  if (bytes.length > limits.maxBytes) return { ok: false, code: "TOO_LARGE" };
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    return { ok: false, code: "JSON_INVALID" };
  let s: string;
  try {
    s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, code: "JSON_INVALID" };
  }
  const p = new Parser(s, limits);
  try {
    p.ws();
    const v = p.value(0);
    p.ws();
    if (!p.eof()) throw new Fail("JSON_INVALID");
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof Fail) return { ok: false, code: e.code };
    throw e;
  }
}

class Parser {
  private s: string;
  private limits: JsonLimits;
  i = 0;
  constructor(s: string, limits: JsonLimits) {
    this.s = s;
    this.limits = limits;
  }
  eof(): boolean {
    return this.i >= this.s.length;
  }
  peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }
  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  value(depth: number): JsonValue {
    if (depth > this.limits.maxDepth) throw new Fail("TOO_LARGE");
    const c = this.peek();
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    return this.number();
  }
  lit(word: string, val: JsonValue): JsonValue {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return val;
    }
    throw new Fail("JSON_INVALID");
  }
  object(depth: number): JsonObject {
    this.i++; // {
    const out: JsonObject = {};
    this.ws();
    if (this.peek() === 0x7d) {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== 0x22) throw new Fail("JSON_INVALID");
      const k = this.string();
      if (Object.prototype.hasOwnProperty.call(out, k)) throw new Fail("DUPLICATE_KEY");
      this.ws();
      if (this.peek() !== 0x3a) throw new Fail("JSON_INVALID");
      this.i++; // :
      this.ws();
      out[k] = this.value(depth + 1);
      if (Object.keys(out).length > this.limits.maxMembers) throw new Fail("TOO_LARGE");
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        return out;
      }
      throw new Fail("JSON_INVALID");
    }
  }
  array(depth: number): JsonValue[] {
    this.i++; // [
    const out: JsonValue[] = [];
    this.ws();
    if (this.peek() === 0x5d) {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      if (out.length > this.limits.maxElements) throw new Fail("TOO_LARGE");
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        return out;
      }
      throw new Fail("JSON_INVALID");
    }
  }
  string(): string {
    // caller ensured peek() === 0x22
    this.i++; // "
    let out = "";
    for (;;) {
      if (this.eof()) throw new Fail("JSON_INVALID");
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        if (this.eof()) throw new Fail("JSON_INVALID");
        const e = this.s.charCodeAt(this.i);
        this.i++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            out += this.unicodeEscape();
            break;
          }
          default:
            throw new Fail("JSON_INVALID");
        }
        continue;
      }
      if (c < 0x20) throw new Fail("JSON_INVALID");
      if (c >= 0xd800 && c <= 0xdbff) {
        // High surrogate must pair with an immediately following low surrogate.
        const c2 = this.s.charCodeAt(this.i + 1);
        if (c2 >= 0xdc00 && c2 <= 0xdfff) {
          out += this.s.slice(this.i, this.i + 2);
          this.i += 2;
          continue;
        }
        throw new Fail("JSON_INVALID");
      }
      if (c >= 0xdc00 && c <= 0xdfff) throw new Fail("JSON_INVALID");
      out += this.s[this.i]!;
      this.i++;
    }
  }
  private unicodeEscape(): string {
    // Reads exactly XXXX after \u; handles surrogate pairs via a second escape.
    const hex = (): number => {
      if (this.i + 4 > this.s.length) throw new Fail("JSON_INVALID");
      let v = 0;
      for (let k = 0; k < 4; k++) {
        const c = this.s.charCodeAt(this.i + k);
        const d =
          c >= 0x30 && c <= 0x39 ? c - 0x30
          : c >= 0x61 && c <= 0x66 ? c - 0x61 + 10
          : c >= 0x41 && c <= 0x46 ? c - 0x41 + 10
          : -1;
        if (d < 0) throw new Fail("JSON_INVALID");
        v = v * 16 + d;
      }
      this.i += 4;
      return v;
    };
    const u1 = hex();
    if (u1 >= 0xd800 && u1 <= 0xdbff) {
      if (this.s.charCodeAt(this.i) === 0x5c && this.s.charCodeAt(this.i + 1) === 0x75) {
        this.i += 2;
        const u2 = hex();
        if (u2 >= 0xdc00 && u2 <= 0xdfff)
          return String.fromCharCode(u1, u2);
      }
      throw new Fail("JSON_INVALID");
    }
    if (u1 >= 0xdc00 && u1 <= 0xdfff) throw new Fail("JSON_INVALID");
    return String.fromCharCode(u1);
  }
  number(): number {
    const start = this.i;
    const c = this.peek();
    if (c === 0x2d) {
      // Negative: only "-0" could otherwise parse; spec rejects all negatives
      // and lexical negative zero.
      this.i++;
      if (this.s.startsWith("0", this.i) && !/[0-9.eE]/.test(this.s[this.i + 1] ?? ""))
        throw new Fail("NUMBER_INVALID");
      throw new Fail("NUMBER_INVALID");
    }
    if (c < 0x30 || c > 0x39) throw new Fail("JSON_INVALID");
    if (c === 0x30) {
      this.i++;
    } else {
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    }
    const nc = this.peek();
    if (nc === 0x2e || nc === 0x65 || nc === 0x45) throw new Fail("NUMBER_INVALID");
    const text = this.s.slice(start, this.i);
    if (text.length > 1 && text.startsWith("0")) throw new Fail("NUMBER_INVALID");
    // Value bound: integers 0..2^53-1 only.
    if (text.length > 16) {
      const v = BigInt(text);
      if (v > BigInt(MAX_NUM)) throw new Fail("NUMBER_INVALID");
    }
    const v = Number(text);
    if (!Number.isSafeInteger(v) || v < 0 || v > MAX_NUM) throw new Fail("NUMBER_INVALID");
    return v;
  }
}

/** Counter lexical form: 0|[1-9][0-9]{0,18}, numeric bound 2^63-1. */
const COUNTER_RE = /^0|[1-9][0-9]{0,18}$/;
export function isCounter(s: unknown): s is string {
  if (typeof s !== "string" || !COUNTER_RE.test(s)) return false;
  return BigInt(s) <= BIGINT_MAX_COUNTER;
}
