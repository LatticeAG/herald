/**
 * Strict RFC 8032 Ed25519 (pure profile, no ph/ctx, no algorithm negotiation).
 *
 * Enforces the spec's strictness profile on top of raw verification:
 * canonical point encodings (y < p, on-curve), rejection of identity and
 * small-order public keys, canonical S scalars (S < L). Implemented with
 * explicit field/curve arithmetic so TypeScript and Python agree byte-for-byte
 * on acceptance, not just on signatures.
 */

import { createHash, randomBytes } from "node:crypto";

const P = (1n << 255n) - 19n;
const D_CONST = (-121665n * modInv(121666n, P)) % P;
const I = modPow(2n, (P - 1n) / 4n, P); // sqrt(-1)
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const BY = (4n * modInv(5n, P)) % P;
const BX = recoverX(BY, 0n)!;

export interface Point {
  x: bigint;
  y: bigint;
  z: bigint;
  t: bigint;
}

function modInv(a: bigint, m: bigint): bigint {
  // Fermat inversion for prime modulus.
  return modPow(a, m - 2n, m);
}
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function mp(a: bigint): bigint {
  return ((a % P) + P) % P;
}
function ml(a: bigint): bigint {
  return ((a % L) + L) % L;
}

function pt(x: bigint, y: bigint): Point {
  return { x, y, z: 1n, t: mp(x * y) };
}
const IDENTITY: Point = { x: 0n, y: 1n, z: 1n, t: 0n };
const BASE: Point = pt(BX, BY);

function isIdentity(q: Point): boolean {
  const zinv = modInv(q.z, P);
  const x = mp(q.x * zinv);
  const y = mp(q.y * zinv);
  return x === 0n && y === 1n;
}

/** Complete extended-coordinate addition (a = -1 twisted Edwards). */
function add(p1: Point, p2: Point): Point {
  const A = mp((p1.y - p1.x) * (p2.y - p2.x));
  const B = mp((p1.y + p1.x) * (p2.y + p2.x));
  const C = mp(2n * p1.t * p2.t * D_CONST);
  const Dd = mp(2n * p1.z * p2.z);
  const E = mp(B - A);
  const F = mp(Dd - C);
  const G = mp(Dd + C);
  const H = mp(B + A);
  return { x: mp(E * F), y: mp(G * H), z: mp(F * G), t: mp(E * H) };
}

function scalarmult(q: Point, n: bigint): Point {
  let r = IDENTITY;
  let b = q;
  let e = n;
  while (e > 0n) {
    if (e & 1n) r = add(r, b);
    b = add(b, b);
    e >>= 1n;
  }
  return r;
}

/** x = sqrt((y^2-1)/(d*y^2+1)); null when no root. sign selects parity. */
function recoverX(y: bigint, sign: bigint): bigint | null {
  const y2 = mp(y * y);
  const xx = mp((y2 - 1n) * modInv(mp(D_CONST * y2) + 1n, P));
  let x = modPow(xx, (P + 3n) / 8n, P);
  if (mp(x * x - xx) !== 0n) {
    x = mp(x * I);
    if (mp(x * x - xx) !== 0n) return null;
  }
  if (x === 0n && sign === 1n) return null; // non-canonical per RFC 8032
  if ((x & 1n) !== sign) x = P - x;
  return x;
}

export type DecodeResult = { point: Point; canonical: true } | null;

/**
 * Strict point decode: canonical encoding (y < p), on-curve, x exists.
 * Returns the point or null. Does not itself reject small-order points;
 * use isSmallOrder for that check.
 */
export function decodePoint(bytes: Uint8Array): Point | null {
  if (bytes.length !== 32) return null;
  let y = 0n;
  for (let i = 0; i < 32; i++) y |= BigInt(bytes[i]!) << (8n * BigInt(i));
  const sign = (y >> 255n) & 1n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return null; // non-canonical
  const x = recoverX(y, sign);
  if (x === null) return null;
  return pt(x, y);
}

/** True when the point lies in the small (cofactor) subgroup. */
export function isSmallOrder(q: Point): boolean {
  return isIdentity(scalarmult(q, 8n));
}

export function encodePoint(q: Point): Uint8Array {
  const zinv = modInv(q.z, P);
  const x = mp(q.x * zinv);
  let y = mp(q.y * zinv);
  if (x & 1n) y |= 1n << 255n;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((y >> (8n * BigInt(i))) & 0xffn);
  return out;
}

/** Strict public-key validation: canonical, on-curve, not small-order. */
export function publicKeyValid(bytes: Uint8Array): boolean {
  const q = decodePoint(bytes);
  if (q === null) return false;
  return !isSmallOrder(q);
}

function sha512(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha512");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function clampScalar(h: Uint8Array): bigint {
  const a = new Uint8Array(h.slice(0, 32));
  a[0]! &= 248;
  a[31]! &= 63;
  a[31]! |= 64;
  let n = 0n;
  for (let i = 0; i < 32; i++) n |= BigInt(a[i]!) << (8n * BigInt(i));
  return n;
}

function leBytesToBigint(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < b.length; i++) n |= BigInt(b[i]!) << (8n * BigInt(i));
  return n;
}
function bigintToLeBytes(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = Number((n >> (8n * BigInt(i))) & 0xffn);
  return out;
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const a = clampScalar(sha512(seed));
  return encodePoint(scalarmult(BASE, a));
}

export function keygen(): { seed: Uint8Array; publicKey: Uint8Array } {
  const seed = randomBytes(32);
  return { seed, publicKey: publicKeyFromSeed(seed) };
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const a = clampScalar(h);
  const pub = encodePoint(scalarmult(BASE, a));
  const r = ml(leBytesToBigint(sha512(h.slice(32), message)));
  const R = encodePoint(scalarmult(BASE, r));
  const k = ml(leBytesToBigint(sha512(R, pub, message)));
  const S = ml(r + k * a);
  const sig = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(bigintToLeBytes(S, 32), 32);
  return sig;
}

export function isCanonicalScalar(sBytes: Uint8Array): boolean {
  if (sBytes.length !== 32) return false;
  return leBytesToBigint(sBytes) < L;
}

/**
 * Strict verify: canonical public key (not small-order), canonical R,
 * canonical S, cofactorless verification equation [S]B = R + [k]A.
 */
export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const A = decodePoint(publicKey);
  if (A === null || isSmallOrder(A)) return false;
  const Rb = signature.slice(0, 32);
  const R = decodePoint(Rb);
  if (R === null) return false;
  const sBytes = signature.slice(32);
  if (!isCanonicalScalar(sBytes)) return false;
  const S = leBytesToBigint(sBytes);
  const k = ml(leBytesToBigint(sha512(Rb, publicKey, message)));
  // [S]B ?= R + [k]A
  const lhs = scalarmult(BASE, S);
  const rhs = add(R, scalarmult(A, k));
  return encodePoint(lhs).every((b, i) => b === encodePoint(rhs)[i]);
}
