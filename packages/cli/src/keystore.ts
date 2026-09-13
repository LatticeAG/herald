/**
 * Local explicit-file signer profile (spec §9.2): KeyFile documents at
 * chmod 0600 under a 0700 directory, exclusive creation, owner checked,
 * symlinks rejected. No seeds on the command line, stdout, or logs.
 */

import { constants as C } from "node:fs";
import { accessSync, closeSync, lstatSync, mkdirSync, openSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomFillSync } from "node:crypto";
import { b64uDecode, b64uEncode, publicKeyFromSeed, ed25519Sign, digestBytes, isKeyId, newId } from "@latticeag/herald-core";
import type { JsonObject, KeyFile, PublicKey, Signed } from "@latticeag/herald-core";

export class CliExit extends Error {
  readonly exitCode: number;
  constructor(exitCode: number, message: string) {
    super(message);
    this.exitCode = exitCode;
  }
}

/** Load a KeyFile enforcing permission, ownership, and symlink checks. */
export function loadKeyFile(path: string): KeyFile {
  const p = resolve(path);
  let st;
  try {
    st = lstatSync(p);
  } catch {
    throw new CliExit(7, `key file not found: ${path}`);
  }
  if (st.isSymbolicLink()) throw new CliExit(7, `key file is a symlink: ${path}`);
  if (!st.isFile()) throw new CliExit(7, `key file is not a regular file: ${path}`);
  const mode = st.mode & 0o777;
  if (mode !== 0o600) throw new CliExit(7, `key file must be mode 0600 (found ${mode.toString(8)}): ${path}`);
  const dirSt = lstatSync(dirname(p));
  if ((dirSt.mode & 0o777) !== 0o700) throw new CliExit(7, `key directory must be mode 0700: ${dirname(p)}`);
  let kf: KeyFile;
  try {
    kf = JSON.parse(readFileSync(p, "utf8")) as KeyFile;
  } catch {
    throw new CliExit(2, `key file is not valid JSON: ${path}`);
  }
  if (kf.v !== 1 || !isKeyId(kf.kid) || kf.algorithm !== "Ed25519") throw new CliExit(2, `key file malformed: ${path}`);
  const seed = b64uDecode(kf.seed_b64u);
  if (seed === null || seed.length !== 32) throw new CliExit(2, `key file seed malformed: ${path}`);
  return kf;
}

/** Generate a new keypair and write an exclusive KeyFile. */
export function keyGenerate(outPath: string): { keyFile: KeyFile; publicKey: PublicKey } {
  const seed = new Uint8Array(32);
  randomFillSync(seed);
  const pub = publicKeyFromSeed(seed);
  const kid = newId("key");
  const keyFile: KeyFile = { v: 1, kid, algorithm: "Ed25519", seed_b64u: b64uEncode(seed) };
  const publicKey: PublicKey = { id: kid, public_key: b64uEncode(pub) };
  const p = resolve(outPath);
  const dir = dirname(p);
  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    accessSync(dir, C.W_OK);
  } catch {
    throw new CliExit(7, `cannot write key directory: ${dir}`);
  }
  const dirSt = lstatSync(dir);
  if (dirSt.isSymbolicLink()) throw new CliExit(7, `key directory is a symlink: ${dir}`);
  try {
    const fd = openSync(p, "wx", 0o600);
    writeFileSync(fd, JSON.stringify(keyFile) + "\n");
    closeSync(fd);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliExit(7, `key file already exists: ${outPath}`);
    throw new CliExit(7, `cannot create key file: ${outPath}`);
  }
  return { keyFile, publicKey };
}

/** Sign a digest-bound object under one KeyFile. */
export function signWith(keyFile: KeyFile, tag: Parameters<typeof digestBytes>[0], body: JsonObject): Signed<JsonObject> {
  const seed = b64uDecode(keyFile.seed_b64u)!;
  const sig = ed25519Sign(seed, digestBytes(tag, body));
  return { body, proofs: [{ kid: keyFile.kid, signature: b64uEncode(sig) }] };
}
