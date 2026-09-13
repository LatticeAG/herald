/**
 * Private-record encryption envelope (spec §11):
 *   key_version:uint32be || nonce:12 || AES-256-GCM(ciphertext || tag:16)
 * AAD = UTF-8 JCS of {root, table, primary_key, key_version}.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { canonicalize } from "@latticeag/herald-core";

export class AeadBox {
  private key: Uint8Array;
  private version: number;
  constructor(dataKey: Uint8Array, version = 1) {
    if (dataKey.length !== 32) throw new Error("data key must be 32 bytes");
    this.key = dataKey;
    this.version = version;
  }
  encrypt(root: string, table: string, pk: string, plaintext: Uint8Array): Uint8Array {
    const aad = canonicalize({
      key_version: this.version,
      primary_key: pk,
      root,
      table,
    });
    const nonce = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key, nonce);
    c.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
    const tag = c.getAuthTag();
    const out = new Uint8Array(4 + 12 + ct.length + 16);
    new DataView(out.buffer).setUint32(0, this.version);
    out.set(nonce, 4);
    out.set(ct, 16);
    out.set(tag, 16 + ct.length);
    return out;
  }
  decrypt(root: string, table: string, pk: string, blob: Uint8Array): Uint8Array {
    const version = new DataView(blob.buffer, blob.byteOffset).getUint32(0);
    const aad = canonicalize({
      key_version: version,
      primary_key: pk,
      root,
      table,
    });
    const nonce = blob.slice(4, 16);
    const ct = blob.slice(16, blob.length - 16);
    const tag = blob.slice(blob.length - 16);
    const d = createDecipheriv("aes-256-gcm", this.key, nonce);
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(ct)), d.final()]));
  }
}
