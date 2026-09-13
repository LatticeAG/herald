/**
 * Conformance harness: loads the normative fixtures and mirrors the fixture
 * generator's signing helpers so tests can build mutated-but-valid commands.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  b64uDecode, b64uEncode, digest, digestBytes, ed25519Sign, ed25519Verify,
  canonicalize,
} from "@latticeag/herald-core";
import type { Signed, JsonObject, Command, AuditEvent, RootDocument, Status, AgentCard, HumanBinding, Rotation, PublicKey } from "@latticeag/herald-core";
import { NodeSqliteDb } from "../../packages/worker/src/sql.ts";
import { AeadBox } from "../../packages/worker/src/aead.ts";
import { RootDO } from "../../packages/worker/src/rootdo.ts";

const here = dirname(fileURLToPath(import.meta.url));
export const FX = JSON.parse(readFileSync(join(here, "../../fixtures/fixtures.json"), "utf8")) as Record<string, any>;

export const T: number = FX.T;
export const R: string = FX.R;

export function seed(n: number): Uint8Array {
  return b64uDecode(FX.KEYS[String(n)].seed_b64u)!;
}
export function pub(n: number): PublicKey {
  return { id: FX.KEYS[String(n)].kid, public_key: FX.KEYS[String(n)].public_key };
}
export function jkt(n: number): string {
  return FX.KEYS[String(n)].jkt;
}

/** Fixture `signed()`: proofs sorted by key index (== kid order here). */
export function signed<T extends JsonObject>(tag: Parameters<typeof digestBytes>[0], body: T, signers: number[]): Signed<T> {
  const uniq = [...new Set(signers)].sort((a, b) => a - b);
  const proofs = uniq.map((n) => ({
    kid: FX.KEYS[String(n)].kid,
    signature: b64uEncode(ed25519Sign(seed(n), digestBytes(tag, body))),
  }));
  return { body: JSON.parse(JSON.stringify(body)), proofs };
}

export function ident(prefix: string, n: number): string {
  return `${prefix}_${String(n).padStart(21, "0")}`;
}

export function command(n: number, actor: number, revision: string | number, action: JsonObject, subject: string = FX.A): Signed<Command> {
  return signed("COMMAND", {
    v: 1, root: R, op_id: ident("ho", n), actor: FX.KEYS[String(actor)].kid,
    subject, expected_revision: String(revision), issued_at: T, expires_at: T + 60, action,
  } as unknown as Command, [actor]);
}

export function event(seq: number, prev: string, kind: string, requestHash: string, objects: string[], allocated: number | null = null, invalidated: number[] = [], epoch = "1", state = "active", signer = 2): Signed<AuditEvent> {
  return signed("EVENT", {
    v: 1, root: R, seq: String(seq), prev, time: T, root_epoch: epoch, kind,
    request_hash: requestHash, objects: [...objects].sort(), invalidated: [...invalidated].sort((a, b) => a - b),
    allocated, root_state: state,
  } as unknown as AuditEvent, [signer]);
}

export function status(over: Partial<Status> = {}, signer = 2): Signed<Status> {
  const base: Status = FX.ST.body;
  return signed("STATUS", { ...base, ...over } as Status, [signer]);
}

export function bits(...indices: number[]): string {
  const raw = new Uint8Array(16384);
  for (const i of indices) raw[i >> 3] = raw[i >> 3]! | (1 << (i % 8));
  return b64uEncode(raw);
}

export function enc(o: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(o));
}

export function canonEq(a: unknown, b: unknown): boolean {
  return Buffer.from(canonicalize(a as JsonObject)).equals(Buffer.from(canonicalize(b as JsonObject)));
}

const seeds = new Map(Object.values(FX.KEYS).map((k: any) => [k.kid, b64uDecode(k.seed_b64u)!] as const));

export interface World {
  db: NodeSqliteDb;
  d: RootDO;
}

/** Fresh registry; clock pinned at fixture time T. */
export function world(clock: () => number = () => T): World {
  const db = new NodeSqliteDb(":memory:");
  const d = new RootDO(db, {
    root: R,
    serviceKeys: (kid) => seeds.get(kid) ?? null,
    dataBox: new AeadBox(new Uint8Array(32).fill(7)),
    clock,
  });
  d.bootstrap(FX.SR);
  return { db, d };
}

/** S1 = bootstrap + enroll; S2 = +issue; S3 = +rotate. */
export function worldAt(stage: 0 | 1 | 2 | 3, clock?: () => number): World {
  const w = world(clock);
  if (stage >= 1) w.d.submitCommand(enc(FX.ENROLL));
  if (stage >= 2) w.d.submitCommand(enc(FX.ISSUE));
  if (stage >= 3) w.d.submitCommand(enc(FX.ROTATE));
  return w;
}

export function seqOf(w: World): string {
  return String(w.db.get("SELECT seq FROM root_state WHERE singleton=1")!["seq"]);
}

export function lastEvent(w: World): Signed<AuditEvent> {
  const r = w.db.get("SELECT canonical FROM events ORDER BY seq DESC LIMIT 1")!;
  return JSON.parse(new TextDecoder().decode(r["canonical"] as Uint8Array));
}
