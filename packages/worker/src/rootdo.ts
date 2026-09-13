/**
 * RootDO — the sole mutable authority for one Herald root (spec §2, §5, §6).
 * Implements the §6.1 transaction and idempotency algorithm: every mutation is
 * one SQLite transaction under the serialization barrier; crash before commit
 * leaves no successful mutation; exact replay returns the stored reply.
 */

import {
  b64uDecode, b64uEncode, canonicalize, D, digestBytes, ed25519Sign,
  ed25519Verify, err, HeraldError, isBindingId, isCardId, isDid, isRootId,
  isKeyId, callerJkt, parseJsonStrict, LIMITS_ORDINARY, verifyProofSet,
  MAX_AGENTS, MAX_BINDING_LIFETIME, MAX_BINDING_REVISIONS, MAX_CARD_LIFETIME,
  MAX_COMMAND_LIFETIME, MAX_KEY_EPOCHS, MAX_QUERY_LIFETIME, STATUS_SLOTS,
  validate, didParts,
} from "@latticeag/herald-core";
import type {
  AgentCard, AuditEvent, Command, HumanBinding, IdentityBundle,
  PublicKey, Query, Receipt, RootDocument, Rotation, Signed, Status, Fresh,
  FreshReply, AgentRecord, MutationReply, ResolveReply, ExportReply, LogPage,
  RootHistoryReply,
} from "@latticeag/herald-core";
import type { JsonObject, JsonValue } from "@latticeag/herald-core";
import type { SqlDb, Row } from "./sql.ts";
import type { AeadBox } from "./aead.ts";

const ZERO_HASH = "0".repeat(64);
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS root_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), root TEXT NOT NULL UNIQUE,
  epoch INTEGER NOT NULL, seq INTEGER NOT NULL, head TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active','frozen')), last_time INTEGER NOT NULL,
  allocated_bits BLOB NOT NULL CHECK(length(allocated_bits)=16384),
  revoked_bits BLOB NOT NULL CHECK(length(revoked_bits)=16384)
);
CREATE TABLE IF NOT EXISTS root_documents (epoch INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS agents (
  did TEXT PRIMARY KEY, revision INTEGER NOT NULL, key_epoch INTEGER NOT NULL,
  state TEXT NOT NULL, current_key TEXT NOT NULL, binding_hash TEXT NOT NULL,
  current_card_hash TEXT, last_card_hash TEXT, private_record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
  kid TEXT PRIMARY KEY, public_key BLOB NOT NULL UNIQUE, role TEXT NOT NULL,
  did TEXT, first_seq INTEGER NOT NULL, retired_seq INTEGER, revoked_seq INTEGER
);
CREATE TABLE IF NOT EXISTS objects (
  hash TEXT PRIMARY KEY, object_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  did TEXT, canonical_ciphertext BLOB NOT NULL, data_key_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cards (
  card_id TEXT PRIMARY KEY, did TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
  slot INTEGER NOT NULL UNIQUE CHECK(slot>=0 AND slot<131072), issuance_seq INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bindings (id TEXT PRIMARY KEY, did TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, state TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, did TEXT NOT NULL UNIQUE, human_kid TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS operations (
  op_id TEXT PRIMARY KEY, actor TEXT NOT NULL, request_hash TEXT NOT NULL,
  subject TEXT NOT NULL, seq INTEGER NOT NULL UNIQUE, receipt_ciphertext BLOB NOT NULL,
  command_ciphertext BLOB NOT NULL, reply_ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_cards ON cards(did,issuance_seq);
CREATE INDEX IF NOT EXISTS agent_operations ON operations(subject,seq);
CREATE INDEX IF NOT EXISTS agent_bindings ON bindings(did);
`;

export interface KeyResolver {
  (kid: string): Uint8Array | null;
}

export interface FrontierMirror {
  load(): { seq: string; log_hash: string } | null;
  save(f: { seq: string; log_hash: string }): void;
}

export interface RootDOOptions {
  root: string;
  serviceKeys: KeyResolver; // kid -> seed for the root's service keys (current + retained)
  dataBox: AeadBox;
  clock: () => number; // trusted unix seconds
  frontier?: FrontierMirror; // independently retained acknowledged frontier
  crashHook?: ((point: "before_commit" | "after_sign") => void) | undefined;
  /**
   * Signature primitive seam. Defaults to the strict profile; tests may
   * inject a faster backend (node:crypto) — strict-accept ⊆ backend-accept,
   * so the injected backend is a valid lower bound for schedule fuzzing.
   */
  signFn?: (seed: Uint8Array, digest: Uint8Array) => Uint8Array;
  verifyFn?: (pk: Uint8Array, digest: Uint8Array, sig: Uint8Array) => boolean;
}

interface RootState {
  epoch: number;
  seq: number;
  head: string;
  state: "active" | "frozen";
  last_time: number;
  allocated_bits: Uint8Array;
  revoked_bits: Uint8Array;
}

interface AgentRow {
  did: string;
  revision: bigint;
  key_epoch: bigint;
  state: string;
  current_key: PublicKey;
  binding_hash: string;
  current_card_hash: string | null;
  last_card_hash: string | null;
}

interface KeyRow {
  kid: string;
  public_key: Uint8Array;
  role: string;
  did: string | null;
  first_seq: number;
  retired_seq: number | null;
  revoked_seq: number | null;
}

export class RootDO {
  private db: SqlDb;
  private opts: RootDOOptions;

  constructor(db: SqlDb, opts: RootDOOptions) {
    this.db = db;
    this.opts = opts;
    this.db.exec(SCHEMA_SQL);
  }

  private get verifyFn() {
    return this.opts.verifyFn ?? ed25519Verify;
  }

  /** Authoritative nondecreasing time: max(last_time, trusted clock). */
  private now(): number {
    const st = this.rootState();
    const t = Math.floor(this.opts.clock());
    if (st && t < st.last_time - 2) throw err("CLOCK_UNSAFE");
    return st ? Math.max(st.last_time, t) : t;
  }

  private rootState(): RootState | null {
    const r = this.db.get("SELECT * FROM root_state WHERE singleton=1");
    if (!r) return null;
    return {
      epoch: Number(r["epoch"]),
      seq: Number(r["seq"]),
      head: r["head"] as string,
      state: r["state"] as "active" | "frozen",
      last_time: Number(r["last_time"]),
      allocated_bits: new Uint8Array(r["allocated_bits"] as Uint8Array),
      revoked_bits: new Uint8Array(r["revoked_bits"] as Uint8Array),
    };
  }

  private rootDoc(epoch: number): Signed<RootDocument> | null {
    const r = this.db.get("SELECT canonical FROM root_documents WHERE epoch=?", epoch);
    if (!r) return null;
    return JSON.parse(new TextDecoder().decode(r["canonical"] as Uint8Array)) as Signed<RootDocument>;
  }
  private currentDoc(): Signed<RootDocument> {
    const st = this.rootState();
    if (!st) throw err("ROOT_UNKNOWN");
    return this.rootDoc(st.epoch)!;
  }

  private agent(did: string): AgentRow | null {
    const r = this.db.get("SELECT * FROM agents WHERE did=?", did);
    if (!r) return null;
    return {
      did: r["did"] as string,
      revision: BigInt(r["revision"] as number),
      key_epoch: BigInt(r["key_epoch"] as number),
      state: r["state"] as string,
      current_key: JSON.parse(r["current_key"] as string) as PublicKey,
      binding_hash: r["binding_hash"] as string,
      current_card_hash: (r["current_card_hash"] as string | null) ?? null,
      last_card_hash: (r["last_card_hash"] as string | null) ?? null,
    };
  }

  private keyRow(kid: string): KeyRow | null {
    const r = this.db.get("SELECT * FROM keys WHERE kid=?", kid);
    if (!r) return null;
    return {
      kid: r["kid"] as string,
      public_key: new Uint8Array(r["public_key"] as Uint8Array),
      role: r["role"] as string,
      did: (r["did"] as string | null) ?? null,
      first_seq: Number(r["first_seq"]),
      retired_seq: (r["retired_seq"] as number | null) ?? null,
      revoked_seq: (r["revoked_seq"] as number | null) ?? null,
    };
  }

  private keyByBytes(pub: Uint8Array): KeyRow | null {
    const r = this.db.get("SELECT * FROM keys WHERE public_key=?", pub);
    return r ? this.keyRow(r["kid"] as string) : null;
  }

  private storeObject(tag: "BINDING" | "CARD" | "ROTATION", objectId: string, did: string | null, env: Signed<JsonObject>): string {
    const hash = D(tag, env.body);
    const plain = canonicalize(env as unknown as JsonObject);
    const ct = this.opts.dataBox.encrypt(this.opts.root, "objects", objectId, plain);
    this.db.run(
      "INSERT INTO objects(hash,object_id,kind,did,canonical_ciphertext,data_key_version) VALUES(?,?,?,?,?,1)",
      hash, objectId, tag, did, ct,
    );
    return hash;
  }

  private loadObject(hash: string, kind: string): Signed<JsonObject> | null {
    const r = this.db.get("SELECT object_id, canonical_ciphertext FROM objects WHERE hash=? AND kind=?", hash, kind);
    if (!r) return null;
    const plain = this.opts.dataBox.decrypt(this.opts.root, "objects", r["object_id"] as string, new Uint8Array(r["canonical_ciphertext"] as Uint8Array));
    return JSON.parse(new TextDecoder().decode(plain)) as Signed<JsonObject>;
  }

  private currentServiceKey(): { doc: Signed<RootDocument>; kid: string; public_key: string; seed: Uint8Array } {
    const doc = this.currentDoc();
    const kid = doc.body.service_key.id;
    const seed = this.opts.serviceKeys(kid);
    if (!seed) throw err("UNAVAILABLE");
    return { doc, kid, public_key: doc.body.service_key.public_key, seed };
  }

  private signEnvelope<T extends JsonObject>(tag: Parameters<typeof D>[0], body: T, seed: Uint8Array, kid: string): Signed<T> {
    const digest = digestBytes(tag, body);
    const sig = (this.opts.signFn ?? ed25519Sign)(seed, digest);
    return { body, proofs: [{ kid, signature: b64uEncode(sig) }] };
  }

  private writeFrontier(st: RootState): void {
    this.opts.frontier?.save({ seq: String(st.seq), log_hash: st.head });
  }

  /**
   * Bootstrap: local-only provisioning. Refuses an existing root database.
   * Validates genesis proofs and emits RootCreated (seq=1).
   */
  bootstrap(genesis: Signed<RootDocument>): Signed<AuditEvent> {
    if (this.rootState() !== null) throw err("STATE_TRANSITION");
    const doc = genesis.body;
    if (doc.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    if (validate("RootDocument", doc) !== null) throw err("SCHEMA_INVALID");
    if (doc.epoch !== "1" || doc.previous !== null || doc.cutover !== null) throw err("SCHEMA_INVALID");
    // Genesis proofs: control + service + registrar possession.
    const keys = new Map<string, Uint8Array | null>();
    for (const k of [doc.control_key, doc.service_key, doc.registrar_key]) keys.set(k.id, b64uDecode(k.public_key));
    const pr = verifyProofSet("ROOT", genesis, [doc.control_key.id, doc.service_key.id, doc.registrar_key.id], (kid) => keys.get(kid) ?? null, this.verifyFn);
    if (pr !== null) throw err(pr);
    const now = Math.floor(this.opts.clock());
    const evBody: AuditEvent = {
      v: 1, root: doc.root, seq: "1", prev: ZERO_HASH, time: now,
      root_epoch: "1", kind: "RootCreated", request_hash: D("ROOT", doc),
      objects: [D("ROOT", doc)], invalidated: [], allocated: null, root_state: "active",
    };
    const seed = this.opts.serviceKeys(doc.service_key.id);
    if (!seed) throw err("UNAVAILABLE");
    const ev = this.signEnvelope("EVENT", evBody, seed, doc.service_key.id);
    const head = D("EVENT", evBody);
    this.db.transaction(() => {
      this.db.run(
        "INSERT INTO root_state(singleton,root,epoch,seq,head,state,last_time,allocated_bits,revoked_bits) VALUES(1,?,1,1,?,'active',?,?,?)",
        doc.root, head, now, new Uint8Array(16384), new Uint8Array(16384),
      );
      this.db.run("INSERT INTO root_documents(epoch,hash,canonical) VALUES(1,?,?)", D("ROOT", doc), Buffer.from(canonicalize(genesis as unknown as JsonObject)));
      this.db.run("INSERT INTO events(seq,hash,canonical) VALUES(1,?,?)", head, Buffer.from(canonicalize(ev as unknown as JsonObject)));
      for (const [k, role] of [[doc.control_key, "control"], [doc.service_key, "service"], [doc.registrar_key, "registrar"]] as const) {
        this.db.run("INSERT INTO keys(kid,public_key,role,did,first_seq) VALUES(?,?,?,NULL,1)", k.id, b64uDecode(k.public_key), role);
      }
    });
    this.writeFrontier({ epoch: 1, seq: 1, head, state: "active", last_time: now, allocated_bits: new Uint8Array(0), revoked_bits: new Uint8Array(0) });
    return ev;
  }

  private registerKey(k: PublicKey, role: string, did: string | null, seq: number): void {
    const pub = b64uDecode(k.public_key);
    if (!pub) throw err("ENCODING_INVALID");
    const byKid = this.keyRow(k.id);
    const byBytes = this.keyByBytes(pub);
    if (byKid) {
      // Identical kid must carry identical bytes/role (human key reuse is allowed only then).
      const same = Buffer.from(byKid.public_key).equals(Buffer.from(pub)) && byKid.role === role;
      if (!same) throw err("KEY_REUSED");
      if (role === "human") return; // identical human row may be referenced
      throw err("KEY_REUSED");
    }
    if (byBytes) throw err("KEY_REUSED"); // key bytes cannot occupy multiple roles/aliases
    this.db.run("INSERT INTO keys(kid,public_key,role,did,first_seq) VALUES(?,?,?,?,?)", k.id, pub, role, did, seq);
  }

  private assertProofs<T extends JsonObject>(tag: Parameters<typeof D>[0], env: Signed<T>, signers: PublicKey[]): void {
    const map = new Map<string, Uint8Array | null>();
    for (const k of signers) map.set(k.id, b64uDecode(k.public_key));
    const r = verifyProofSet(tag, env, signers.map((s) => s.id), (kid) => map.get(kid) ?? null, this.verifyFn);
    if (r !== null) throw err(r);
  }

  // ---------- Command submission (§6.1) ----------

  submitCommand(raw: Uint8Array): MutationReply {
    // Step 1: transport size, strict JSON, version, closed schema, scalars.
    const parsed = parseJsonStrict(raw, LIMITS_ORDINARY);
    if (!parsed.ok) throw err(parsed.code);
    const badSchema = validate("Command", parsed.value);
    if (badSchema !== null) throw err(badSchema);
    const cmd = parsed.value as unknown as Signed<Command>;
    const body = cmd.body;
    if (body.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");

    // Step 2: request hash + actor cryptographic proof using retained key bytes.
    const requestHash = D("COMMAND", body);
    const actorRow = this.keyRow(body.actor);
    if (actorRow === null) throw err("SIGNATURE_INVALID");
    if (cmd.proofs.length !== 1 || cmd.proofs[0]!.kid !== body.actor) throw err("SIGNATURE_INVALID");
    const sig = b64uDecode(cmd.proofs[0]!.signature);
    if (sig === null || !this.verifyFn(actorRow.public_key, digestBytes("COMMAND", body), sig))
      throw err("SIGNATURE_INVALID");

    return this.db.transaction(() => this.submitInner(body, cmd, requestHash, raw));
  }

  private submitInner(body: Command, cmd: Signed<Command>, requestHash: string, raw: Uint8Array): MutationReply {
    const st = this.rootState();
    if (st === null) throw err("ROOT_UNKNOWN");

    // Step 3: idempotent replay / conflict under the barrier.
    const tomb = this.db.get("SELECT actor,request_hash,reply_ciphertext FROM operations WHERE op_id=?", body.op_id);
    if (tomb) {
      if (tomb["actor"] !== body.actor || tomb["request_hash"] !== requestHash) throw err("IDEMPOTENCY_CONFLICT");
      const plain = this.opts.dataBox.decrypt(this.opts.root, "operations", body.op_id, new Uint8Array(tomb["reply_ciphertext"] as Uint8Array));
      return JSON.parse(new TextDecoder().decode(plain)) as MutationReply;
    }

    // Step 4: authoritative time and command window.
    const now = this.now();
    if (body.expires_at - body.issued_at > MAX_COMMAND_LIFETIME) throw err("COMMAND_EXPIRED");
    if (body.issued_at > now) throw err("NOT_YET_VALID");
    if (now >= body.expires_at) throw err("COMMAND_EXPIRED");

    // Step 5: root active, subject/root binding, revision, terminal state, actor authority.
    if (st.state === "frozen") throw err("ROOT_FROZEN");
    const action = body.action;

    // Nested root consistency: every enclosed object's root must equal the command root.
    for (const r of this.enclosedRoots(action)) {
      if (r !== body.root) throw err("METHOD_TARGET_INVALID");
    }

    const doc = this.currentDoc();
    const controlKid = doc.body.control_key.id;
    const registrarKid = doc.body.registrar_key.id;

    const isRootAction = action.kind === "root.rotate" || action.kind === "root.freeze";
    let agentRow: AgentRow | null = null;
    if (isRootAction) {
      if (body.subject !== body.root || !isRootId(body.subject)) throw err("NOT_FOUND");
      if (BigInt(body.expected_revision) !== BigInt(st.epoch)) throw err("REVISION_CONFLICT");
    } else {
      if (!isDid(body.subject) || didParts(body.subject)!.root !== body.root) throw err("NOT_FOUND");
      agentRow = this.agent(body.subject);
      if (action.kind === "binding.enroll") {
        if (agentRow !== null) throw err("REVISION_CONFLICT");
        if (BigInt(body.expected_revision) !== 0n) throw err("REVISION_CONFLICT");
      } else {
        if (agentRow === null) throw err("NOT_FOUND");
        if (BigInt(body.expected_revision) !== agentRow.revision) throw err("REVISION_CONFLICT");
        if (agentRow.state === "revoked" && action.kind !== "revoke") throw err("AGENT_REVOKED");
      }
    }

    // Actor authority: registered, current, and in the action's allowed set.
    const actorKey = this.keyRow(body.actor)!;
    this.assertActorAuthority(actorKey, action, body, agentRow, doc);

    // Object proof sets + enclosed-object evaluation (steps 5–6).
    const outcome = this.evaluateAction(body, action, agentRow, doc, now, st);

    // Steps 7–9: build immutable state, sign event+receipt, commit, reply.
    const newSeq = st.seq + 1;
    const evBody: AuditEvent = {
      v: 1, root: body.root, seq: String(newSeq), prev: st.head, time: now,
      root_epoch: String(st.epoch), kind: outcome.kind, request_hash: requestHash,
      objects: [...outcome.objects].sort(), invalidated: [...outcome.invalidated].sort((a, b) => a - b),
      allocated: outcome.allocated, root_state: outcome.rootState,
    };
    const signKid = outcome.signWith ?? doc.body.service_key.id;
    const seed = this.opts.serviceKeys(signKid);
    if (!seed) throw err("UNAVAILABLE");
    const ev = this.signEnvelope("EVENT", evBody, seed, signKid);
    const evHash = D("EVENT", evBody);
    const rcBody: Receipt = {
      v: 1, root: body.root, op_id: body.op_id, request_hash: requestHash,
      seq: String(newSeq), event_hash: evHash, kind: outcome.kind,
      objects: evBody.objects, allocated: outcome.allocated,
    };
    const rc = this.signEnvelope("RECEIPT", rcBody, seed, signKid);

    this.opts.crashHook?.("after_sign");

    const reply: MutationReply = { v: 1, receipt: rc, record: outcome.record };

    // Apply state changes.
    const newAllocated = st.allocated_bits;
    const newRevoked = st.revoked_bits;
    if (outcome.allocated !== null) newAllocated[outcome.allocated >> 3] = (newAllocated[outcome.allocated >> 3]! | (1 << (outcome.allocated % 8)));
    for (const s of outcome.invalidated) newRevoked[s >> 3] = (newRevoked[s >> 3]! | (1 << (s % 8)));

    this.db.run(
      "UPDATE root_state SET epoch=?, seq=?, head=?, state=?, last_time=?, allocated_bits=?, revoked_bits=? WHERE singleton=1",
      outcome.newEpoch ?? st.epoch, newSeq, evHash, outcome.rootState, Math.max(st.last_time, now), newAllocated, newRevoked,
    );
    this.db.run("INSERT INTO events(seq,hash,canonical) VALUES(?,?,?)", newSeq, evHash, Buffer.from(canonicalize(ev as unknown as JsonObject)));

    for (const w of outcome.writes) w();

    const enc = (v: unknown) => this.opts.dataBox.encrypt(this.opts.root, "operations", body.op_id, canonicalize(v as JsonObject));
    this.db.run(
      "INSERT INTO operations(op_id,actor,request_hash,subject,seq,receipt_ciphertext,command_ciphertext,reply_ciphertext) VALUES(?,?,?,?,?,?,?,?)",
      body.op_id, body.actor, requestHash, body.subject, newSeq,
      enc(rc), enc(cmd), enc(reply),
    );

    this.opts.crashHook?.("before_commit");
    return reply;
  }

  private *enclosedRoots(action: Command["action"]): Generator<string> {
    switch (action.kind) {
      case "binding.enroll": yield action.binding.body.root; yield didParts(action.binding.body.did)?.root ?? ""; break;
      case "card.issue": yield action.card.body.root; yield didParts(action.card.body.did)?.root ?? ""; break;
      case "binding.renew":
        yield action.binding.body.root; yield didParts(action.binding.body.did)?.root ?? "";
        yield action.card.body.root; yield didParts(action.card.body.did)?.root ?? ""; break;
      case "card.rotate":
        yield action.rotation.body.root; yield didParts(action.rotation.body.did)?.root ?? "";
        yield action.card.body.root; yield didParts(action.card.body.did)?.root ?? ""; break;
      case "revoke": break;
      case "root.rotate": yield action.document.body.root; break;
      case "root.freeze": break;
    }
  }

  private assertActorAuthority(
    actor: KeyRow, action: Command["action"], body: Command,
    agent: AgentRow | null, doc: Signed<RootDocument>,
  ): void {
    // Retired or revoked keys never hold authority.
    if (actor.retired_seq !== null || actor.revoked_seq !== null) throw err("FORBIDDEN");
    const role = actor.role;
    const isAgentKey = agent !== null && role === "agent" && actor.did === agent.did && agent.current_key.id === actor.kid;
    const isBoundHuman = agent !== null && role === "human" &&
      this.db.get("SELECT 1 FROM principals WHERE did=? AND human_kid=?", agent.did, actor.kid) !== undefined;
    const isRegistrar = role === "registrar" && actor.kid === doc.body.registrar_key.id;
    const isControl = role === "control" && actor.kid === doc.body.control_key.id;

    switch (action.kind) {
      case "binding.enroll": if (!isRegistrar) throw err("FORBIDDEN"); break;
      case "binding.renew": if (!isRegistrar) throw err("FORBIDDEN"); break;
      case "card.issue": case "card.rotate":
        if (!isAgentKey && !isBoundHuman) throw err("FORBIDDEN"); break;
      case "revoke": {
        const t = action.target;
        const ok = t === "binding" ? (isBoundHuman || isRegistrar) : (isAgentKey || isBoundHuman || isRegistrar);
        if (!ok) throw err("FORBIDDEN");
        break;
      }
      case "root.rotate": case "root.freeze":
        if (!isControl) throw err("FORBIDDEN"); break;
    }
  }

  // ---------- Action evaluation (§6.1 step 6) ----------

  private evaluateAction(
    body: Command, action: Command["action"], agent: AgentRow | null,
    doc: Signed<RootDocument>, now: number, st: RootState,
  ): {
    kind: AuditEvent["kind"]; objects: string[]; invalidated: number[];
    allocated: number | null; rootState: "active" | "frozen";
    newEpoch?: number; record: AgentRecord | null; signWith?: string;
    writes: (() => void)[];
  } {
    switch (action.kind) {
      case "binding.enroll": return this.evalEnroll(body, action.binding, doc, now, st);
      case "card.issue": return this.evalIssue(body, action.card, agent!, doc, now, st);
      case "binding.renew": return this.evalRenew(body, action.binding, action.card, agent!, doc, now, st);
      case "card.rotate": return this.evalRotate(body, action.rotation, action.card, agent!, doc, now, st);
      case "revoke": return this.evalRevoke(body, action, agent!, doc, now, st);
      case "root.rotate": return this.evalRootRotate(body, action.document, doc, st);
      case "root.freeze": return this.evalFreeze(body, doc, st);
    }
  }

  private checkObjectTimes(kind: "binding" | "card", o: HumanBinding | AgentCard, now: number): void {
    if (o.issued_at > now) throw err("NOT_YET_VALID");
    if (o.expires_at <= now) throw err("INTERVAL_INVALID");
    if (kind === "binding") {
      const b = o as HumanBinding;
      if (!(b.issued_at < b.expires_at)) throw err("INTERVAL_INVALID");
      if (b.expires_at - b.issued_at > MAX_BINDING_LIFETIME) throw err("INTERVAL_INVALID");
      if (b.issued_at < now - MAX_COMMAND_LIFETIME) throw err("INTERVAL_INVALID");
    } else {
      const c = o as AgentCard;
      if (!(c.issued_at <= c.not_before && c.not_before < c.expires_at)) throw err("INTERVAL_INVALID");
      if (c.not_before !== c.issued_at) throw err("INTERVAL_INVALID"); // v1: no future activation
      if (c.expires_at - c.issued_at > MAX_CARD_LIFETIME) throw err("INTERVAL_INVALID");
    }
  }

  private assertSlotFree(st: RootState, slot: number): void {
    const allocatedCount = countBits(st.allocated_bits);
    if (allocatedCount >= STATUS_SLOTS) throw err("CAPACITY");
    if (((st.allocated_bits[slot >> 3]! >> (slot % 8)) & 1) === 1) throw err("SLOT_USED");
  }

  private assertAgentCapacity(): void {
    const n = this.db.get("SELECT COUNT(*) AS c FROM agents")!["c"] as number;
    if (n >= MAX_AGENTS) throw err("CAPACITY");
  }

  private evalEnroll(body: Command, sb: Signed<HumanBinding>, doc: Signed<RootDocument>, now: number, st: RootState) {
    const b = sb.body;
    // Object proof set: registrar (current epoch) + human + initial agent.
    this.assertProofs("BINDING", sb, [doc.body.registrar_key, b.human_key, b.agent_key]);
    // (a) identifier uniqueness
    if (this.db.get("SELECT 1 FROM principals WHERE id=?", b.principal_id)) throw err("ID_USED");
    if (this.db.get("SELECT 1 FROM bindings WHERE id=?", b.id)) throw err("ID_USED");
    this.registerKeyProbe(b.agent_key, "agent", b.did);
    this.registerKeyProbe(b.human_key, "human", null);
    // (c) epoch link: binding.registrar_epoch == current root epoch.
    if (b.registrar_epoch !== doc.body.epoch) throw err("EPOCH_MISMATCH");
    // (d) cross-links
    if (didParts(b.did)!.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    if (b.did !== body.subject) throw err("BINDING_MISMATCH");
    // (e) times
    this.checkObjectTimes("binding", b, now);
    // (f) quotas
    this.assertAgentCapacity();
    if (countBits(st.allocated_bits) >= STATUS_SLOTS) throw err("CAPACITY");

    const bHash = D("BINDING", b);
    const seq = st.seq + 1;
    const writes: (() => void)[] = [
      () => this.storeObject("BINDING", b.id, b.did, sb as unknown as Signed<JsonObject>),
      () => this.registerKey(b.agent_key, "agent", b.did, seq),
      () => this.registerKey(b.human_key, "human", null, seq),
      () => this.db.run("INSERT INTO agents(did,revision,key_epoch,state,current_key,binding_hash,current_card_hash,last_card_hash,private_record) VALUES(?,1,1,'enrolled',?,?,NULL,NULL,?)",
        b.did, JSON.stringify(b.agent_key), bHash,
        this.opts.dataBox.encrypt(this.opts.root, "agents", b.did, canonicalize({ binding_id: b.id, principal_id: b.principal_id }))),
      () => this.db.run("INSERT INTO bindings(id,did,hash,state,expires_at) VALUES(?,?,?,'current',?)", b.id, b.did, bHash, b.expires_at),
      () => this.db.run("INSERT INTO principals(id,did,human_kid) VALUES(?,?,?)", b.principal_id, b.did, b.human_key.id),
    ];
    const record: AgentRecord = {
      v: 1, root: body.root, did: b.did, revision: "1", key_epoch: "1",
      state: "enrolled", binding_hash: bHash, current_card_hash: null, current_key: b.agent_key,
    };
    return { kind: "BindingEnrolled" as const, objects: [bHash], invalidated: [], allocated: null, rootState: "active" as const, record, writes };
  }

  /** (a) identifier uniqueness for a new card object. */
  private checkCardIds(c: AgentCard): void {
    if (this.db.get("SELECT 1 FROM cards WHERE card_id=?", c.id)) throw err("ID_USED");
    if (this.db.get("SELECT 1 FROM objects WHERE object_id=?", c.id)) throw err("ID_USED");
  }

  /** (b) predecessor: card.previous vs the agent's last card hash. */
  private checkCardPredecessor(c: AgentCard, agent: AgentRow): void {
    if ((c.previous ?? null) !== agent.last_card_hash) throw err("PREDECESSOR_MISMATCH");
  }

  /** (d) cross-links between card, binding, agent, and expected key. */
  private checkCardLinks(
    c: AgentCard, agent: AgentRow, binding: HumanBinding,
    expectedCardKey: PublicKey, bindingHash: string,
  ): void {
    if (c.did !== agent.did) throw err("BINDING_MISMATCH");
    if (didParts(c.did)!.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    if (c.binding_hash !== bindingHash) throw err("BINDING_MISMATCH");
    if (c.human_principal !== binding.principal_id) throw err("BINDING_MISMATCH");
    if (c.key.id !== expectedCardKey.id || c.key.public_key !== expectedCardKey.public_key) throw err("HOLDER_MISMATCH");
    for (const g of c.gateway_bindings) {
      if (g.caller_jkt !== callerJkt(c.key.public_key)) throw err("HOLDER_MISMATCH");
    }
  }

  /** (e) card interval within the binding interval. */
  private checkCardTimes(c: AgentCard, binding: HumanBinding, now: number): void {
    this.checkObjectTimes("card", c, now);
    if (c.expires_at > binding.expires_at || c.not_before < binding.issued_at) throw err("INTERVAL_INVALID");
  }

  private evalIssue(body: Command, sc: Signed<AgentCard>, agent: AgentRow, doc: Signed<RootDocument>, now: number, st: RootState) {
    const c = sc.body;
    const binding = this.currentBinding(agent.did);
    if (binding === null) throw err("STATE_TRANSITION");
    // Proof set: card key + bound human key.
    this.assertProofs("CARD", sc, [c.key, binding.human_key]);
    this.checkCardIds(c);                                  // (a)
    this.checkCardPredecessor(c, agent);                   // (b)
    if (BigInt(c.key_epoch) !== agent.key_epoch) throw err("EPOCH_MISMATCH"); // (c)
    this.checkCardLinks(c, agent, binding, agent.current_key, agent.binding_hash); // (d)
    this.checkCardTimes(c, binding, now);                  // (e)
    this.assertSlotFree(st, c.status_index);               // (f)

    const cHash = D("CARD", c);
    const seq = st.seq + 1;
    const invalidated = this.invalidatedForReplacement(agent, st);
    const writes: (() => void)[] = [
      () => this.storeObject("CARD", c.id, c.did, sc as unknown as Signed<JsonObject>),
      () => this.applyCardReplacement(agent, c, cHash, seq, st),
    ];
    const record = this.recordFor(agent, cHash);
    return { kind: "CardIssued" as const, objects: [cHash], invalidated, allocated: c.status_index, rootState: "active" as const, record, writes };
  }

  private evalRenew(body: Command, sb: Signed<HumanBinding>, sc: Signed<AgentCard>, agent: AgentRow, doc: Signed<RootDocument>, now: number, st: RootState) {
    const b = sb.body;
    const c = sc.body;
    const curBinding = this.currentBinding(agent.did);
    if (curBinding === null) throw err("STATE_TRANSITION");
    // Proof sets: binding = registrar + human + current agent; card = card key + human.
    this.assertProofs("BINDING", sb, [doc.body.registrar_key, b.human_key, b.agent_key]);
    this.assertProofs("CARD", sc, [c.key, b.human_key]);
    // (a) identifier uniqueness
    if (this.db.get("SELECT 1 FROM bindings WHERE id=?", b.id)) throw err("ID_USED");
    if (this.db.get("SELECT 1 FROM principals WHERE id=? AND did<>?", b.principal_id, b.did)) throw err("ID_USED");
    this.checkCardIds(c);
    // (b) predecessors
    if ((b.previous ?? null) !== agent.binding_hash) throw err("PREDECESSOR_MISMATCH");
    this.checkCardPredecessor(c, agent);
    // (c) epoch links
    if (b.registrar_epoch !== doc.body.epoch) throw err("EPOCH_MISMATCH");
    if (BigInt(c.key_epoch) !== agent.key_epoch) throw err("EPOCH_MISMATCH");
    // (d) cross-links: immutable binding fields + renewal attests current key.
    if (b.did !== agent.did || b.root !== this.opts.root || b.principal_id !== curBinding.principal_id ||
        b.human_key.id !== curBinding.human_key.id || b.human_key.public_key !== curBinding.human_key.public_key)
      throw err("BINDING_MISMATCH");
    if (b.agent_key.id !== agent.current_key.id || b.agent_key.public_key !== agent.current_key.public_key)
      throw err("BINDING_MISMATCH");
    // (e) times
    this.checkObjectTimes("binding", b, now);
    const bHash = D("BINDING", b);
    this.checkCardLinks(c, agent, b, agent.current_key, bHash);
    this.checkCardTimes(c, b, now);
    // (f) quotas + slot
    const revs = this.db.get("SELECT COUNT(*) AS c FROM bindings WHERE did=?", b.did)!["c"] as number;
    if (revs >= MAX_BINDING_REVISIONS) throw err("CAPACITY");
    this.assertSlotFree(st, c.status_index);

    const cHash = D("CARD", c);
    const seq = st.seq + 1;
    const invalidated = this.invalidatedForReplacement(agent, st);
    const writes: (() => void)[] = [
      () => this.storeObject("BINDING", b.id, b.did, sb as unknown as Signed<JsonObject>),
      () => this.storeObject("CARD", c.id, c.did, sc as unknown as Signed<JsonObject>),
      () => {
        this.db.run("UPDATE bindings SET state='superseded' WHERE hash=?", agent.binding_hash);
        this.db.run("INSERT INTO bindings(id,did,hash,state,expires_at) VALUES(?,?,?,'current',?)", b.id, b.did, bHash, b.expires_at);
        this.applyCardReplacement(agent, c, cHash, seq, st);
        this.db.run("UPDATE agents SET binding_hash=? WHERE did=?", bHash, b.did);
      },
    ];
    const record = this.recordFor(agent, cHash, { binding_hash: bHash });
    return { kind: "BindingRenewed" as const, objects: [bHash, cHash], invalidated, allocated: c.status_index, rootState: "active" as const, record, writes };
  }

  private evalRotate(body: Command, sr: Signed<Rotation>, sc: Signed<AgentCard>, agent: AgentRow, doc: Signed<RootDocument>, now: number, st: RootState) {
    const r = sr.body;
    const c = sc.body;
    const binding = this.currentBinding(agent.did);
    if (binding === null) throw err("STATE_TRANSITION");
    if (agent.last_card_hash === null) throw err("STATE_TRANSITION"); // no previously issued card
    const priorCard = this.cardByHash(r.old_card_hash);
    // Rotation proof set: old agent key (= the agent's current key) + new agent
    // key + current human; card: new key + human.
    this.assertProofs("ROTATION", sr, [agent.current_key, c.key, binding.human_key]);
    this.assertProofs("CARD", sc, [c.key, binding.human_key]);
    // (a) uniqueness: nonce, card id, key reuse
    if (this.db.get("SELECT 1 FROM objects WHERE object_id=?", r.nonce)) throw err("ID_USED");
    this.checkCardIds(c);
    this.registerKeyProbe(r.new_key, "agent", agent.did);
    // (b) predecessors
    if (r.old_card_hash !== agent.last_card_hash) throw err("PREDECESSOR_MISMATCH");
    if (priorCard === null) throw err("PREDECESSOR_MISMATCH");
    this.checkCardPredecessor(c, agent);
    // (c) epoch links
    if (BigInt(r.from_epoch) !== agent.key_epoch) throw err("EPOCH_MISMATCH");
    if (BigInt(r.to_epoch) !== agent.key_epoch + 1n) throw err("EPOCH_MISMATCH");
    if (BigInt(c.key_epoch) !== agent.key_epoch + 1n) throw err("EPOCH_MISMATCH");
    // (d) cross-links
    if (r.did !== agent.did) throw err("ROTATION_MISMATCH");
    if (didParts(r.did)!.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    if (r.new_key.id !== c.key.id || r.new_key.public_key !== c.key.public_key) throw err("ROTATION_MISMATCH");
    if (r.old_key_id !== priorCard.key.id) throw err("ROTATION_MISMATCH");
    if (r.new_card_hash !== D("CARD", c)) throw err("ROTATION_MISMATCH");
    this.checkCardLinks(c, agent, binding, r.new_key, agent.binding_hash);
    // (e) rotation window + card times
    if (r.issued_at > now) throw err("COMMAND_EXPIRED");
    if (now >= r.expires_at || r.expires_at - r.issued_at > MAX_COMMAND_LIFETIME) throw err("COMMAND_EXPIRED");
    this.checkCardTimes(c, binding, now);
    // (f) quotas + slot: agent key epoch never wraps past 256.
    if (agent.key_epoch + 1n > BigInt(MAX_KEY_EPOCHS)) throw err("CAPACITY");
    this.assertSlotFree(st, c.status_index);

    const cHash = D("CARD", c);
    const seq = st.seq + 1;
    const invalidated = this.invalidatedForReplacement(agent, st);
    const writes: (() => void)[] = [
      () => this.storeObject("ROTATION", r.nonce, r.did, sr as unknown as Signed<JsonObject>),
      () => this.storeObject("CARD", c.id, c.did, sc as unknown as Signed<JsonObject>),
      () => {
        this.registerKey(r.new_key, "agent", agent.did, seq);
        this.db.run("UPDATE keys SET retired_seq=? WHERE kid=?", seq, priorCard.key.id);
        this.applyCardReplacement(agent, c, cHash, seq, st);
        this.db.run("UPDATE agents SET key_epoch=?, current_key=? WHERE did=?", Number(agent.key_epoch + 1n), JSON.stringify(r.new_key), agent.did);
      },
    ];
    const record = this.recordFor(agent, cHash, { key_epoch: String(agent.key_epoch + 1n), current_key: r.new_key });
    return { kind: "CardRotated" as const, objects: [cHash, D("ROTATION", r)], invalidated, allocated: c.status_index, rootState: "active" as const, record, writes };
  }

  private evalRevoke(body: Command, action: Extract<Command["action"], { kind: "revoke" }>, agent: AgentRow, doc: Signed<RootDocument>, now: number, st: RootState) {
    // Target type form and ownership.
    const did = agent.did;
    if (action.target === "agent" && !isDid(action.id)) throw err("ID_INVALID");
    if (action.target === "binding" && !isBindingId(action.id)) throw err("ID_INVALID");
    if (action.target === "card" && !isCardId(action.id)) throw err("ID_INVALID");

    const seq = st.seq + 1;
    const newRevokedPreview = st.revoked_bits;
    void newRevokedPreview;

    if (action.target === "agent") {
      if (action.id !== did) throw err("NOT_FOUND");
      if (agent.state === "revoked") throw err("ALREADY_REVOKED");
      const invalidated = this.currentSlotBits(agent, st);
      const writes = [() => this.applyAgentRevoked(agent, seq)];
      return { kind: "AgentRevoked" as const, objects: [] as string[], invalidated, allocated: null, rootState: "active" as const, record: this.recordFor(agent, null, { state: "revoked" }), writes };
    }
    if (action.target === "binding") {
      const row = this.db.get("SELECT * FROM bindings WHERE id=? AND did=?", action.id, did);
      if (!row) throw err("NOT_FOUND");
      if (row["state"] === "revoked") throw err("ALREADY_REVOKED");
      if (row["state"] === "superseded") throw err("STATE_TRANSITION");
      const invalidated = this.currentSlotBits(agent, st);
      const writes = [() => {
        this.db.run("UPDATE bindings SET state='revoked' WHERE id=?", action.id);
        this.applyAgentRevoked(agent, seq);
      }];
      return { kind: "BindingRevoked" as const, objects: [] as string[], invalidated, allocated: null, rootState: "active" as const, record: this.recordFor(agent, null, { state: "revoked" }), writes };
    }
    // card
    const card = this.db.get("SELECT * FROM cards WHERE card_id=? AND did=?", action.id, did);
    if (!card) throw err("NOT_FOUND");
    const cardState = card["state"] as string;
    const cardSlot = Number(card["slot"]);
    if (action.reason === "COMPROMISE") {
      // Atomic escalation: agent revoked; target slot + current slot invalidated.
      if (agent.state === "revoked") throw err("ALREADY_REVOKED");
      const inv = new Set<number>(this.currentSlotBits(agent, st));
      inv.add(cardSlot);
      const invalidated = [...inv].filter((s) => ((st.revoked_bits[s >> 3]! >> (s % 8)) & 1) === 0);
      const writes = [() => {
        this.db.run("UPDATE cards SET state='revoked' WHERE card_id=?", action.id);
        this.applyAgentRevoked(agent, seq);
      }];
      return { kind: "AgentRevoked" as const, objects: [] as string[], invalidated, allocated: null, rootState: "active" as const, record: this.recordFor(agent, null, { state: "revoked" }), writes };
    }
    if (cardState === "revoked") throw err("ALREADY_REVOKED");
    const isCurrent = agent.current_card_hash === (card["hash"] as string);
    const invalidated = ((st.revoked_bits[cardSlot >> 3]! >> (cardSlot % 8)) & 1) === 0 ? [cardSlot] : [];
    const writes = [() => {
      this.db.run("UPDATE cards SET state='revoked' WHERE card_id=?", action.id);
      if (isCurrent) this.db.run("UPDATE agents SET current_card_hash=NULL, state='enrolled' WHERE did=?", did);
    }];
    const newState = (isCurrent ? "enrolled" : agent.state) as "enrolled" | "active" | "revoked";
    return { kind: "CardRevoked" as const, objects: [] as string[], invalidated, allocated: null, rootState: "active" as const, record: this.recordFor(agent, isCurrent ? null : agent.current_card_hash, { state: newState }), writes };
  }

  private evalRootRotate(body: Command, sd: Signed<RootDocument>, doc: Signed<RootDocument>, st: RootState) {
    const d = sd.body;
    // Proof set: control + old service + new service + new registrar (deduped).
    this.assertProofs("ROOT", sd, [doc.body.control_key, doc.body.service_key, d.service_key, d.registrar_key]);
    // (a) new key material must not alias other roles; key IDs may not repeat
    // with different bytes.
    this.registerKeyProbe(d.service_key, "service", null);
    if (d.registrar_key.id !== doc.body.registrar_key.id) {
      this.registerKeyProbe(d.registrar_key, "registrar", null);
    } else {
      const pub = b64uDecode(d.registrar_key.public_key)!;
      const existing = this.keyRow(d.registrar_key.id)!;
      if (!Buffer.from(existing.public_key).equals(Buffer.from(pub)) || existing.role !== "registrar") throw err("KEY_REUSED");
    }
    // (b) predecessors: previous document hash + cutover pins the current head.
    if (d.previous !== D("ROOT", doc.body)) throw err("PREDECESSOR_MISMATCH");
    if (d.cutover === null || BigInt(d.cutover.seq) !== BigInt(st.seq) || d.cutover.log_hash !== st.head)
      throw err("PREDECESSOR_MISMATCH");
    // (c) epoch link.
    if (BigInt(d.epoch) !== BigInt(st.epoch) + 1n) throw err("EPOCH_MISMATCH");
    // (d) cross-links: same root/control/slot geometry.
    if (d.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    if (d.control_key.id !== doc.body.control_key.id || d.control_key.public_key !== doc.body.control_key.public_key)
      throw err("BINDING_MISMATCH");
    if (d.status_slots !== 131072) throw err("SCHEMA_INVALID");
    // (f) root epoch never wraps past 64.
    if (BigInt(d.epoch) > 64n) throw err("CAPACITY");

    const seq = st.seq + 1;
    const writes: (() => void)[] = [
      () => {
        this.db.run("INSERT INTO root_documents(epoch,hash,canonical) VALUES(?,?,?)", Number(d.epoch), D("ROOT", d), Buffer.from(canonicalize(sd as unknown as JsonObject)));
        this.db.run("UPDATE keys SET retired_seq=? WHERE kid=?", seq, doc.body.service_key.id);
        this.registerKey(d.service_key, "service", null, seq);
        if (d.registrar_key.id !== doc.body.registrar_key.id) {
          this.db.run("UPDATE keys SET retired_seq=? WHERE kid=?", seq, doc.body.registrar_key.id);
          this.registerKey(d.registrar_key, "registrar", null, seq);
        }
      },
    ];
    // The RootRotated event and its receipt are signed by the PRE-cutover
    // service key under the pre-rotation epoch (spec §4, §7).
    return {
      kind: "RootRotated" as const, objects: [D("ROOT", d)], invalidated: [], allocated: null,
      rootState: "active" as const, newEpoch: Number(d.epoch), record: null,
      signWith: doc.body.service_key.id, writes,
    };
  }

  private evalFreeze(body: Command, doc: Signed<RootDocument>, st: RootState) {
    return {
      kind: "RootFrozen" as const, objects: [] as string[], invalidated: [], allocated: null,
      rootState: "frozen" as const, record: null, writes: [] as (() => void)[],
    };
  }

  // ---------- helpers ----------

  private currentBinding(did: string): HumanBinding | null {
    const row = this.db.get("SELECT hash FROM bindings WHERE did=? AND state='current'", did);
    if (!row) return null;
    const obj = this.loadObject(row["hash"] as string, "BINDING");
    return obj ? (obj.body as unknown as HumanBinding) : null;
  }

  private cardByHash(hash: string): AgentCard | null {
    const row = this.db.get("SELECT object_id FROM objects WHERE hash=? AND kind='CARD'", hash);
    if (!row) return null;
    const obj = this.loadObject(hash, "CARD");
    return obj ? (obj.body as unknown as AgentCard) : null;
  }

  private invalidatedForReplacement(agent: AgentRow, st: RootState): number[] {
    return this.currentSlotBits(agent, st);
  }

  /** Slots of the agent's current card whose revoked bit is still 0. */
  private currentSlotBits(agent: AgentRow, st: RootState): number[] {
    if (agent.current_card_hash === null) return [];
    const row = this.db.get("SELECT slot FROM cards WHERE hash=?", agent.current_card_hash);
    if (!row) return [];
    const slot = Number(row["slot"]);
    return ((st.revoked_bits[slot >> 3]! >> (slot % 8)) & 1) === 0 ? [slot] : [];
  }

  private applyCardReplacement(agent: AgentRow, c: AgentCard, cHash: string, seq: number, st: RootState): void {
    if (agent.current_card_hash !== null) {
      this.db.run("UPDATE cards SET state='superseded' WHERE hash=? AND state='current'", agent.current_card_hash);
    }
    this.db.run(
      "INSERT INTO cards(card_id,did,hash,slot,issuance_seq,expires_at,state) VALUES(?,?,?,?,?,?,'current')",
      c.id, agent.did, cHash, c.status_index, seq, c.expires_at,
    );
    this.db.run(
      "UPDATE agents SET revision=revision+1, current_card_hash=?, last_card_hash=?, state='active' WHERE did=?",
      cHash, cHash, agent.did,
    );
  }

  private applyAgentRevoked(agent: AgentRow, seq: number): void {
    this.db.run("UPDATE agents SET state='revoked', current_card_hash=NULL, revision=revision+1 WHERE did=?", agent.did);
    this.db.run("UPDATE cards SET state='revoked' WHERE did=? AND state='current'", agent.did);
    this.db.run("UPDATE bindings SET state='revoked' WHERE did=? AND state='current'", agent.did);
    this.db.run("UPDATE keys SET revoked_seq=? WHERE did=? AND role='agent' AND revoked_seq IS NULL", seq, agent.did);
    // Principal rows are permanent (identifiers are never reassigned); the bound
    // human key loses read/command authority through the revoked agent state.
  }

  private recordFor(agent: AgentRow, currentCardHash: string | null, over: Partial<AgentRecord> = {}): AgentRecord {
    return {
      v: 1, root: this.opts.root, did: agent.did,
      revision: String(agent.revision + 1n),
      key_epoch: String(agent.key_epoch),
      state: "active",
      binding_hash: agent.binding_hash,
      current_card_hash: currentCardHash,
      current_key: agent.current_key,
      ...over,
    };
  }

  private registerKeyProbe(k: PublicKey, role: string, did: string | null): void {
    const pub = b64uDecode(k.public_key)!;
    const byKid = this.keyRow(k.id);
    const byBytes = this.keyByBytes(pub);
    if (byKid) {
      const same = Buffer.from(byKid.public_key).equals(Buffer.from(pub)) && byKid.role === role;
      if (!same) throw err("KEY_REUSED");
      if (role !== "human") throw err("KEY_REUSED");
    }
    if (byBytes && byBytes.kid !== k.id) throw err("KEY_REUSED");
    if (byBytes && byBytes.kid === k.id && role !== "human") throw err("KEY_REUSED");
  }

  // ---------- Queries (§5) ----------

  submitQuery(raw: Uint8Array): JsonValue {
    const parsed = parseJsonStrict(raw, LIMITS_ORDINARY);
    if (!parsed.ok) throw err(parsed.code);
    const badSchema = validate("Query", parsed.value);
    if (badSchema !== null) throw err(badSchema);
    const q = parsed.value as unknown as Signed<Query>;
    const body = q.body;
    if (body.root !== this.opts.root) throw err("METHOD_TARGET_INVALID");
    const qk = body.query;
    const nestedDid = qk.kind === "resolve" || qk.kind === "export" ? qk.did : null;
    if (nestedDid !== null && didParts(nestedDid)!.root !== body.root) throw err("METHOD_TARGET_INVALID");
    // Actor cryptographic proof against retained key bytes.
    const actorRow = this.keyRow(body.actor);
    if (actorRow === null) throw err("SIGNATURE_INVALID");
    if (q.proofs.length !== 1 || q.proofs[0]!.kid !== body.actor) throw err("SIGNATURE_INVALID");
    const sig = b64uDecode(q.proofs[0]!.signature);
    if (sig === null || !this.verifyFn(actorRow.public_key, digestBytes("QUERY", body), sig))
      throw err("SIGNATURE_INVALID");
    // Query window.
    const now = this.now();
    if (BigInt(body.expires_at) - BigInt(body.issued_at) > BigInt(MAX_QUERY_LIFETIME)) throw err("QUERY_EXPIRED");
    if (body.issued_at > now) throw err("QUERY_EXPIRED");
    if (now >= body.expires_at) throw err("QUERY_EXPIRED");

    switch (qk.kind) {
      case "resolve": return this.queryResolve(qk.did, qk.card_id, actorRow);
      case "receipt": return this.queryReceipt(qk.op_id, actorRow);
      case "export": return this.queryExport(qk.did, qk.after_revision, qk.limit, actorRow);
    }
  }

  /** Read authority: current agent key, bound human (non-revoked), or registrar. */
  private canReadDid(actor: KeyRow, did: string): boolean {
    const agent = this.agent(did);
    if (agent === null) return false;
    const doc = this.currentDoc();
    if (actor.role === "registrar" && actor.kid === doc.body.registrar_key.id) return true;
    if (actor.retired_seq !== null || actor.revoked_seq !== null) return false;
    if (agent.state === "revoked") return false; // registrar handled above
    if (actor.role === "agent" && actor.did === did && agent.current_key.id === actor.kid) return true;
    if (actor.role === "human") {
      return this.db.get("SELECT 1 FROM principals WHERE did=? AND human_kid=?", did, actor.kid) !== undefined;
    }
    return false;
  }

  private rootsArray(): Signed<RootDocument>[] {
    const st = this.rootState()!;
    const out: Signed<RootDocument>[] = [];
    for (let e = 1; e <= st.epoch; e++) out.push(this.rootDoc(e)!);
    return out;
  }

  private bundleFor(agent: AgentRow, cardHash: string | null): IdentityBundle | null {
    if (cardHash === null) return null;
    const card = this.db.get("SELECT * FROM cards WHERE hash=?", cardHash);
    if (!card) return null;
    const cardObj = this.loadObject(cardHash, "CARD")! as unknown as Signed<AgentCard>;
    const bindingObj = this.loadObject(cardObj.body.binding_hash, "BINDING") as unknown as Signed<HumanBinding> | null;
    if (bindingObj === null) return null;
    const op = this.db.get("SELECT op_id, receipt_ciphertext FROM operations WHERE seq=?", Number(card["issuance_seq"]));
    if (!op) return null;
    const rcPlain = this.opts.dataBox.decrypt(this.opts.root, "operations", op["op_id"] as string, new Uint8Array(op["receipt_ciphertext"] as Uint8Array));
    const receipt = JSON.parse(new TextDecoder().decode(rcPlain)) as Signed<Receipt>;
    let priorCard: Signed<AgentCard> | null = null;
    let rotation: Signed<Rotation> | null = null;
    if (receipt.body.kind === "CardRotated") {
      const priorHash = cardObj.body.previous;
      if (priorHash) priorCard = this.loadObject(priorHash, "CARD") as unknown as Signed<AgentCard>;
      const ev = this.db.get("SELECT canonical FROM events WHERE seq=?", Number(card["issuance_seq"]));
      if (ev) {
        const evObj = JSON.parse(new TextDecoder().decode(ev["canonical"] as Uint8Array)) as Signed<AuditEvent>;
        const rotHash = evObj.body.objects.find((h: string) => h !== cardHash && h !== cardObj.body.binding_hash);
        if (rotHash) rotation = this.loadObject(rotHash, "ROTATION") as unknown as Signed<Rotation>;
      }
    }
    return {
      v: 1, roots: this.rootsArray(), binding: bindingObj, card: cardObj,
      receipt, prior_card: priorCard, rotation,
    };
  }

  private agentRecord(agent: AgentRow): AgentRecord {
    return {
      v: 1, root: this.opts.root, did: agent.did, revision: String(agent.revision),
      key_epoch: String(agent.key_epoch), state: agent.state as AgentRecord["state"],
      binding_hash: agent.binding_hash, current_card_hash: agent.current_card_hash,
      current_key: agent.current_key,
    };
  }

  private queryResolve(did: string, cardId: string | null, actor: KeyRow): ResolveReply {
    const agent = this.agent(did);
    if (agent === null || !this.canReadDid(actor, did)) throw err("NOT_FOUND");
    if (cardId === null) {
      return { v: 1, record: this.agentRecord(agent), bundle: this.bundleFor(agent, agent.current_card_hash) };
    }
    const card = this.db.get("SELECT * FROM cards WHERE card_id=? AND did=?", cardId, did);
    if (!card) throw err("NOT_FOUND");
    const bundle = this.bundleFor(agent, card["hash"] as string);
    return { v: 1, record: this.agentRecord(agent), bundle };
  }

  /** True while the key still holds its original authority. */
  private actorStillAuthorized(actor: KeyRow): boolean {
    if (actor.retired_seq !== null || actor.revoked_seq !== null) return false;
    const doc = this.currentDoc();
    if (actor.role === "control") return actor.kid === doc.body.control_key.id;
    if (actor.role === "registrar") return actor.kid === doc.body.registrar_key.id;
    if (actor.role === "agent" && actor.did !== null) {
      const agent = this.agent(actor.did);
      return agent !== null && agent.state !== "revoked" && agent.current_key.id === actor.kid;
    }
    if (actor.role === "human") {
      const row = this.db.get("SELECT did FROM principals WHERE human_kid=?", actor.kid);
      if (!row) return false;
      const agent = this.agent(row["did"] as string);
      return agent !== null && agent.state !== "revoked";
    }
    return false;
  }

  private queryReceipt(opId: string, actor: KeyRow): Signed<Receipt> {
    const op = this.db.get("SELECT * FROM operations WHERE op_id=?", opId);
    if (!op) throw err("NOT_FOUND");
    const subject = op["subject"] as string;
    const doc = this.currentDoc();
    // Allowed: the op's still-authorized actor, a bound human of a non-revoked
    // subject, or the current registrar.
    let ok = actor.role === "registrar" && actor.kid === doc.body.registrar_key.id;
    if (!ok && actor.kid === (op["actor"] as string) && this.actorStillAuthorized(actor)) ok = true;
    if (!ok && actor.role === "human" && isDid(subject)) {
      const agent = this.agent(subject);
      ok = agent !== null && agent.state !== "revoked" &&
        this.db.get("SELECT 1 FROM principals WHERE did=? AND human_kid=?", subject, actor.kid) !== undefined;
    }
    if (!ok) throw err("NOT_FOUND");
    const plain = this.opts.dataBox.decrypt(this.opts.root, "operations", opId, new Uint8Array(op["receipt_ciphertext"] as Uint8Array));
    return JSON.parse(new TextDecoder().decode(plain)) as Signed<Receipt>;
  }

  private queryExport(did: string, afterRevision: string, limit: number, actor: KeyRow): ExportReply {
    if (!this.canReadDid(actor, did)) throw err("NOT_FOUND");
    const ops = this.db.all(
      "SELECT op_id, command_ciphertext, receipt_ciphertext FROM operations WHERE subject=? ORDER BY seq ASC", did,
    );
    const records: ExportReply["records"] = [];
    let rev = 0;
    for (const op of ops) {
      rev++;
      if (BigInt(rev) <= BigInt(afterRevision)) continue;
      if (records.length >= limit) break;
      const dec = (col: string) => JSON.parse(new TextDecoder().decode(
        this.opts.dataBox.decrypt(this.opts.root, "operations", op["op_id"] as string, new Uint8Array(op[col] as Uint8Array)),
      ));
      records.push({ revision: String(rev), command: dec("command_ciphertext"), receipt: dec("receipt_ciphertext") });
    }
    return { v: 1, records, next_revision: records.length === 0 ? null : (rev >= ops.length ? null : records[records.length - 1]!.revision) };
  }

  // ---------- Status / freshness / public reads ----------

  getStatus(now?: number): Signed<Status> {
    const st = this.rootState();
    if (st === null) throw err("ROOT_UNKNOWN");
    const t = now ?? this.now();
    const svc = this.currentServiceKey();
    const body: Status = {
      v: 1, root: this.opts.root, root_epoch: String(st.epoch), seq: String(st.seq),
      log_hash: st.head, state: st.state, issued_at: t, expires_at: t + 60,
      slots: STATUS_SLOTS as 131072, bits: b64uEncode(st.revoked_bits),
    };
    // Persist clock-safety metadata: last_time advances on issued status.
    if (t > st.last_time) {
      this.db.run("UPDATE root_state SET last_time=? WHERE singleton=1", t);
    }
    return this.signEnvelope("STATUS", body, svc.seed, svc.kid);
  }

  postFreshness(challenge: string): FreshReply {
    const t = this.now();
    const status = this.getStatus(t);
    const svc = this.currentServiceKey();
    const st = this.rootState()!;
    const fBody: Fresh = {
      v: 1, root: this.opts.root, challenge, status_hash: D("STATUS", status.body),
      seq: String(st.seq), log_hash: st.head, checked_at: status.body.issued_at,
      valid_until: status.body.issued_at + 5,
    };
    return { v: 1, fresh: this.signEnvelope("FRESH", fBody, svc.seed, svc.kid), status };
  }

  getEvents(after: bigint, limit: number): LogPage {
    const rows = this.db.all("SELECT seq, canonical FROM events WHERE seq>? ORDER BY seq ASC LIMIT ?", Number(after), limit);
    const events = rows.map((r) => JSON.parse(new TextDecoder().decode(r["canonical"] as Uint8Array)) as Signed<AuditEvent>);
    return { v: 1, events, next_after: events.length === limit ? String(rows[rows.length - 1]!["seq"]) : null };
  }

  getDocument(): Signed<RootDocument> {
    return this.currentDoc();
  }

  getDocuments(after: bigint, limit: number): RootHistoryReply {
    const rows = this.db.all("SELECT epoch, canonical FROM root_documents WHERE epoch>? ORDER BY epoch ASC LIMIT ?", Number(after), limit);
    const docs = rows.map((r) => JSON.parse(new TextDecoder().decode(r["canonical"] as Uint8Array)) as Signed<RootDocument>);
    return { v: 1, documents: docs, next_after: docs.length === limit ? String(rows[rows.length - 1]!["epoch"]) : null };
  }

  /** Readiness probe (§8, §14): storage, head integrity, frontier continuity, capacity. */
  readiness(): { status: "ready" | "not_ready"; code: string } {
    try {
      const st = this.rootState();
      if (st === null) return { status: "not_ready", code: "UNAVAILABLE" };
      // Head integrity: stored head must equal the last event's hash.
      const last = this.db.get("SELECT hash FROM events WHERE seq=?", st.seq);
      if (!last || (last["hash"] as string) !== st.head) return { status: "not_ready", code: "INTEGRITY_FAILURE" };
      // Acknowledged-frontier continuity: DB head must not lag the retained frontier.
      const f = this.opts.frontier?.load();
      if (f && (BigInt(st.seq) < BigInt(f.seq) || (BigInt(st.seq) === BigInt(f.seq) && st.head !== f.log_hash)))
        return { status: "not_ready", code: "INTEGRITY_FAILURE" };
      return { status: "ready", code: "OK" };
    } catch {
      return { status: "not_ready", code: "STORAGE_BUSY" };
    }
  }

  /** Metrics gauges (§14). */
  gauges(): { committed_events: number; allocated_slots: number; live_agents: number } {
    const st = this.rootState();
    if (st === null) return { committed_events: 0, allocated_slots: 0, live_agents: 0 };
    const live = this.db.get("SELECT COUNT(*) AS c FROM agents WHERE state<>'revoked'")!["c"] as number;
    return { committed_events: st.seq, allocated_slots: countBits(st.allocated_bits), live_agents: live };
  }
}

export function countBits(bits: Uint8Array): number {
  let n = 0;
  for (const b of bits) {
    let x = b;
    while (x) { n += x & 1; x >>= 1; }
  }
  return n;
}
