/** Wire-level TypeScript types mirroring spec §3–§10. */

import type { JsonObject } from "./json.ts";

export type Counter = string;
export type Seconds = number;
export type Hash = string;
export type B64u = string;
export type RootId = string;
export type AgentId = string;
export type CardId = string;
export type PrincipalId = string;
export type BindingId = string;
export type KeyId = string;
export type OpId = string;
export type Nonce = string;
export type Did = string;

export interface PublicKey extends JsonObject {
  id: KeyId;
  public_key: B64u;
}
export interface Proof extends JsonObject {
  kid: KeyId;
  signature: B64u;
}
export interface Signed<T extends JsonObject> extends JsonObject {
  body: T;
  proofs: Proof[];
}

export interface RootDocument extends JsonObject {
  v: 1;
  root: RootId;
  epoch: Counter;
  previous: Hash | null;
  control_key: PublicKey;
  service_key: PublicKey;
  registrar_key: PublicKey;
  origin: string;
  created_at: Seconds;
  status_slots: 131072;
  cutover: { seq: Counter; log_hash: Hash } | null;
}

export interface HumanBinding extends JsonObject {
  v: 1;
  id: BindingId;
  root: RootId;
  did: Did;
  principal_id: PrincipalId;
  previous: Hash | null;
  human_key: PublicKey;
  agent_key: PublicKey;
  registrar_epoch: Counter;
  assurance: "operator-attested";
  consent: "agent-accountability-v1";
  issued_at: Seconds;
  expires_at: Seconds;
}

export interface GatewayBinding extends JsonObject {
  gateway: string;
  tenant_id: string;
  sub: string;
  caller_jkt: B64u;
}

export interface BindingEnrollAction extends JsonObject {
  kind: "binding.enroll";
  binding: Signed<HumanBinding>;
}
export interface CardIssueAction extends JsonObject {
  kind: "card.issue";
  card: Signed<AgentCard>;
}
export interface BindingRenewAction extends JsonObject {
  kind: "binding.renew";
  binding: Signed<HumanBinding>;
  card: Signed<AgentCard>;
}
export interface CardRotateAction extends JsonObject {
  kind: "card.rotate";
  rotation: Signed<Rotation>;
  card: Signed<AgentCard>;
}
export interface RevokeAction extends JsonObject {
  kind: "revoke";
  target: "agent" | "binding" | "card";
  id: string;
  reason: RevokeReason;
}
export interface RootRotateAction extends JsonObject {
  kind: "root.rotate";
  document: Signed<RootDocument>;
}
export interface RootFreezeAction extends JsonObject {
  kind: "root.freeze";
  reason: "COMPROMISE" | "ADMINISTRATIVE";
}

export interface AgentCard extends JsonObject {
  v: 1;
  id: CardId;
  root: RootId;
  did: Did;
  previous: Hash | null;
  key: PublicKey;
  key_epoch: Counter;
  human_principal: PrincipalId;
  binding_hash: Hash;
  capabilities_hash: Hash;
  gateway_bindings: GatewayBinding[];
  issued_at: Seconds;
  not_before: Seconds;
  expires_at: Seconds;
  status_index: number;
}

export interface Capabilities extends JsonObject {
  v: 1;
  capabilities: string[];
}

export interface Rotation extends JsonObject {
  v: 1;
  root: RootId;
  did: Did;
  from_epoch: Counter;
  to_epoch: Counter;
  old_card_hash: Hash;
  new_card_hash: Hash;
  old_key_id: KeyId;
  new_key: PublicKey;
  issued_at: Seconds;
  expires_at: Seconds;
  nonce: Nonce;
}

export type CommandAction =
  | BindingEnrollAction
  | CardIssueAction
  | BindingRenewAction
  | CardRotateAction
  | RevokeAction
  | RootRotateAction
  | RootFreezeAction;

export type RevokeReason = "COMPROMISE" | "WITHDRAWN" | "RETIRED" | "ADMINISTRATIVE";

export interface Command extends JsonObject {
  v: 1;
  root: RootId;
  op_id: OpId;
  actor: KeyId;
  subject: Did | RootId;
  expected_revision: Counter;
  issued_at: Seconds;
  expires_at: Seconds;
  action: CommandAction;
}

export interface ResolveQuery extends JsonObject {
  kind: "resolve";
  did: Did;
  card_id: CardId | null;
}
export interface ReceiptQuery extends JsonObject {
  kind: "receipt";
  op_id: OpId;
}
export interface ExportQuery extends JsonObject {
  kind: "export";
  did: Did;
  after_revision: Counter;
  limit: number;
}
export type QueryKind = ResolveQuery | ReceiptQuery | ExportQuery;

export interface Query extends JsonObject {
  v: 1;
  root: RootId;
  query_id: string;
  actor: KeyId;
  issued_at: Seconds;
  expires_at: Seconds;
  query: QueryKind;
}

export interface AgentRecord extends JsonObject {
  v: 1;
  root: RootId;
  did: Did;
  revision: Counter;
  key_epoch: Counter;
  state: "enrolled" | "active" | "revoked";
  binding_hash: Hash;
  current_card_hash: Hash | null;
  current_key: PublicKey;
}

export type EventKind =
  | "RootCreated" | "RootRotated" | "RootFrozen" | "BindingEnrolled"
  | "BindingRenewed" | "CardIssued" | "CardRotated" | "CardRevoked"
  | "AgentRevoked" | "BindingRevoked";

export interface AuditEvent extends JsonObject {
  v: 1;
  root: RootId;
  seq: Counter;
  prev: Hash;
  time: Seconds;
  root_epoch: Counter;
  kind: EventKind;
  request_hash: Hash;
  objects: Hash[];
  invalidated: number[];
  allocated: number | null;
  root_state: "active" | "frozen";
}

export interface Receipt extends JsonObject {
  v: 1;
  root: RootId;
  op_id: OpId;
  request_hash: Hash;
  seq: Counter;
  event_hash: Hash;
  kind: EventKind;
  objects: Hash[];
  allocated: number | null;
}

export interface IdentityBundle extends JsonObject {
  v: 1;
  roots: Signed<RootDocument>[];
  binding: Signed<HumanBinding>;
  card: Signed<AgentCard>;
  receipt: Signed<Receipt>;
  prior_card: Signed<AgentCard> | null;
  rotation: Signed<Rotation> | null;
}

export interface Status extends JsonObject {
  v: 1;
  root: RootId;
  root_epoch: Counter;
  seq: Counter;
  log_hash: Hash;
  state: "active" | "frozen";
  issued_at: Seconds;
  expires_at: Seconds;
  slots: 131072;
  bits: B64u;
}

export interface FreshRequest extends JsonObject {
  v: 1;
  challenge: Nonce;
}

export interface Fresh extends JsonObject {
  v: 1;
  root: RootId;
  challenge: Nonce;
  status_hash: Hash;
  seq: Counter;
  log_hash: Hash;
  checked_at: Seconds;
  valid_until: Seconds;
}

export interface FreshReply extends JsonObject {
  v: 1;
  fresh: Signed<Fresh>;
  status: Signed<Status>;
}

export interface MutationReply extends JsonObject {
  v: 1;
  receipt: Signed<Receipt>;
  record: AgentRecord | null;
}

export interface ResolveReply extends JsonObject {
  v: 1;
  record: AgentRecord;
  bundle: IdentityBundle | null;
}

export interface ExportRecord extends JsonObject {
  revision: Counter;
  command: Signed<Command>;
  receipt: Signed<Receipt>;
}

export interface ExportReply extends JsonObject {
  v: 1;
  records: ExportRecord[];
  next_revision: Counter | null;
}

export interface LogPage extends JsonObject {
  v: 1;
  events: Signed<AuditEvent>[];
  next_after: Counter | null;
}

export interface RootHistoryReply extends JsonObject {
  v: 1;
  documents: Signed<RootDocument>[];
  next_after: Counter | null;
}

export interface Frontier extends JsonObject {
  root: RootId;
  seq: Counter;
  log_hash: Hash;
  root_epoch: Counter;
}

export interface RootPin extends JsonObject {
  root: RootId;
  control_fingerprint: Hash;
  genesis_hash: Hash;
  origin: string;
  enabled: boolean;
  min_epoch: Counter;
}

export interface ClientConfig extends JsonObject {
  v: 1;
  mode: "production" | "development";
  roots: RootPin[];
  cache_dir: string;
  key_refs: { kid: KeyId; path: string }[];
  clock_max_error_s: 2;
  read_max_age_s: 60;
  fresh_max_age_s: 5;
}

export interface ServerConfig extends JsonObject {
  v: 1;
  root: RootId;
  root_document_path: string;
  service_secret_binding: string;
  private_data_key_binding: string;
  root_do_binding: string;
  production: boolean;
  max_agents: 8192;
  status_slots: 131072;
  public_get_per_minute: 120;
  public_fresh_per_minute: 120;
  write_per_actor_per_minute: 30;
  revocation_reserve_per_minute: 60;
}

export interface KeyFile extends JsonObject {
  v: 1;
  kid: KeyId;
  algorithm: "Ed25519";
  seed_b64u: B64u;
}

export interface VerifyInput {
  bundle: IdentityBundle;
  status: Signed<Status>;
  fresh: Signed<Fresh> | null;
  challenge: Nonce | null;
  now: Seconds;
  mode: "fresh" | "bounded_cache";
}

export interface TrustContext {
  pins: RootPin[];
  frontiers: Frontier[];
  known_revocations: { root: RootId; bits: B64u }[];
  received_age_s: number;
  challenge_outstanding: Nonce | null;
  challenge_consumed: boolean;
  /** Managed by the wrapper (verifyWithContext); informational in pure verify. */
  cache_state?: "EMPTY" | "USABLE" | "STALE" | "FORKED" | "DISABLED";
}

export type VerifyResult =
  | {
      v: 1;
      decision: "allow";
      code: "ACTIVE";
      did: Did;
      card_hash: Hash;
      principal_id: PrincipalId;
      key_epoch: Counter;
      root: RootId;
      status_seq: Counter;
      checked_at: Seconds;
      valid_until: Seconds;
      evidence_hash: Hash;
    }
  | { v: 1; decision: "deny"; code: string };

export type HistoryResult =
  | { v: 1; valid: true; live: false; last_seq: Counter; last_hash: Hash }
  | { v: 1; valid: false; live: false; code: string };

export interface HeraldBindingRef extends JsonObject {
  source: string;
  card_id: string;
  card_hash: Hash;
}

export interface HeraldCheck extends JsonObject {
  v: 1;
  tenant_id: string;
  sub: string;
  caller_jkt: B64u;
  binding: HeraldBindingRef;
  challenge: string;
  mode: "fresh" | "bounded_cache";
  now: Seconds;
}

export interface HeraldObservation extends JsonObject {
  v: 1;
  challenge: string;
  card_hash: Hash;
  sub: string;
  caller_jkt: B64u;
  status: "active" | "revoked";
  checked_at: Seconds;
  valid_until: Seconds;
  evidence_hash: Hash;
}

export interface ExportSummary extends JsonObject {
  v: 1;
  count: number;
  next_revision: Counter | null;
  path: string;
  hash: Hash;
}

export interface DoctorReply extends JsonObject {
  v: 1;
  ready: boolean;
  checks: {
    clock: "ok" | "unsafe";
    root: "trusted" | "untrusted";
    storage: "ok" | "unavailable";
    capacity: "ok" | "warning" | "full";
    cache: "usable" | "stale" | "forked";
  };
}

export interface MigrationDescriptor extends JsonObject {
  v: 1;
  from: number;
  to: number;
  source_head: Hash;
  expected_events: Counter;
}
