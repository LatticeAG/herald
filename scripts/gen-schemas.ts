/**
 * Generates JSON Schema 2020-12 artifacts into schemas/. The runtime
 * validators in packages/core/src/schema.ts are authoritative; these
 * artifacts are the interoperable descriptive form required by §4
 * ("implementations MUST generate equivalent ... JSON Schema 2020-12
 * artifacts from these contracts"). Field sets are closed
 * (additionalProperties:false) to mirror the validators.
 *
 * Usage: node scripts/gen-schemas.ts [outdir]
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

type J = Record<string, unknown>;

const NANOID21 = "^[A-Za-z0-9_-]{21}$";
const NANOID32 = "^[A-Za-z0-9_-]{32}$";

const id = (prefix: string, len = 21): J => ({
  type: "string",
  pattern: `^${prefix}_${NANOID21.slice(1)}`.replace("{21}", `{${len}}`),
});
const HASH: J = { type: "string", pattern: "^[0-9a-f]{64}$" };
const COUNTER: J = { type: "string", pattern: "^(0|[1-9][0-9]{0,19})$" };
const SECONDS: J = { type: "integer", minimum: 0, maximum: 253402300799 };
const VERSION: J = { const: 1 };
const NONCE: J = { type: "string", pattern: `^hn_${NANOID32.slice(1)}` };
const DID: J = { type: "string", pattern: "^did:herald:hr_[A-Za-z0-9_-]{21}:ha_[A-Za-z0-9_-]{21}$", maxLength: 64 };
const B64U = (n: number): J => ({ type: "string", pattern: `^[A-Za-z0-9_-]{${Math.ceil((4 * n) / 3)}}$`, description: `base64url of ${n} bytes` });
const ORIGIN: J = { type: "string", pattern: "^https://[^/?#]+(:443)?$", description: "HTTPS origin, no path/userinfo/query/fragment, port 443 only; http://localhost allowed in development profiles" };
const NULL: J = { type: "null" };
const nullOr = (j: J): J => ({ anyOf: [NULL, j] });
const BOOL: J = { type: "boolean" };

function obj(fields: Record<string, J>): J {
  return {
    type: "object",
    properties: fields,
    required: Object.keys(fields),
    additionalProperties: false,
  };
}
const arr = (items: J, max?: number): J => ({
  type: "array", items, ...(max !== undefined ? { maxItems: max } : {}),
});
const oneOf = (...vals: unknown[]): J => ({ enum: vals });
const intIn = (lo: number, hi: number): J => ({ type: "integer", minimum: lo, maximum: hi });

const SLOTS = 131072;

const PublicKey = obj({ id: id("hk"), public_key: B64U(32) });
const Proof = obj({ kid: id("hk"), signature: B64U(64) });
const Proofs: J = {
  type: "array", items: Proof, minItems: 1, maxItems: 16,
  description: "strictly ascending unique by kid",
};
const signed = (body: J): J => obj({ body, proofs: Proofs });

const RootDocument = obj({
  control_key: PublicKey, created_at: SECONDS,
  cutover: nullOr(obj({ log_hash: HASH, seq: COUNTER })),
  epoch: COUNTER, origin: ORIGIN, previous: nullOr(HASH),
  registrar_key: PublicKey, root: id("hr"), service_key: PublicKey,
  status_slots: { const: SLOTS }, v: VERSION,
});
const SignedRootDocument = signed(RootDocument);

const HumanBinding = obj({
  agent_key: PublicKey, assurance: oneOf("operator-attested"),
  consent: oneOf("agent-accountability-v1"), did: DID, expires_at: SECONDS,
  human_key: PublicKey, id: id("hb"), issued_at: SECONDS,
  principal_id: id("hp"), previous: nullOr(HASH), registrar_epoch: COUNTER,
  root: id("hr"), v: VERSION,
});
const SignedHumanBinding = signed(HumanBinding);

const GatewayBinding = obj({
  caller_jkt: B64U(32), gateway: id("lsg"), sub: id("lsu"), tenant_id: id("ltn"),
});

const AgentCard = obj({
  binding_hash: HASH, capabilities_hash: HASH, did: DID, expires_at: SECONDS,
  gateway_bindings: { type: "array", items: GatewayBinding, maxItems: 4, description: "sorted unique by (gateway,tenant_id,sub)" },
  human_principal: id("hp"), id: id("hc"), issued_at: SECONDS, key: PublicKey,
  key_epoch: COUNTER, not_before: SECONDS, previous: nullOr(HASH),
  root: id("hr"), status_index: intIn(0, SLOTS - 1), v: VERSION,
});
const SignedAgentCard = signed(AgentCard);

const Capabilities = obj({
  capabilities: { type: "array", items: { type: "string", pattern: "^[a-z][a-z0-9._-]{0,63}$" }, maxItems: 64, uniqueItems: true, description: "sorted unique" },
  v: VERSION,
});

const Rotation = obj({
  did: DID, expires_at: SECONDS, from_epoch: COUNTER, issued_at: SECONDS,
  new_card_hash: HASH, new_key: PublicKey, nonce: NONCE,
  old_card_hash: HASH, old_key_id: id("hk"), root: id("hr"),
  to_epoch: COUNTER, v: VERSION,
});
const SignedRotation = signed(Rotation);

const Action: J = {
  oneOf: [
    obj({ binding: SignedHumanBinding, kind: { const: "binding.enroll" } }),
    obj({ card: SignedAgentCard, kind: { const: "card.issue" } }),
    obj({ binding: SignedHumanBinding, card: SignedAgentCard, kind: { const: "binding.renew" } }),
    obj({ card: SignedAgentCard, kind: { const: "card.rotate" }, rotation: SignedRotation }),
    obj({
      id: { anyOf: [DID, id("hb"), id("hc")] }, kind: { const: "revoke" },
      reason: oneOf("COMPROMISE", "WITHDRAWN", "RETIRED", "ADMINISTRATIVE"),
      target: oneOf("agent", "binding", "card"),
    }),
    obj({ document: SignedRootDocument, kind: { const: "root.rotate" } }),
    obj({ kind: { const: "root.freeze" }, reason: oneOf("COMPROMISE", "ADMINISTRATIVE") }),
  ],
  discriminator: { propertyName: "kind" },
};

const Command = signed(obj({
  action: Action, actor: id("hk"), expected_revision: COUNTER,
  expires_at: SECONDS, issued_at: SECONDS, op_id: id("ho"),
  root: id("hr"), subject: { anyOf: [DID, id("hr")] }, v: VERSION,
}));

const Query = signed(obj({
  actor: id("hk"), expires_at: SECONDS, issued_at: SECONDS,
  query: {
    oneOf: [
      obj({ card_id: nullOr(id("hc")), did: DID, kind: { const: "resolve" } }),
      obj({ kind: { const: "receipt" }, op_id: id("ho") }),
      obj({ after_revision: COUNTER, did: DID, kind: { const: "export" }, limit: intIn(1, 100) }),
    ],
    discriminator: { propertyName: "kind" },
  },
  query_id: id("hq"), root: id("hr"), v: VERSION,
}));

const AgentRecord = obj({
  binding_hash: HASH, current_card_hash: nullOr(HASH), current_key: PublicKey,
  did: DID, key_epoch: COUNTER, revision: COUNTER, root: id("hr"),
  state: oneOf("enrolled", "active", "revoked"), v: VERSION,
});

const EVENT_KINDS = [
  "RootCreated", "RootRotated", "RootFrozen", "BindingEnrolled", "BindingRenewed",
  "CardIssued", "CardRotated", "CardRevoked", "AgentRevoked", "BindingRevoked",
];

const Receipt = signed(obj({
  allocated: nullOr(intIn(0, SLOTS - 1)), event_hash: HASH,
  kind: oneOf(...EVENT_KINDS), objects: arr(HASH), op_id: id("ho"),
  request_hash: HASH, root: id("hr"), seq: COUNTER, v: VERSION,
}));

const IdentityBundle = obj({
  binding: SignedHumanBinding, card: SignedAgentCard,
  prior_card: nullOr(SignedAgentCard), receipt: Receipt,
  roots: arr(SignedRootDocument, 64), rotation: nullOr(SignedRotation), v: VERSION,
});

const AuditEvent = signed(obj({
  allocated: nullOr(intIn(0, SLOTS - 1)),
  invalidated: { type: "array", items: { type: "integer", minimum: 0 }, description: "strictly ascending unique" },
  kind: oneOf(...EVENT_KINDS), objects: arr(HASH), prev: HASH,
  request_hash: HASH, root: id("hr"), root_epoch: COUNTER,
  root_state: oneOf("active", "frozen"), seq: COUNTER, time: SECONDS, v: VERSION,
}));

const Status = signed(obj({
  bits: B64U(16384), expires_at: SECONDS, issued_at: SECONDS, log_hash: HASH,
  root: id("hr"), root_epoch: COUNTER, seq: COUNTER,
  slots: { const: SLOTS }, state: oneOf("active", "frozen"), v: VERSION,
}));

const FreshRequest = obj({ challenge: NONCE, v: VERSION });
const Fresh = signed(obj({
  challenge: NONCE, checked_at: SECONDS, log_hash: HASH, root: id("hr"),
  seq: COUNTER, status_hash: HASH, valid_until: SECONDS, v: VERSION,
}));
const FreshReply = obj({ fresh: Fresh, status: Status, v: VERSION });

const LogPage = obj({ events: arr(AuditEvent, 100), next_after: nullOr(COUNTER), v: VERSION });
const RootHistoryReply = obj({ documents: arr(SignedRootDocument, 64), next_after: nullOr(COUNTER), v: VERSION });
const MutationReply = obj({ receipt: Receipt, record: nullOr(AgentRecord), v: VERSION });
const ResolveReply = obj({ bundle: nullOr(IdentityBundle), record: AgentRecord, v: VERSION });
const ExportRecord = obj({ command: Command, receipt: Receipt, revision: COUNTER });
const ExportReply = obj({ next_revision: nullOr(COUNTER), records: arr(ExportRecord, 100), v: VERSION });
const ErrorReply = obj({
  error: obj({ code: { type: "string", pattern: "^[A-Z_]{2,40}$" }, retryable: BOOL }),
  v: VERSION,
});
const HealthReply = obj({ status: oneOf("alive"), v: VERSION });
const ReadinessReply = obj({ code: { type: "string" }, status: oneOf("ready", "not_ready"), v: VERSION });
const Frontier = obj({ log_hash: HASH, root: id("hr"), root_epoch: COUNTER, seq: COUNTER });
const RootPin = obj({
  control_fingerprint: HASH, enabled: BOOL, genesis_hash: HASH,
  min_epoch: COUNTER, origin: ORIGIN, root: id("hr"),
});
const ClientConfig = obj({
  cache_dir: { type: "string" }, clock_max_error_s: { const: 2 },
  fresh_max_age_s: { const: 5 },
  key_refs: arr(obj({ kid: id("hk"), path: { type: "string" } }), 64),
  mode: oneOf("production", "development"), read_max_age_s: { const: 60 },
  roots: arr(RootPin, 32), v: VERSION,
});
const ServerConfig = obj({
  max_agents: { const: 8192 },
  private_data_key_binding: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,31}$" },
  production: BOOL, public_fresh_per_minute: { const: 120 },
  public_get_per_minute: { const: 120 }, revocation_reserve_per_minute: { const: 60 },
  root: id("hr"), root_do_binding: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,31}$" },
  root_document_path: { type: "string" },
  service_secret_binding: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,31}$" },
  status_slots: { const: SLOTS }, v: VERSION,
  write_per_actor_per_minute: { const: 30 },
});
const KeyFile = obj({ algorithm: oneOf("Ed25519"), kid: id("hk"), seed_b64u: B64U(32), v: VERSION });
const ExportSummary = obj({
  count: { type: "integer", minimum: 0 }, hash: HASH,
  next_revision: nullOr(COUNTER), path: { type: "string" }, v: VERSION,
});
const DoctorReply = obj({
  checks: obj({
    cache: oneOf("usable", "stale", "forked"), capacity: oneOf("ok", "warning", "full"),
    clock: oneOf("ok", "unsafe"), root: oneOf("trusted", "untrusted"),
    storage: oneOf("ok", "unavailable"),
  }),
  ready: BOOL, v: VERSION,
});
const MigrationDescriptor = obj({
  expected_events: COUNTER, from: { type: "integer", minimum: 0 },
  source_head: HASH, to: { type: "integer", minimum: 0 }, v: VERSION,
});

const HeraldBindingRef = obj({
  card_hash: HASH, card_id: { type: "string" },
  source: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,31}$" },
});
const HeraldCheck = obj({
  binding: HeraldBindingRef, caller_jkt: B64U(32), challenge: { type: "string" },
  mode: oneOf("fresh", "bounded_cache"), now: SECONDS, sub: { type: "string" },
  tenant_id: { type: "string" }, v: VERSION,
});
const HeraldObservation = obj({
  caller_jkt: B64U(32), card_hash: HASH, challenge: { type: "string" },
  checked_at: SECONDS, evidence_hash: HASH, status: oneOf("active", "revoked"),
  sub: { type: "string" }, v: VERSION,
});

const SCHEMAS: Record<string, J> = {
  PublicKey, Proof, RootDocument, SignedRootDocument,
  HumanBinding, SignedHumanBinding, GatewayBinding,
  AgentCard, SignedAgentCard, Capabilities,
  Rotation, SignedRotation, Command, Query, AgentRecord, Receipt,
  IdentityBundle, AuditEvent, Status, FreshRequest, Fresh, FreshReply,
  LogPage, RootHistoryReply, MutationReply, ResolveReply, ExportReply,
  ErrorReply, HealthReply, ReadinessReply, Frontier, RootPin,
  ClientConfig, ServerConfig, KeyFile, ExportSummary, DoctorReply,
  MigrationDescriptor, HeraldCheck, HeraldObservation,
};

const out = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "../schemas");
mkdirSync(out, { recursive: true });
for (const [name, schema] of Object.entries(SCHEMAS)) {
  const doc = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: `https://latticeag.dev/schemas/herald/${name}.schema.json`,
    title: `Herald ${name}`,
    ...schema,
  };
  writeFileSync(join(out, `${name}.schema.json`), JSON.stringify(doc, null, 2) + "\n");
}
console.log(`wrote ${Object.keys(SCHEMAS).length} schemas to ${out}`);
