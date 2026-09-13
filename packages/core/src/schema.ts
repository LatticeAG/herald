/**
 * Closed wire-schema validators (spec §3–§10). Every object type is closed:
 * unknown fields, unknown enum members, unsupported versions, and null where
 * not allowed are errors. Within each object, fields are walked in JCS
 * (UTF-16) order and the first failure is returned. A reserved delegation
 * field name at any depth of a signed body yields DELEGATION_FORBIDDEN
 * before the general unknown-field rule.
 */

import { b64uDecode } from "./base64url.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { isCounter } from "./json.ts";
import type { EventKind } from "./types.ts";
import {
  isAgentId, isBindingId, isCardId, isDid, isGatewayId, isHash, isKeyId,
  isNonce, isOpId, isOrigin, isPrincipalId, isQueryId, isRootId, isSubId,
  isTenantId,
} from "./ids.ts";

const MAX_SECONDS = 253402300799;
export const STATUS_SLOTS = 131072;
export const MAX_AGENTS = 8192;
export const MAX_CARD_LIFETIME = 86400;
export const MAX_BINDING_LIFETIME = 7776000;
export const MAX_COMMAND_LIFETIME = 120;
export const MAX_QUERY_LIFETIME = 30;
export const MAX_ROOT_EPOCHS = 64;
export const MAX_KEY_EPOCHS = 256;
export const MAX_BINDING_REVISIONS = 64;
export const MAX_GATEWAY_BINDINGS = 4;
export const MAX_CAPABILITIES = 64;
export const MAX_PAGE = 100;
export const MAX_DOC_PAGE = 64;

export const RESERVED_FIELD_NAMES = new Set([
  "delegation", "delegate", "delegated_by", "parent", "chain",
  "proof_chain", "proofChain", "attenuation", "capability_chain",
  "issuer_chain", "via",
]);

const CAP_RE = /^[a-z][a-z0-9._-]{0,63}$/;
const SOURCE_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const ROLE_RE = /^[a-z][a-z0-9_-]{0,31}$/;

type Check = (v: JsonValue) => string | null;

/** A checker combinator for literals/enums. */
function oneOf<T extends JsonValue>(...vals: T[]): Check {
  return (v) => (vals.includes(v as T) ? null : "SCHEMA_INVALID");
}
/** Protocol version field: any value other than 1 is VERSION_UNSUPPORTED. */
function version(v: JsonValue): string | null {
  return v === 1 ? null : "VERSION_UNSUPPORTED";
}
function seconds(v: JsonValue): string | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SECONDS
    ? null : "NUMBER_INVALID";
}
function nonnegInt(v: JsonValue): string | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? null : "NUMBER_INVALID";
}
function intIn(lo: number, hi: number): Check {
  return (v) =>
    typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi ? null : "NUMBER_INVALID";
}
function counter(v: JsonValue): string | null {
  return isCounter(v) ? null : "NUMBER_INVALID";
}
function hash(v: JsonValue): string | null {
  return isHash(v) ? null : "ENCODING_INVALID";
}
function hashOrNull(v: JsonValue): string | null {
  return v === null ? null : isHash(v) ? null : "ENCODING_INVALID";
}
function b64uLen(len: number): Check {
  return (v) =>
    typeof v === "string" && b64uDecode(v)?.length === len ? null : "ENCODING_INVALID";
}
function str(check?: (s: string) => boolean, code = "SCHEMA_INVALID"): Check {
  return (v) => (typeof v === "string" && (check ? check(s0(v)) : true) ? null : code);
  function s0(x: JsonValue): string {
    return x as string;
  }
}
function idCheck(f: (s: unknown) => boolean): Check {
  return (v) => (f(v) ? null : "ID_INVALID");
}
function bool(v: JsonValue): string | null {
  return typeof v === "boolean" ? null : "SCHEMA_INVALID";
}

/** Sorted-unique array of strings (designated set ordering). */
function sortedUnique(elems: (string | number)[]): boolean {
  for (let i = 1; i < elems.length; i++) {
    const a = elems[i - 1]!;
    const b = elems[i]!;
    if (typeof a === "string" && typeof b === "string") {
      if (a >= b) return false;
    } else if (typeof a === "number" && typeof b === "number") {
      if (a >= b) return false;
    } else return false;
  }
  return true;
}

function arr(elem: Check, opts?: { max?: number; sortedUnique?: boolean }): Check {
  return (v) => {
    if (!Array.isArray(v)) return "SCHEMA_INVALID";
    if (opts?.max !== undefined && v.length > opts.max) return "SCHEMA_INVALID";
    const seen: (string | number)[] = [];
    for (const e of v) {
      const c = elem(e);
      if (c !== null) return c;
      if (typeof e === "string" || typeof e === "number") seen.push(e);
    }
    if (opts?.sortedUnique && !sortedUnique(seen)) return "SCHEMA_INVALID";
    return null;
  };
}

function nullOr(c: Check): Check {
  return (v) => (v === null ? null : c(v));
}

function obj(fields: [string, Check][], requiredAll = true): Check {
  const spec = new Map(fields);
  return (v) => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return "SCHEMA_INVALID";
    const o = v as JsonObject;
    const keys = Object.keys(o).sort();
    for (const k of keys) {
      const c = spec.get(k);
      if (!c) return "SCHEMA_INVALID";
      const r = c(o[k]!);
      if (r !== null) return r;
    }
    if (requiredAll) {
      for (const k of spec.keys()) if (!Object.prototype.hasOwnProperty.call(o, k)) return "SCHEMA_INVALID";
    }
    return null;
  };
}

function scanReserved(v: JsonValue): boolean {
  if (typeof v !== "object" || v === null) return false;
  if (Array.isArray(v)) {
    for (const e of v) if (scanReserved(e)) return true;
    return false;
  }
  const keys = Object.keys(v as JsonObject).sort();
  for (const k of keys) {
    if (RESERVED_FIELD_NAMES.has(k)) return true;
    if (scanReserved((v as JsonObject)[k]!)) return true;
  }
  return false;
}

/** Run the reserved-name scan then the object field walk for a signed body. */
function bodyCheck(inner: Check): Check {
  return (v) => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return "SCHEMA_INVALID";
    if (scanReserved(v)) return "DELEGATION_FORBIDDEN";
    return inner(v);
  };
}

// ---------- Scalar object types ----------

export const vPublicKey: Check = obj([
  ["id", idCheck(isKeyId)],
  ["public_key", b64uLen(32)],
]);

export const vProof: Check = obj([
  ["kid", idCheck(isKeyId)],
  ["signature", b64uLen(64)],
]);

export const vProofs: Check = (v) => {
  if (!Array.isArray(v) || v.length < 1 || v.length > 16) return "SCHEMA_INVALID";
  const kids: string[] = [];
  for (const e of v) {
    const c = vProof(e);
    if (c !== null) return c;
    kids.push((e as JsonObject)["kid"] as string);
  }
  for (let i = 1; i < kids.length; i++) {
    if (kids[i - 1]! >= kids[i]!) return "SCHEMA_INVALID"; // not strictly ascending unique
  }
  return null;
};

function signed(inner: Check): Check {
  return obj([
    ["body", bodyCheck(inner)],
    ["proofs", vProofs],
  ]);
}

export const vCutover: Check = nullOr(
  obj([
    ["log_hash", hash],
    ["seq", counter],
  ]),
);

const DEV_OK = { development: false };

export function rootDocumentCheck(development = false): Check {
  return obj([
    ["control_key", vPublicKey],
    ["created_at", seconds],
    ["cutover", vCutover],
    ["epoch", counter],
    ["origin", (v) => (isOrigin(v, development) ? null : "SCHEMA_INVALID")],
    ["previous", hashOrNull],
    ["registrar_key", vPublicKey],
    ["root", idCheck(isRootId)],
    ["service_key", vPublicKey],
    ["status_slots", oneOf(STATUS_SLOTS)],
    ["v", version],
  ]);
}
export const vRootDocument = rootDocumentCheck(false);

export const vHumanBinding: Check = obj([
  ["agent_key", vPublicKey],
  ["assurance", oneOf("operator-attested")],
  ["consent", oneOf("agent-accountability-v1")],
  ["did", idCheck(isDid)],
  ["expires_at", seconds],
  ["human_key", vPublicKey],
  ["id", idCheck(isBindingId)],
  ["issued_at", seconds],
  ["principal_id", idCheck(isPrincipalId)],
  ["previous", hashOrNull],
  ["registrar_epoch", counter],
  ["root", idCheck(isRootId)],
  ["v", version],
]);

export const vGatewayBinding: Check = obj([
  ["caller_jkt", (v) => (typeof v === "string" && b64uDecode(v) !== null && b64uDecode(v)!.length === 32 ? null : "ENCODING_INVALID")],
  ["gateway", idCheck(isGatewayId)],
  ["sub", idCheck(isSubId)],
  ["tenant_id", idCheck(isTenantId)],
]);

const vGatewayBindings: Check = (v) => {
  if (!Array.isArray(v) || v.length > MAX_GATEWAY_BINDINGS) return "SCHEMA_INVALID";
  let prev: [string, string, string] | null = null;
  for (const e of v) {
    const c = vGatewayBinding(e);
    if (c !== null) return c;
    const g = e as JsonObject;
    const cur: [string, string, string] = [g["gateway"] as string, g["tenant_id"] as string, g["sub"] as string];
    if (prev !== null) {
      for (let i = 0; i < 3; i++) {
        if (cur[i]! < prev[i]!) return "SCHEMA_INVALID";
        if (cur[i]! > prev[i]!) break;
        if (i === 2) return "SCHEMA_INVALID"; // duplicate tuple
      }
    }
    prev = cur;
  }
  return null;
};

export const vAgentCard: Check = obj([
  ["binding_hash", hash],
  ["capabilities_hash", hash],
  ["did", idCheck(isDid)],
  ["expires_at", seconds],
  ["gateway_bindings", vGatewayBindings],
  ["human_principal", idCheck(isPrincipalId)],
  ["id", idCheck(isCardId)],
  ["issued_at", seconds],
  ["key", vPublicKey],
  ["key_epoch", counter],
  ["not_before", seconds],
  ["previous", hashOrNull],
  ["root", idCheck(isRootId)],
  ["status_index", intIn(0, STATUS_SLOTS - 1)],
  ["v", version],
]);

export const vCapabilities: Check = obj([
  ["capabilities", arr((v) => (typeof v === "string" && CAP_RE.test(v) ? null : "SCHEMA_INVALID"), { max: MAX_CAPABILITIES, sortedUnique: true })],
  ["v", version],
]);

export const vRotation: Check = obj([
  ["did", idCheck(isDid)],
  ["expires_at", seconds],
  ["from_epoch", counter],
  ["issued_at", seconds],
  ["new_card_hash", hash],
  ["new_key", vPublicKey],
  ["nonce", idCheck(isNonce)],
  ["old_card_hash", hash],
  ["old_key_id", idCheck(isKeyId)],
  ["root", idCheck(isRootId)],
  ["to_epoch", counter],
  ["v", version],
]);

const vEnroll: Check = obj([["binding", signed(vHumanBinding)], ["kind", oneOf("binding.enroll")]]);
const vIssue: Check = obj([["card", signed(vAgentCard)], ["kind", oneOf("card.issue")]]);
const vRenew: Check = obj([
  ["binding", signed(vHumanBinding)],
  ["card", signed(vAgentCard)],
  ["kind", oneOf("binding.renew")],
]);
const vRotate: Check = obj([
  ["card", signed(vAgentCard)],
  ["kind", oneOf("card.rotate")],
  ["rotation", signed(vRotation)],
]);
const vRevoke: Check = obj([
  ["id", (v) => (typeof v === "string" && (isDid(v) || isBindingId(v) || isCardId(v)) ? null : "ID_INVALID")],
  ["kind", oneOf("revoke")],
  ["reason", oneOf("COMPROMISE", "WITHDRAWN", "RETIRED", "ADMINISTRATIVE")],
  ["target", oneOf("agent", "binding", "card")],
]);
const vRotateRoot: Check = obj([["document", signed(vRootDocument)], ["kind", oneOf("root.rotate")]]);
const vFreezeRoot: Check = obj([
  ["kind", oneOf("root.freeze")],
  ["reason", oneOf("COMPROMISE", "ADMINISTRATIVE")],
]);

export function actionCheck(v: JsonValue): string | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return "SCHEMA_INVALID";
  const kind = (v as JsonObject)["kind"];
  switch (kind) {
    case "binding.enroll": return vEnroll(v);
    case "card.issue": return vIssue(v);
    case "binding.renew": return vRenew(v);
    case "card.rotate": return vRotate(v);
    case "revoke": return vRevoke(v);
    case "root.rotate": return vRotateRoot(v);
    case "root.freeze": return vFreezeRoot(v);
    default: return "SCHEMA_INVALID";
  }
}

export const vCommandBody: Check = obj([
  ["action", actionCheck],
  ["actor", idCheck(isKeyId)],
  ["expected_revision", counter],
  ["expires_at", seconds],
  ["issued_at", seconds],
  ["op_id", idCheck(isOpId)],
  ["root", idCheck(isRootId)],
  ["subject", (v) => (isDid(v) || isRootId(v) ? null : "ID_INVALID")],
  ["v", version],
]);
export const vCommand = signed(vCommandBody);

const vResolveQ: Check = obj([
  ["card_id", nullOr(idCheck(isCardId))],
  ["did", idCheck(isDid)],
  ["kind", oneOf("resolve")],
]);
const vReceiptQ: Check = obj([
  ["kind", oneOf("receipt")],
  ["op_id", idCheck(isOpId)],
]);
const vExportQ: Check = obj([
  ["after_revision", counter],
  ["did", idCheck(isDid)],
  ["kind", oneOf("export")],
  ["limit", intIn(1, MAX_PAGE)],
]);
export function queryKindCheck(v: JsonValue): string | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return "SCHEMA_INVALID";
  switch ((v as JsonObject)["kind"]) {
    case "resolve": return vResolveQ(v);
    case "receipt": return vReceiptQ(v);
    case "export": return vExportQ(v);
    default: return "SCHEMA_INVALID";
  }
}
export const vQueryBody: Check = obj([
  ["actor", idCheck(isKeyId)],
  ["expires_at", seconds],
  ["issued_at", seconds],
  ["query", queryKindCheck],
  ["query_id", idCheck(isQueryId)],
  ["root", idCheck(isRootId)],
  ["v", version],
]);
export const vQuery = signed(vQueryBody);

export const vAgentRecord: Check = obj([
  ["binding_hash", hash],
  ["current_card_hash", hashOrNull],
  ["current_key", vPublicKey],
  ["did", idCheck(isDid)],
  ["key_epoch", counter],
  ["revision", counter],
  ["root", idCheck(isRootId)],
  ["state", oneOf("enrolled", "active", "revoked")],
  ["v", version],
]);

export const EVENT_KINDS = [
  "RootCreated", "RootRotated", "RootFrozen", "BindingEnrolled", "BindingRenewed",
  "CardIssued", "CardRotated", "CardRevoked", "AgentRevoked", "BindingRevoked",
] as const;
const EVENT_KIND_SET = new Set<string>(EVENT_KINDS);
export function isEventKind(s: string): s is EventKind {
  return EVENT_KIND_SET.has(s);
}

export const vReceiptBody: Check = obj([
  ["allocated", nullOr(intIn(0, STATUS_SLOTS - 1))],
  ["event_hash", hash],
  ["kind", (v) => (typeof v === "string" && isEventKind(v) ? null : "SCHEMA_INVALID")],
  ["objects", arr(hash, { sortedUnique: true })],
  ["op_id", idCheck(isOpId)],
  ["request_hash", hash],
  ["root", idCheck(isRootId)],
  ["seq", counter],
  ["v", version],
]);
export const vReceipt = signed(vReceiptBody);

export const vSignedRootDocument = signed(vRootDocument);
export const vSignedHumanBinding = signed(vHumanBinding);
export const vSignedAgentCard = signed(vAgentCard);
export const vSignedRotation = signed(vRotation);

export const vIdentityBundle: Check = obj([
  ["binding", vSignedHumanBinding],
  ["card", vSignedAgentCard],
  ["prior_card", nullOr(vSignedAgentCard)],
  ["receipt", vReceipt],
  ["roots", arr(vSignedRootDocument, { max: MAX_ROOT_EPOCHS })],
  ["rotation", nullOr(vSignedRotation)],
  ["v", version],
]);

export const vAuditEventBody: Check = obj([
  ["allocated", nullOr(intIn(0, STATUS_SLOTS - 1))],
  ["invalidated", arr(nonnegInt, { sortedUnique: true })],
  ["kind", (v) => (typeof v === "string" && isEventKind(v) ? null : "SCHEMA_INVALID")],
  ["objects", arr(hash, { sortedUnique: true })],
  ["prev", hash],
  ["request_hash", hash],
  ["root", idCheck(isRootId)],
  ["root_epoch", counter],
  ["root_state", oneOf("active", "frozen")],
  ["seq", counter],
  ["time", seconds],
  ["v", version],
]);
export const vAuditEvent = signed(vAuditEventBody);

export const vStatusBody: Check = obj([
  ["bits", (v) => (typeof v === "string" && b64uDecode(v)?.length === 16384 ? null : "ENCODING_INVALID")],
  ["expires_at", seconds],
  ["issued_at", seconds],
  ["log_hash", hash],
  ["root", idCheck(isRootId)],
  ["root_epoch", counter],
  ["seq", counter],
  ["slots", oneOf(STATUS_SLOTS)],
  ["state", oneOf("active", "frozen")],
  ["v", version],
]);
export const vStatus = signed(vStatusBody);

export const vFreshRequest: Check = obj([
  ["challenge", idCheck(isNonce)],
  ["v", version],
]);

export const vFreshBody: Check = obj([
  ["challenge", idCheck(isNonce)],
  ["checked_at", seconds],
  ["log_hash", hash],
  ["root", idCheck(isRootId)],
  ["seq", counter],
  ["status_hash", hash],
  ["valid_until", seconds],
  ["v", version],
]);
export const vFresh = signed(vFreshBody);

export const vFreshReply: Check = obj([
  ["fresh", vFresh],
  ["status", vStatus],
  ["v", version],
]);

export const vLogPage: Check = obj([
  ["events", arr(vAuditEvent, { max: MAX_PAGE })],
  ["next_after", nullOr(counter)],
  ["v", version],
]);

export const vRootHistoryReply: Check = obj([
  ["documents", arr(vSignedRootDocument, { max: MAX_DOC_PAGE })],
  ["next_after", nullOr(counter)],
  ["v", version],
]);

export const vMutationReply: Check = obj([
  ["receipt", vReceipt],
  ["record", nullOr(vAgentRecord)],
  ["v", version],
]);

export const vResolveReply: Check = obj([
  ["bundle", nullOr(vIdentityBundle)],
  ["record", vAgentRecord],
  ["v", version],
]);

export const vExportRecord: Check = obj([
  ["command", vCommand],
  ["receipt", vReceipt],
  ["revision", counter],
]);

export const vExportReply: Check = obj([
  ["next_revision", nullOr(counter)],
  ["records", arr(vExportRecord, { max: MAX_PAGE })],
  ["v", version],
]);

export const vErrorReply: Check = obj([
  ["error", obj([
    ["code", (v) => (typeof v === "string" && /^[A-Z_]{2,40}$/.test(v) ? null : "SCHEMA_INVALID")],
    ["retryable", bool],
  ])],
  ["v", version],
]);

export const vHealthReply: Check = obj([
  ["status", oneOf("alive")],
  ["v", version],
]);

export const vReadinessReply: Check = obj([
  ["code", str()],
  ["status", oneOf("ready", "not_ready")],
  ["v", version],
]);

export const vFrontier: Check = obj([
  ["log_hash", hash],
  ["root", idCheck(isRootId)],
  ["root_epoch", counter],
  ["seq", counter],
]);

// ---------- Config types ----------

export const vRootPin: Check = obj([
  ["control_fingerprint", hash],
  ["enabled", bool],
  ["genesis_hash", hash],
  ["min_epoch", counter],
  ["origin", str((s) => isOrigin(s, true))],
  ["root", idCheck(isRootId)],
]);

export const vClientConfig: Check = obj([
  ["cache_dir", str()],
  ["clock_max_error_s", oneOf(2)],
  ["fresh_max_age_s", oneOf(5)],
  ["key_refs", arr(obj([
    ["kid", idCheck(isKeyId)],
    ["path", str()],
  ]), { max: 64, sortedUnique: false })],
  ["mode", oneOf("production", "development")],
  ["read_max_age_s", oneOf(60)],
  ["roots", arr(vRootPin, { max: 32 })],
  ["v", version],
]);

export const vServerConfig: Check = obj([
  ["max_agents", oneOf(MAX_AGENTS)],
  ["private_data_key_binding", str((s) => ROLE_RE.test(s))],
  ["production", bool],
  ["public_fresh_per_minute", oneOf(120)],
  ["public_get_per_minute", oneOf(120)],
  ["revocation_reserve_per_minute", oneOf(60)],
  ["root", idCheck(isRootId)],
  ["root_do_binding", str((s) => ROLE_RE.test(s))],
  ["root_document_path", str()],
  ["service_secret_binding", str((s) => ROLE_RE.test(s))],
  ["status_slots", oneOf(STATUS_SLOTS)],
  ["write_per_actor_per_minute", oneOf(30)],
  ["v", version],
]);

export const vKeyFile: Check = obj([
  ["algorithm", oneOf("Ed25519")],
  ["kid", idCheck(isKeyId)],
  ["seed_b64u", b64uLen(32)],
  ["v", version],
]);

export const vExportSummary: Check = obj([
  ["count", nonnegInt],
  ["hash", hash],
  ["next_revision", nullOr(counter)],
  ["path", str()],
  ["v", version],
]);

export const vDoctorReply: Check = obj([
  ["checks", obj([
    ["cache", oneOf("usable", "stale", "forked")],
    ["capacity", oneOf("ok", "warning", "full")],
    ["clock", oneOf("ok", "unsafe")],
    ["root", oneOf("trusted", "untrusted")],
    ["storage", oneOf("ok", "unavailable")],
  ])],
  ["ready", bool],
  ["v", version],
]);

export const vMigrationDescriptor: Check = obj([
  ["expected_events", counter],
  ["from", nonnegInt],
  ["source_head", hash],
  ["to", nonnegInt],
  ["v", version],
]);

// ---------- Adapter types (§10) ----------

export const vHeraldBindingRef: Check = obj([
  ["card_hash", hash],
  ["card_id", str()],
  ["source", str((s) => SOURCE_RE.test(s))],
]);

export const vHeraldCheck: Check = obj([
  ["binding", vHeraldBindingRef],
  ["caller_jkt", b64uLen(32)],
  ["challenge", str()],
  ["mode", oneOf("fresh", "bounded_cache")],
  ["now", seconds],
  ["sub", str()],
  ["tenant_id", str()],
  ["v", version],
]);

export const vHeraldObservation: Check = obj([
  ["caller_jkt", b64uLen(32)],
  ["card_hash", hash],
  ["challenge", str()],
  ["checked_at", seconds],
  ["evidence_hash", hash],
  ["status", oneOf("active", "revoked")],
  ["sub", str()],
  ["v", version],
]);

// ---------- Dispatcher ----------

const VALIDATORS: Record<string, Check> = {
  PublicKey: vPublicKey,
  Proof: vProof,
  RootDocument: vRootDocument,
  HumanBinding: vHumanBinding,
  GatewayBinding: vGatewayBinding,
  AgentCard: vAgentCard,
  Capabilities: vCapabilities,
  Rotation: vRotation,
  Command: vCommand,
  Query: vQuery,
  AgentRecord: vAgentRecord,
  Receipt: vReceipt,
  IdentityBundle: vIdentityBundle,
  AuditEvent: vAuditEvent,
  Status: vStatus,
  FreshRequest: vFreshRequest,
  Fresh: vFresh,
  FreshReply: vFreshReply,
  LogPage: vLogPage,
  RootHistoryReply: vRootHistoryReply,
  MutationReply: vMutationReply,
  ResolveReply: vResolveReply,
  ExportReply: vExportReply,
  ErrorReply: vErrorReply,
  HealthReply: vHealthReply,
  ReadinessReply: vReadinessReply,
  Frontier: vFrontier,
  RootPin: vRootPin,
  ClientConfig: vClientConfig,
  ServerConfig: vServerConfig,
  KeyFile: vKeyFile,
  ExportSummary: vExportSummary,
  DoctorReply: vDoctorReply,
  MigrationDescriptor: vMigrationDescriptor,
  HeraldCheck: vHeraldCheck,
  HeraldObservation: vHeraldObservation,
  SignedRootDocument: vSignedRootDocument,
  SignedHumanBinding: vSignedHumanBinding,
  SignedAgentCard: vSignedAgentCard,
  SignedRotation: vSignedRotation,
};

export function validate(type: string, value: JsonValue): string | null {
  const c = VALIDATORS[type];
  if (!c) throw new Error(`unknown wire type ${type}`);
  return c(value);
}
