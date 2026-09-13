"""Closed wire-schema validators (spec §3–§10). Every object type is closed:
unknown fields, unknown enum members, unsupported versions, and null where
not allowed are errors. Within each object, fields are walked in JCS
(UTF-16) order and the first failure is returned. A reserved delegation
field name at any depth of a signed body yields DELEGATION_FORBIDDEN before
the general unknown-field rule.
"""

import re

from .b64u import b64u_decode
from .strictjson import is_counter
from .ids import (
    is_agent_id, is_binding_id, is_card_id, is_did, is_gateway_id, is_hash,
    is_key_id, is_nonce, is_op_id, is_origin, is_principal_id, is_query_id,
    is_root_id, is_sub_id, is_tenant_id,
)

MAX_SECONDS = 253402300799
STATUS_SLOTS = 131072
MAX_AGENTS = 8192
MAX_CARD_LIFETIME = 86400
MAX_BINDING_LIFETIME = 7776000
MAX_COMMAND_LIFETIME = 120
MAX_QUERY_LIFETIME = 30
MAX_ROOT_EPOCHS = 64
MAX_KEY_EPOCHS = 256
MAX_BINDING_REVISIONS = 64
MAX_GATEWAY_BINDINGS = 4
MAX_CAPABILITIES = 64
MAX_PAGE = 100
MAX_DOC_PAGE = 64

RESERVED_FIELD_NAMES = frozenset([
    "delegation", "delegate", "delegated_by", "parent", "chain",
    "proof_chain", "proofChain", "attenuation", "capability_chain",
    "issuer_chain", "via",
])

CAP_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
SOURCE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def one_of(*vals):
    def c(v):
        return None if any(type(v) is type(x) and v == x for x in vals) else "SCHEMA_INVALID"
    return c


def _version(v):
    return None if v == 1 and _is_int(v) else "VERSION_UNSUPPORTED"


def _seconds(v):
    return None if _is_int(v) and 0 <= v <= MAX_SECONDS else "NUMBER_INVALID"


def _nonneg_int(v):
    return None if _is_int(v) and v >= 0 else "NUMBER_INVALID"


def _int_in(lo, hi):
    return lambda v: None if _is_int(v) and lo <= v <= hi else "NUMBER_INVALID"


def _counter(v):
    return None if is_counter(v) else "NUMBER_INVALID"


def _hash(v):
    return None if is_hash(v) else "ENCODING_INVALID"


def _hash_or_null(v):
    return None if v is None else _hash(v)


def _b64u_len(length):
    def c(v):
        if not isinstance(v, str):
            return "ENCODING_INVALID"
        b = b64u_decode(v)
        return None if b is not None and len(b) == length else "ENCODING_INVALID"
    return c


def _str(check=None, code="SCHEMA_INVALID"):
    def c(v):
        if not isinstance(v, str):
            return code
        if check is not None and not check(v):
            return code
        return None
    return c


def _id_check(f):
    return lambda v: None if f(v) else "ID_INVALID"


def _bool(v):
    return None if isinstance(v, bool) else "SCHEMA_INVALID"


def _sorted_unique(elems):
    for i in range(1, len(elems)):
        a, b = elems[i - 1], elems[i]
        if type(a) is str and type(b) is str or _is_int(a) and _is_int(b):
            if a >= b:
                return False
        else:
            return False
    return True


def _arr(elem, max_len=None, sorted_unique=False):
    def c(v):
        if not isinstance(v, list):
            return "SCHEMA_INVALID"
        if max_len is not None and len(v) > max_len:
            return "SCHEMA_INVALID"
        seen = []
        for e in v:
            r = elem(e)
            if r is not None:
                return r
            if isinstance(e, (str, int)) and not isinstance(e, bool):
                seen.append(e)
        if sorted_unique and not _sorted_unique(seen):
            return "SCHEMA_INVALID"
        return None
    return c


def _null_or(c):
    return lambda v: None if v is None else c(v)


def _obj(fields, required_all=True):
    spec = dict(fields)
    order = sorted(spec.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))

    def c(v):
        if not isinstance(v, dict):
            return "SCHEMA_INVALID"
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        for k in keys:
            chk = spec.get(k)
            if chk is None:
                return "SCHEMA_INVALID"
            r = chk(v[k])
            if r is not None:
                return r
        if required_all:
            for k in spec:
                if k not in v:
                    return "SCHEMA_INVALID"
        return None
    return c


def _scan_reserved(v):
    if not isinstance(v, (dict, list)):
        return False
    if isinstance(v, list):
        return any(_scan_reserved(e) for e in v)
    for k in v:
        if k in RESERVED_FIELD_NAMES:
            return True
        if _scan_reserved(v[k]):
            return True
    return False


def _body_check(inner):
    def c(v):
        if not isinstance(v, dict):
            return "SCHEMA_INVALID"
        if _scan_reserved(v):
            return "DELEGATION_FORBIDDEN"
        return inner(v)
    return c


# ---------- Scalar object types ----------

vPublicKey = _obj([
    ("id", _id_check(is_key_id)),
    ("public_key", _b64u_len(32)),
])

vProof = _obj([
    ("kid", _id_check(is_key_id)),
    ("signature", _b64u_len(64)),
])


def vProofs(v):
    if not isinstance(v, list) or len(v) < 1 or len(v) > 16:
        return "SCHEMA_INVALID"
    kids = []
    for e in v:
        c = vProof(e)
        if c is not None:
            return c
        kids.append(e["kid"])
    for i in range(1, len(kids)):
        if kids[i - 1] >= kids[i]:
            return "SCHEMA_INVALID"
    return None


def _signed(inner):
    return _obj([
        ("body", _body_check(inner)),
        ("proofs", vProofs),
    ])


vCutover = _null_or(_obj([
    ("log_hash", _hash),
    ("seq", _counter),
]))


def root_document_check(development=False):
    return _obj([
        ("control_key", vPublicKey),
        ("created_at", _seconds),
        ("cutover", vCutover),
        ("epoch", _counter),
        ("origin", lambda v: None if is_origin(v, development) else "SCHEMA_INVALID"),
        ("previous", _hash_or_null),
        ("registrar_key", vPublicKey),
        ("root", _id_check(is_root_id)),
        ("service_key", vPublicKey),
        ("status_slots", one_of(STATUS_SLOTS)),
        ("v", _version),
    ])


vRootDocument = root_document_check(False)

vHumanBinding = _obj([
    ("agent_key", vPublicKey),
    ("assurance", one_of("operator-attested")),
    ("consent", one_of("agent-accountability-v1")),
    ("did", _id_check(is_did)),
    ("expires_at", _seconds),
    ("human_key", vPublicKey),
    ("id", _id_check(is_binding_id)),
    ("issued_at", _seconds),
    ("principal_id", _id_check(is_principal_id)),
    ("previous", _hash_or_null),
    ("registrar_epoch", _counter),
    ("root", _id_check(is_root_id)),
    ("v", _version),
])

vGatewayBinding = _obj([
    ("caller_jkt", _b64u_len(32)),
    ("gateway", _id_check(is_gateway_id)),
    ("sub", _id_check(is_sub_id)),
    ("tenant_id", _id_check(is_tenant_id)),
])


def vGatewayBindings(v):
    if not isinstance(v, list) or len(v) > MAX_GATEWAY_BINDINGS:
        return "SCHEMA_INVALID"
    prev = None
    for e in v:
        c = vGatewayBinding(e)
        if c is not None:
            return c
        cur = (e["gateway"], e["tenant_id"], e["sub"])
        if prev is not None:
            for i in range(3):
                if cur[i] < prev[i]:
                    return "SCHEMA_INVALID"
                if cur[i] > prev[i]:
                    break
                if i == 2:
                    return "SCHEMA_INVALID"  # duplicate tuple
        prev = cur
    return None


vAgentCard = _obj([
    ("binding_hash", _hash),
    ("capabilities_hash", _hash),
    ("did", _id_check(is_did)),
    ("expires_at", _seconds),
    ("gateway_bindings", vGatewayBindings),
    ("human_principal", _id_check(is_principal_id)),
    ("id", _id_check(is_card_id)),
    ("issued_at", _seconds),
    ("key", vPublicKey),
    ("key_epoch", _counter),
    ("not_before", _seconds),
    ("previous", _hash_or_null),
    ("root", _id_check(is_root_id)),
    ("status_index", _int_in(0, STATUS_SLOTS - 1)),
    ("v", _version),
])

vCapabilities = _obj([
    ("capabilities", _arr(
        lambda v: None if isinstance(v, str) and CAP_RE.match(v) else "SCHEMA_INVALID",
        max_len=MAX_CAPABILITIES, sorted_unique=True)),
    ("v", _version),
])

vRotation = _obj([
    ("did", _id_check(is_did)),
    ("expires_at", _seconds),
    ("from_epoch", _counter),
    ("issued_at", _seconds),
    ("new_card_hash", _hash),
    ("new_key", vPublicKey),
    ("nonce", _id_check(is_nonce)),
    ("old_card_hash", _hash),
    ("old_key_id", _id_check(is_key_id)),
    ("root", _id_check(is_root_id)),
    ("to_epoch", _counter),
    ("v", _version),
])

_vEnroll = _obj([("binding", _signed(vHumanBinding)), ("kind", one_of("binding.enroll"))])
_vIssue = _obj([("card", _signed(vAgentCard)), ("kind", one_of("card.issue"))])
_vRenew = _obj([
    ("binding", _signed(vHumanBinding)),
    ("card", _signed(vAgentCard)),
    ("kind", one_of("binding.renew")),
])
_vRotate = _obj([
    ("card", _signed(vAgentCard)),
    ("kind", one_of("card.rotate")),
    ("rotation", _signed(vRotation)),
])
_vRevoke = _obj([
    ("id", lambda v: None if isinstance(v, str) and (
        is_did(v) or is_binding_id(v) or is_card_id(v)) else "ID_INVALID"),
    ("kind", one_of("revoke")),
    ("reason", one_of("COMPROMISE", "WITHDRAWN", "RETIRED", "ADMINISTRATIVE")),
    ("target", one_of("agent", "binding", "card")),
])
_vRotateRoot = _obj([("document", _signed(vRootDocument)), ("kind", one_of("root.rotate"))])
_vFreezeRoot = _obj([
    ("kind", one_of("root.freeze")),
    ("reason", one_of("COMPROMISE", "ADMINISTRATIVE")),
])

_ACTION_CHECKS = {
    "binding.enroll": _vEnroll,
    "card.issue": _vIssue,
    "binding.renew": _vRenew,
    "card.rotate": _vRotate,
    "revoke": _vRevoke,
    "root.rotate": _vRotateRoot,
    "root.freeze": _vFreezeRoot,
}


def action_check(v):
    if not isinstance(v, dict):
        return "SCHEMA_INVALID"
    c = _ACTION_CHECKS.get(v.get("kind"))
    return c(v) if c else "SCHEMA_INVALID"


vCommandBody = _obj([
    ("action", action_check),
    ("actor", _id_check(is_key_id)),
    ("expected_revision", _counter),
    ("expires_at", _seconds),
    ("issued_at", _seconds),
    ("op_id", _id_check(is_op_id)),
    ("root", _id_check(is_root_id)),
    ("subject", lambda v: None if is_did(v) or is_root_id(v) else "ID_INVALID"),
    ("v", _version),
])
vCommand = _signed(vCommandBody)

_vResolveQ = _obj([
    ("card_id", _null_or(_id_check(is_card_id))),
    ("did", _id_check(is_did)),
    ("kind", one_of("resolve")),
])
_vReceiptQ = _obj([
    ("kind", one_of("receipt")),
    ("op_id", _id_check(is_op_id)),
])
_vExportQ = _obj([
    ("after_revision", _counter),
    ("did", _id_check(is_did)),
    ("kind", one_of("export")),
    ("limit", _int_in(1, MAX_PAGE)),
])

_QUERY_CHECKS = {"resolve": _vResolveQ, "receipt": _vReceiptQ, "export": _vExportQ}


def query_kind_check(v):
    if not isinstance(v, dict):
        return "SCHEMA_INVALID"
    c = _QUERY_CHECKS.get(v.get("kind"))
    return c(v) if c else "SCHEMA_INVALID"


vQueryBody = _obj([
    ("actor", _id_check(is_key_id)),
    ("expires_at", _seconds),
    ("issued_at", _seconds),
    ("query", query_kind_check),
    ("query_id", _id_check(is_query_id)),
    ("root", _id_check(is_root_id)),
    ("v", _version),
])
vQuery = _signed(vQueryBody)

vAgentRecord = _obj([
    ("binding_hash", _hash),
    ("current_card_hash", _hash_or_null),
    ("current_key", vPublicKey),
    ("did", _id_check(is_did)),
    ("key_epoch", _counter),
    ("revision", _counter),
    ("root", _id_check(is_root_id)),
    ("state", one_of("enrolled", "active", "revoked")),
    ("v", _version),
])

EVENT_KINDS = (
    "RootCreated", "RootRotated", "RootFrozen", "BindingEnrolled",
    "BindingRenewed", "CardIssued", "CardRotated", "CardRevoked",
    "AgentRevoked", "BindingRevoked",
)
_EVENT_KIND_SET = frozenset(EVENT_KINDS)


def is_event_kind(s):
    return s in _EVENT_KIND_SET


def _event_kind(v):
    return None if isinstance(v, str) and is_event_kind(v) else "SCHEMA_INVALID"


vReceiptBody = _obj([
    ("allocated", _null_or(_int_in(0, STATUS_SLOTS - 1))),
    ("event_hash", _hash),
    ("kind", _event_kind),
    ("objects", _arr(_hash, sorted_unique=True)),
    ("op_id", _id_check(is_op_id)),
    ("request_hash", _hash),
    ("root", _id_check(is_root_id)),
    ("seq", _counter),
    ("v", _version),
])
vReceipt = _signed(vReceiptBody)

vSignedRootDocument = _signed(vRootDocument)
vSignedHumanBinding = _signed(vHumanBinding)
vSignedAgentCard = _signed(vAgentCard)
vSignedRotation = _signed(vRotation)

vIdentityBundle = _obj([
    ("binding", vSignedHumanBinding),
    ("card", vSignedAgentCard),
    ("prior_card", _null_or(vSignedAgentCard)),
    ("receipt", vReceipt),
    ("roots", _arr(vSignedRootDocument, max_len=MAX_ROOT_EPOCHS)),
    ("rotation", _null_or(vSignedRotation)),
    ("v", _version),
])

vAuditEventBody = _obj([
    ("allocated", _null_or(_int_in(0, STATUS_SLOTS - 1))),
    ("invalidated", _arr(_nonneg_int, sorted_unique=True)),
    ("kind", _event_kind),
    ("objects", _arr(_hash, sorted_unique=True)),
    ("prev", _hash),
    ("request_hash", _hash),
    ("root", _id_check(is_root_id)),
    ("root_epoch", _counter),
    ("root_state", one_of("active", "frozen")),
    ("seq", _counter),
    ("time", _seconds),
    ("v", _version),
])
vAuditEvent = _signed(vAuditEventBody)


def _bits(v):
    if not isinstance(v, str):
        return "ENCODING_INVALID"
    b = b64u_decode(v)
    return None if b is not None and len(b) == 16384 else "ENCODING_INVALID"


vStatusBody = _obj([
    ("bits", _bits),
    ("expires_at", _seconds),
    ("issued_at", _seconds),
    ("log_hash", _hash),
    ("root", _id_check(is_root_id)),
    ("root_epoch", _counter),
    ("seq", _counter),
    ("slots", one_of(STATUS_SLOTS)),
    ("state", one_of("active", "frozen")),
    ("v", _version),
])
vStatus = _signed(vStatusBody)

vFreshRequest = _obj([
    ("challenge", _id_check(is_nonce)),
    ("v", _version),
])

vFreshBody = _obj([
    ("challenge", _id_check(is_nonce)),
    ("checked_at", _seconds),
    ("log_hash", _hash),
    ("root", _id_check(is_root_id)),
    ("seq", _counter),
    ("status_hash", _hash),
    ("valid_until", _seconds),
    ("v", _version),
])
vFresh = _signed(vFreshBody)

vFreshReply = _obj([
    ("fresh", vFresh),
    ("status", vStatus),
    ("v", _version),
])

vLogPage = _obj([
    ("events", _arr(vAuditEvent, max_len=MAX_PAGE)),
    ("next_after", _null_or(_counter)),
    ("v", _version),
])

vRootHistoryReply = _obj([
    ("documents", _arr(vSignedRootDocument, max_len=MAX_DOC_PAGE)),
    ("next_after", _null_or(_counter)),
    ("v", _version),
])

vMutationReply = _obj([
    ("receipt", vReceipt),
    ("record", _null_or(vAgentRecord)),
    ("v", _version),
])

vResolveReply = _obj([
    ("bundle", _null_or(vIdentityBundle)),
    ("record", vAgentRecord),
    ("v", _version),
])

vExportRecord = _obj([
    ("command", vCommand),
    ("receipt", vReceipt),
    ("revision", _counter),
])

vExportReply = _obj([
    ("next_revision", _null_or(_counter)),
    ("records", _arr(vExportRecord, max_len=MAX_PAGE)),
    ("v", _version),
])

vErrorReply = _obj([
    ("error", _obj([
        ("code", lambda v: None if isinstance(v, str) and re.match(r"^[A-Z_]{2,40}$", v) else "SCHEMA_INVALID"),
        ("retryable", _bool),
    ])),
    ("v", _version),
])

vHealthReply = _obj([
    ("status", one_of("alive")),
    ("v", _version),
])

vReadinessReply = _obj([
    ("code", _str()),
    ("status", one_of("ready", "not_ready")),
    ("v", _version),
])

vFrontier = _obj([
    ("log_hash", _hash),
    ("root", _id_check(is_root_id)),
    ("root_epoch", _counter),
    ("seq", _counter),
])

# ---------- Config types ----------

vRootPin = _obj([
    ("control_fingerprint", _hash),
    ("enabled", _bool),
    ("genesis_hash", _hash),
    ("min_epoch", _counter),
    ("origin", _str(lambda s: is_origin(s, True))),
    ("root", _id_check(is_root_id)),
])

vClientConfig = _obj([
    ("cache_dir", _str()),
    ("clock_max_error_s", one_of(2)),
    ("fresh_max_age_s", one_of(5)),
    ("key_refs", _arr(_obj([
        ("kid", _id_check(is_key_id)),
        ("path", _str()),
    ]), max_len=64)),
    ("mode", one_of("production", "development")),
    ("read_max_age_s", one_of(60)),
    ("roots", _arr(vRootPin, max_len=32)),
    ("v", _version),
])

vServerConfig = _obj([
    ("max_agents", one_of(MAX_AGENTS)),
    ("private_data_key_binding", _str(lambda s: ROLE_RE.match(s) is not None)),
    ("production", _bool),
    ("public_fresh_per_minute", one_of(120)),
    ("public_get_per_minute", one_of(120)),
    ("revocation_reserve_per_minute", one_of(60)),
    ("root", _id_check(is_root_id)),
    ("root_do_binding", _str(lambda s: ROLE_RE.match(s) is not None)),
    ("root_document_path", _str()),
    ("service_secret_binding", _str(lambda s: ROLE_RE.match(s) is not None)),
    ("status_slots", one_of(STATUS_SLOTS)),
    ("write_per_actor_per_minute", one_of(30)),
    ("v", _version),
])

vKeyFile = _obj([
    ("algorithm", one_of("Ed25519")),
    ("kid", _id_check(is_key_id)),
    ("seed_b64u", _b64u_len(32)),
    ("v", _version),
])

vExportSummary = _obj([
    ("count", _nonneg_int),
    ("hash", _hash),
    ("next_revision", _null_or(_counter)),
    ("path", _str()),
    ("v", _version),
])

vDoctorReply = _obj([
    ("checks", _obj([
        ("cache", one_of("usable", "stale", "forked")),
        ("capacity", one_of("ok", "warning", "full")),
        ("clock", one_of("ok", "unsafe")),
        ("root", one_of("trusted", "untrusted")),
        ("storage", one_of("ok", "unavailable")),
    ])),
    ("ready", _bool),
    ("v", _version),
])

vMigrationDescriptor = _obj([
    ("expected_events", _counter),
    ("from", _nonneg_int),
    ("source_head", _hash),
    ("to", _nonneg_int),
    ("v", _version),
])

# ---------- Adapter types (§10) ----------

vHeraldBindingRef = _obj([
    ("card_hash", _hash),
    ("card_id", _str()),
    ("source", _str(lambda s: SOURCE_RE.match(s) is not None)),
])

vHeraldCheck = _obj([
    ("binding", vHeraldBindingRef),
    ("caller_jkt", _b64u_len(32)),
    ("challenge", _str()),
    ("mode", one_of("fresh", "bounded_cache")),
    ("now", _seconds),
    ("sub", _str()),
    ("tenant_id", _str()),
    ("v", _version),
])

vHeraldObservation = _obj([
    ("caller_jkt", _b64u_len(32)),
    ("card_hash", _hash),
    ("challenge", _str()),
    ("checked_at", _seconds),
    ("evidence_hash", _hash),
    ("status", one_of("active", "revoked")),
    ("sub", _str()),
    ("v", _version),
])

# ---------- Dispatcher ----------

VALIDATORS = {
    "PublicKey": vPublicKey,
    "Proof": vProof,
    "RootDocument": vRootDocument,
    "HumanBinding": vHumanBinding,
    "GatewayBinding": vGatewayBinding,
    "AgentCard": vAgentCard,
    "Capabilities": vCapabilities,
    "Rotation": vRotation,
    "Command": vCommand,
    "Query": vQuery,
    "AgentRecord": vAgentRecord,
    "Receipt": vReceipt,
    "IdentityBundle": vIdentityBundle,
    "AuditEvent": vAuditEvent,
    "Status": vStatus,
    "FreshRequest": vFreshRequest,
    "Fresh": vFresh,
    "FreshReply": vFreshReply,
    "LogPage": vLogPage,
    "RootHistoryReply": vRootHistoryReply,
    "MutationReply": vMutationReply,
    "ResolveReply": vResolveReply,
    "ExportReply": vExportReply,
    "ErrorReply": vErrorReply,
    "HealthReply": vHealthReply,
    "ReadinessReply": vReadinessReply,
    "Frontier": vFrontier,
    "RootPin": vRootPin,
    "ClientConfig": vClientConfig,
    "ServerConfig": vServerConfig,
    "KeyFile": vKeyFile,
    "ExportSummary": vExportSummary,
    "DoctorReply": vDoctorReply,
    "MigrationDescriptor": vMigrationDescriptor,
    "HeraldCheck": vHeraldCheck,
    "HeraldObservation": vHeraldObservation,
    "SignedRootDocument": vSignedRootDocument,
    "SignedHumanBinding": vSignedHumanBinding,
    "SignedAgentCard": vSignedAgentCard,
    "SignedRotation": vSignedRotation,
}


def validate(type_name, value):
    c = VALIDATORS.get(type_name)
    if c is None:
        raise ValueError("unknown wire type " + type_name)
    return c(value)
