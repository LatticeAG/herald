"""Spec §8.2 error-code → HTTP status table and retryable set."""

ERROR_HTTP = {
    "JSON_INVALID": 400, "DUPLICATE_KEY": 400, "SCHEMA_INVALID": 400,
    "NUMBER_INVALID": 400, "ID_INVALID": 400, "ENCODING_INVALID": 400,
    "VERSION_UNSUPPORTED": 400, "METHOD_TARGET_INVALID": 400,
    "SIGNATURE_INVALID": 401, "PROOF_SET_INVALID": 401,
    "QUERY_EXPIRED": 401, "COMMAND_EXPIRED": 401, "NOT_YET_VALID": 401,
    "FORBIDDEN": 403, "ROOT_FROZEN": 403, "BINDING_REVOKED": 403,
    "AGENT_REVOKED": 403,
    "ROOT_UNKNOWN": 404, "NOT_FOUND": 404, "ROUTE_UNKNOWN": 404,
    "METHOD_NOT_ALLOWED": 405,
    "REVISION_CONFLICT": 409, "IDEMPOTENCY_CONFLICT": 409, "SLOT_USED": 409,
    "ID_USED": 409, "KEY_REUSED": 409, "ALREADY_REVOKED": 409,
    "STATE_TRANSITION": 409, "PREDECESSOR_MISMATCH": 409, "EPOCH_MISMATCH": 409,
    "TOO_LARGE": 413,
    "INTERVAL_INVALID": 422, "BINDING_MISMATCH": 422, "HOLDER_MISMATCH": 422,
    "CAPABILITIES_MISMATCH": 422, "ROTATION_MISMATCH": 422,
    "DELEGATION_FORBIDDEN": 422,
    "RATE_LIMITED": 429, "CAPACITY": 429,
    "UNAVAILABLE": 503, "STORAGE_BUSY": 503, "CLOCK_UNSAFE": 503,
    "INTEGRITY_FAILURE": 503,
}

RETRYABLE = frozenset(("RATE_LIMITED", "UNAVAILABLE", "STORAGE_BUSY"))


def status_for(code):
    return ERROR_HTTP.get(code, 400)


def is_retryable(code):
    return code in RETRYABLE


def error_body(code):
    return {"v": 1, "error": {"code": code, "retryable": is_retryable(code)}}


class HeraldError(Exception):
    """Carries a spec error code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def deny(code):
    return {"v": 1, "decision": "deny", "code": code}
