/**
 * Herald protocol error codes and their wire representation.
 * ErrorReply = {v:1, error:{code, retryable}} — never carries submitted bytes.
 */

export const ERROR_HTTP: Record<string, number> = {
  JSON_INVALID: 400,
  DUPLICATE_KEY: 400,
  SCHEMA_INVALID: 400,
  NUMBER_INVALID: 400,
  ID_INVALID: 400,
  ENCODING_INVALID: 400,
  VERSION_UNSUPPORTED: 400,
  METHOD_TARGET_INVALID: 400,
  SIGNATURE_INVALID: 401,
  PROOF_SET_INVALID: 401,
  QUERY_EXPIRED: 401,
  COMMAND_EXPIRED: 401,
  NOT_YET_VALID: 401,
  FORBIDDEN: 403,
  ROOT_FROZEN: 403,
  BINDING_REVOKED: 403,
  AGENT_REVOKED: 403,
  ROOT_UNKNOWN: 404,
  NOT_FOUND: 404,
  ROUTE_UNKNOWN: 404,
  METHOD_NOT_ALLOWED: 405,
  REVISION_CONFLICT: 409,
  IDEMPOTENCY_CONFLICT: 409,
  SLOT_USED: 409,
  ID_USED: 409,
  KEY_REUSED: 409,
  ALREADY_REVOKED: 409,
  STATE_TRANSITION: 409,
  PREDECESSOR_MISMATCH: 409,
  EPOCH_MISMATCH: 409,
  TOO_LARGE: 413,
  INTERVAL_INVALID: 422,
  BINDING_MISMATCH: 422,
  HOLDER_MISMATCH: 422,
  CAPABILITIES_MISMATCH: 422,
  ROTATION_MISMATCH: 422,
  DELEGATION_FORBIDDEN: 422,
  RATE_LIMITED: 429,
  CAPACITY: 429,
  UNAVAILABLE: 503,
  STORAGE_BUSY: 503,
  CLOCK_UNSAFE: 503,
  INTEGRITY_FAILURE: 503,
  // Local verifier codes (never emitted by the HTTP surface)
  ROOT_UNTRUSTED: 0,
  ROOT_ROLLBACK: 0,
  STATUS_ROLLBACK: 0,
  FORKED: 0,
  STATUS_STALE: 0,
  CHALLENGE_MISMATCH: 0,
  REPLAY: 0,
  CARD_EXPIRED: 0,
  BINDING_EXPIRED: 0,
  CARD_REVOKED: 0,
  EVIDENCE_MISMATCH: 0,
};

const RETRYABLE = new Set(["RATE_LIMITED", "UNAVAILABLE", "STORAGE_BUSY"]);

export function isRetryable(code: string): boolean {
  return RETRYABLE.has(code);
}

export class HeraldError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "HeraldError";
    this.code = code;
  }
  get httpStatus(): number {
    return ERROR_HTTP[this.code] ?? 500;
  }
  get retryable(): boolean {
    return RETRYABLE.has(this.code);
  }
}

export function err(code: string): HeraldError {
  return new HeraldError(code);
}

export function errorReply(code: string): { v: 1; error: { code: string; retryable: boolean } } {
  return { v: 1, error: { code, retryable: isRetryable(code) } };
}

/** Local-verifier deny result constructor. */
export function deny(code: string): { v: 1; decision: "deny"; code: string } {
  return { v: 1, decision: "deny", code };
}
