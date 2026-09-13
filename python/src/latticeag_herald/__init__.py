"""latticeag-herald — Herald sovereign agent identity registry, Python library.

Canonical JSON (RFC 8785), domain-separated tagged digests, strict Ed25519,
closed wire schemas, proof sets, offline verify()/verify_history(), and the
HTTP client wrappers defined by the spec.
"""

from .b64u import b64u_decode, b64u_decode_exact, b64u_encode
from .client import HeraldClient, HeraldHttpError
from .digest import D, TAGS, digest, digest_bytes, is_tag, sha256_bytes, sha256_hex
from .ed25519 import (
    decode_point, ed25519_sign, ed25519_verify, encode_point, is_canonical_scalar,
    is_small_order, keygen, public_key_from_seed, public_key_valid,
)
from .errors import ERROR_HTTP, RETRYABLE, HeraldError, deny, error_body, is_retryable, status_for
from .history import verify_history
from .ids import (
    agent_id_of_did, did_parts, is_agent_id, is_binding_id, is_card_id, is_did,
    is_gateway_id, is_hash, is_key_id, is_nonce, is_op_id, is_origin,
    is_principal_id, is_query_id, is_root_id, is_sub_id, is_tenant_id,
    new_challenge, new_id,
)
from .jcs import canonicalize, canonicalize_text
from .jkt import jkt
from .proofs import sign_body, signed, signed_body_hash, verify_proof_set
from .schema import VALIDATORS, validate
from .strictjson import (
    LIMITS_DOCUMENT_HISTORY, LIMITS_EXPORT, LIMITS_ORDINARY, LIMITS_RESPONSE,
    Limits, is_counter, parse_json_strict,
)
from .verify import verify, verify_with_context

__all__ = [name for name in dir() if not name.startswith("_")]
