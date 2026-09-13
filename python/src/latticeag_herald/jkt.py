"""JWK thumbprint (RFC 7638) over the OKP public-key view used by the
adapter: jkt = b64u(SHA256(J({"crv":"Ed25519","kty":"OKP","x":<b64u>})))."""

import hashlib

from .jcs import canonicalize
from .b64u import b64u_encode


def jkt(public_key_b64u):
    return b64u_encode(hashlib.sha256(canonicalize(
        {"crv": "Ed25519", "kty": "OKP", "x": public_key_b64u})).digest())
