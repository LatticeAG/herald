"""Proof-set verification (spec §3, §5): proofs are sorted ascending by kid,
unique, and must equal exactly the required signer set. Each proof signs
the 32 raw bytes of D(tag, body).
"""

import copy

from .b64u import b64u_decode, b64u_encode
from .digest import digest, digest_bytes
from .ed25519 import ed25519_sign, ed25519_verify


def verify_proof_set(tag, env, expected_kids, key_bytes):
    """Check the proof set equals expected_kids (compared as a set after dedup
    of expected values), then verify every signature.
    Returns None on success, or "PROOF_SET_INVALID" / "SIGNATURE_INVALID"."""
    expected = sorted(set(expected_kids))
    actual = [p["kid"] for p in env["proofs"]]
    if actual != sorted(actual) or len(set(actual)) != len(actual):
        return "PROOF_SET_INVALID"
    if actual != expected:
        return "PROOF_SET_INVALID"
    d = digest_bytes(tag, env["body"])
    for p in env["proofs"]:
        pk = key_bytes(p["kid"])
        sig = b64u_decode(p["signature"])
        if pk is None or sig is None or len(sig) != 64:
            return "SIGNATURE_INVALID"
        if not ed25519_verify(pk, d, sig):
            return "SIGNATURE_INVALID"
    return None


def sign_body(tag, body, kid, seed):
    d = digest_bytes(tag, body)
    return {"kid": kid, "signature": b64u_encode(ed25519_sign(seed, d))}


def signed(tag, body, signers):
    """Build a signed envelope from a body and a list of (kid, seed) pairs."""
    seen = set()
    proofs = []
    for kid, seed in sorted(signers, key=lambda s: s[0]):
        if kid in seen:
            continue
        seen.add(kid)
        proofs.append(sign_body(tag, body, kid, seed))
    return {"body": copy.deepcopy(body), "proofs": proofs}


def signed_body_hash(tag, env):
    return digest(tag, env["body"])
