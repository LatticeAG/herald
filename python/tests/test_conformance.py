"""Conformance vectors (P0 parser/JCS + verifier + history) replayed in Python
against the normative fixtures.json. Byte-exactness checks ensure the Python
implementation is interchangeable with the TypeScript core.
"""

import json
from pathlib import Path

import pytest

from latticeag_herald import (
    b64u_decode, b64u_encode, canonicalize, canonicalize_text, digest,
    digest_bytes, ed25519_sign, ed25519_verify, is_counter, jkt,
    parse_json_strict, public_key_from_seed, signed, verify,
    verify_history, verify_with_context,
)

FX = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "fixtures.json").read_text())
T = 2000000000
R = "hr_" + "0" * 20 + "1"


def seed(n):
    return bytes([n]) * 32


def kid(n):
    return "hk_" + str(n).zfill(21)


def ctx(**over):
    c = {
        "pins": FX["CLIENT_CONFIG"]["roots"], "frontiers": [],
        "known_revocations": [], "received_age_s": 0,
        "challenge_outstanding": None, "challenge_consumed": False,
    }
    c.update(over)
    return c


def v(bundle, status, fresh=None, challenge=None, now=T,
      mode="bounded_cache", c=None):
    return verify({"bundle": bundle, "status": status, "fresh": fresh,
                   "challenge": challenge, "now": now, "mode": mode},
                  c if c is not None else ctx())


def bits(*idx):
    raw = bytearray(16384)
    for i in idx:
        raw[i // 8] |= 1 << (i % 8)
    return b64u_encode(bytes(raw))


# ---------- Byte-exactness against the normative fixture ----------

def test_jcs_matches_fixture_encoding():
    # The fixture's canonical form was emitted by the normative generator's
    # json.dumps(sort_keys=True, separators) — for the fixture alphabet that
    # is identical to JCS.
    for name in ("ROOT", "B", "C"):
        assert canonicalize_text(FX[name]) == json.dumps(
            FX[name], sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def test_digests_match_fixture_hashes():
    # Card/binding cross-links inside the normative fixture are tagged digests.
    assert FX["C"]["binding_hash"] == digest("BINDING", FX["B"])
    assert digest("CARD", FX["C"]) in FX["E3"]["body"]["objects"]
    assert FX["ALLOW"]["evidence_hash"] == digest("EVIDENCE", {
        "bundle": FX["BUNDLE"], "status": FX["ST"], "fresh": None})


def test_ed25519_rfc8032_vectors():
    # RFC 8032 TEST 1.
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60")
    pk_expected = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a" "0ee172f3daa62325af021a68f707511a")
    assert public_key_from_seed(sk) == pk_expected
    sig = ed25519_sign(sk, b"")
    assert sig.hex() == (
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b")
    assert ed25519_verify(pk_expected, b"", sig)


def test_ed25519_cross_impl_fixture_key():
    # The fixture keys were produced by `cryptography`; our implementation must
    # derive identical public keys.
    for n in range(1, 8):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        ref = Ed25519PrivateKey.from_private_bytes(seed(n)).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert public_key_from_seed(seed(n)) == ref
        assert b64u_encode(ref) == FX["KEYS"][str(n)]["public_key"]


# ---------- P0 parser / canonicalization vectors ----------

def test_tv01_canonical_object_ordering():
    assert canonicalize_text({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    # UTF-16 ordering: "Z"(0x5A) < "e"(0x65); astral sorts by surrogates.
    assert canonicalize_text({"é": 1, "z": 2, "A": 3}) == '{"A":3,"z":2,"é":1}'


def test_tv02_duplicate_key_rejected():
    v, code = parse_json_strict(b'{"a":1,"a":2}')
    assert v is None and code == "DUPLICATE_KEY"


def test_tv03_unsafe_numeric_value():
    for doc in (b'{"a":9007199254740993}', b'{"a":1.5}', b'{"a":1e3}'):
        v, code = parse_json_strict(doc)
        assert v is None and code == "NUMBER_INVALID"


def test_tv04_negative_zero_and_exponent():
    for doc in (b'{"a":-0}', b'{"a":-1}', b'{"a":0.0}'):
        v, code = parse_json_strict(doc)
        assert v is None and code == "NUMBER_INVALID"


def test_tv05_unicode_not_normalized():
    # U+00E9 vs decomposed e+U+0301 are distinct keys — no normalization.
    s1, _ = parse_json_strict(b'"\\u00e9"')
    s2, _ = parse_json_strict(b'"e\\u0301"')
    assert s1 != s2
    assert canonicalize_text({"x": s1}) != canonicalize_text({"x": s2})


def test_tv49_bit_ordering():
    b = b64u_decode(bits(17))
    assert b[17 >> 3] & (1 << (17 % 8))
    assert not (b[16 >> 3] & (1 << (16 % 8)))


# ---------- Verifier vectors ----------

def test_tv08_bounded_live():
    assert v(FX["BUNDLE"], FX["ST"]) == FX["ALLOW"]


def test_tv09_fresh():
    c = ctx(challenge_outstanding=FX["N"])
    r = verify_with_context({"bundle": FX["BUNDLE"], "status": FX["ST"],
                             "fresh": FX["F"], "challenge": FX["N"],
                             "now": T, "mode": "fresh"}, c)
    assert r == FX["ALLOW_FRESH"]
    assert c["challenge_consumed"] is True


def test_tv10_wrong_domain():
    bad_card = {"body": FX["SC"]["body"], "proofs": [
        {"kid": kid(4), "signature": b64u_encode(ed25519_sign(seed(4), digest_bytes("BINDING", FX["SC"]["body"])))},
        {"kid": kid(5), "signature": b64u_encode(ed25519_sign(seed(5), digest_bytes("BINDING", FX["SC"]["body"])))},
    ]}
    r = v({**FX["BUNDLE"], "card": bad_card}, FX["ST"])
    assert r["decision"] == "deny" and r["code"] == "SIGNATURE_INVALID"


def test_tv11_tampered_capabilities():
    card = {**FX["SC"]["body"], "capabilities_hash": "0" * 64}
    r = v({**FX["BUNDLE"], "card": {"body": card, "proofs": FX["SC"]["proofs"]}}, FX["ST"])
    assert r["decision"] == "deny" and r["code"] == "SIGNATURE_INVALID"


def test_tv16_card_expiry_boundary():
    st = signed("STATUS", {**FX["ST"]["body"], "issued_at": T + 3600,
                           "expires_at": T + 3660}, [(kid(2), seed(2))])
    r = v(FX["BUNDLE"], st, now=T + 3600)
    assert r["code"] == "CARD_EXPIRED"


def test_tv21_revoked_card():
    assert v(FX["BUNDLE"], FX["ST_REV"])["code"] == "CARD_REVOKED"


def test_tv22_stale_status():
    assert v(FX["BUNDLE"], FX["ST"], now=T + 60)["code"] == "STATUS_STALE"


def test_tv23_wrong_challenge():
    wrong = "hn_" + "C" * 32
    r = v(FX["BUNDLE"], FX["ST"], FX["F"], wrong, T, "fresh",
          ctx(challenge_outstanding=wrong))
    assert r["code"] == "CHALLENGE_MISMATCH"


def test_tv24_five_second_cutoff():
    r = v(FX["BUNDLE"], FX["ST"], FX["F"], FX["N"], T + 5, "fresh",
          ctx(challenge_outstanding=FX["N"]))
    assert r["code"] == "STATUS_STALE"


def test_tv25_snapshot_rollback():
    c = ctx(frontiers=[{"root": R, "seq": "4",
                      "log_hash": digest("EVENT", FX["E4"]["body"]), "root_epoch": "1"}])
    assert v(FX["BUNDLE"], FX["ST"], c=c)["code"] == "STATUS_ROLLBACK"


def test_tv26_equal_seq_fork():
    c = ctx(frontiers=[{"root": R, "seq": "3",
                      "log_hash": digest("EVENT", FX["E3"]["body"]), "root_epoch": "1"}])
    forked = signed("STATUS", {**FX["ST"]["body"], "log_hash": "f" * 64}, [(kid(2), seed(2))])
    assert v(FX["BUNDLE"], forked, c=c)["code"] == "FORKED"


def test_tv34_frozen_root():
    assert v(FX["BUNDLE"], FX["status_frozen"])["code"] == "ROOT_FROZEN"


def test_tv35_untrusted_root():
    assert v(FX["BUNDLE"], FX["ST"], c=ctx(pins=[]))["code"] == "ROOT_UNTRUSTED"


def test_tv45_history_tamper():
    e3 = {**FX["E3"]["body"], "prev": "0" * 64}
    se3 = signed("EVENT", e3, [(kid(2), seed(2))])
    r = verify_history([FX["E1"], FX["E2"], se3], [FX["SR"]], FX["CLIENT_CONFIG"]["roots"])
    assert r == {"v": 1, "valid": False, "live": False, "code": "EVIDENCE_MISMATCH"}


def test_tv46_history_not_live():
    r = verify_history([FX["E1"], FX["E2"], FX["E3"]], [FX["SR"]], FX["CLIENT_CONFIG"]["roots"])
    assert r == {"v": 1, "valid": True, "live": False,
                 "last_seq": "3", "last_hash": digest("EVENT", FX["E3"]["body"])}


def test_tv56_challenge_single_use():
    c = ctx(challenge_outstanding=FX["N"])
    inp = {"bundle": FX["BUNDLE"], "status": FX["ST"], "fresh": FX["F"],
           "challenge": FX["N"], "now": T, "mode": "fresh"}
    assert verify_with_context(inp, c) == FX["ALLOW_FRESH"]
    assert verify_with_context(inp, c)["code"] == "REPLAY"


def test_tv57_rotated_card():
    assert v(FX["BUNDLE_ROTATED"], FX["ST_ROTATED"]) == FX["ALLOW_ROTATED"]
    assert v(FX["BUNDLE"], FX["ST_ROTATED"])["code"] == "CARD_REVOKED"


def test_tv58_rotation_proof_omission():
    bundle = {**FX["BUNDLE_ROTATED"], "rotation": None, "prior_card": None}
    assert v(bundle, FX["ST_ROTATED"])["code"] == "EVIDENCE_MISMATCH"


def test_tv60_retired_service_key():
    st = signed("STATUS", FX["ST_ROOT"]["body"], [(kid(2), seed(2))])
    pin = {**FX["CLIENT_CONFIG"]["roots"][0], "min_epoch": "2"}
    c = ctx(pins=[pin], frontiers=[{"root": R, "seq": "4",
                                    "log_hash": digest("EVENT", FX["E_ROOT"]["body"]),
                                    "root_epoch": "2"}])
    bundle = {**FX["BUNDLE"], "roots": [FX["SR"], FX["SROOT2"]]}
    assert v(bundle, st, c=c)["code"] == "SIGNATURE_INVALID"
