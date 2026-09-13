"""Normative conformance fixture generator for Herald (spec section 8.1/8.2).

This module is the executable form of the specification's normative fixture
constructor. All keys are public deterministic TEST-ONLY values; production
deployments must refuse them (the core library ships the compiled blocklist).

Run:  PYTHONPATH=src python -m latticeag_herald.fixtures > fixtures.json
"""

import base64
import copy
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def ident(prefix, n):
    return prefix + "_" + str(n).zfill(21)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def J(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def D(tag, value):
    return hashlib.sha256(("HERALD/" + tag + "/1\0").encode() + J(value)).hexdigest()


KEYS = {}
for n in range(1, 8):
    sk = Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    KEYS[n] = (sk, {"id": ident("hk", n), "public_key": b64(raw)})


def signed(tag, body, signers):
    digest = bytes.fromhex(D(tag, body))
    proofs = [{"kid": KEYS[n][1]["id"], "signature": b64(KEYS[n][0].sign(digest))}
              for n in sorted(set(signers))]
    return {"body": copy.deepcopy(body), "proofs": proofs}


def bits(indices):
    raw = bytearray(16384)
    for i in indices:
        raw[i // 8] |= 1 << (i % 8)
    return b64(raw)


T = 2000000000
R = ident("hr", 1)
A = "did:herald:" + R + ":" + ident("ha", 1)
P = ident("hp", 1)
N = "hn_" + "A" * 32
G = ident("lsg", 1)
TEN = ident("ltn", 1)
SUB = ident("lsu", 1)
ROOT = {"v": 1, "root": R, "epoch": "1", "previous": None,
        "control_key": KEYS[1][1], "service_key": KEYS[2][1],
        "registrar_key": KEYS[3][1], "origin": "https://registry.example.test",
        "created_at": T - 100, "status_slots": 131072, "cutover": None}
SR = signed("ROOT", ROOT, [1, 2, 3])
B = {"v": 1, "id": ident("hb", 1), "root": R, "did": A, "principal_id": P,
     "previous": None, "human_key": KEYS[4][1], "agent_key": KEYS[5][1], "registrar_epoch": "1",
     "assurance": "operator-attested", "consent": "agent-accountability-v1",
     "issued_at": T - 10, "expires_at": T + 2592000}
SB = signed("BINDING", B, [3, 4, 5])
CAP = {"v": 1, "capabilities": ["documents.read"]}


def jkt(n):
    return b64(hashlib.sha256(J({"crv": "Ed25519", "kty": "OKP", "x": KEYS[n][1]["public_key"]})).digest())


C = {"v": 1, "id": ident("hc", 1), "root": R, "did": A, "previous": None,
     "key": KEYS[5][1], "key_epoch": "1", "human_principal": P,
     "binding_hash": D("BINDING", B), "capabilities_hash": D("CAPABILITIES", CAP),
     "gateway_bindings": [{"gateway": G, "tenant_id": TEN, "sub": SUB, "caller_jkt": jkt(5)}],
     "issued_at": T - 10, "not_before": T - 10, "expires_at": T + 3600, "status_index": 17}
SC = signed("CARD", C, [4, 5])


def command(n, actor, revision, action, subject=A):
    return signed("COMMAND", {"v": 1, "root": R, "op_id": ident("ho", n),
        "actor": KEYS[actor][1]["id"], "subject": subject, "expected_revision": str(revision),
        "issued_at": T, "expires_at": T + 60, "action": action}, [actor])


def event(seq, prev, kind, request_hash, objects, allocated=None, invalidated=(), epoch="1", state="active"):
    return signed("EVENT", {"v": 1, "root": R, "seq": str(seq), "prev": prev, "time": T,
        "root_epoch": epoch, "kind": kind, "request_hash": request_hash,
        "objects": sorted(objects), "invalidated": sorted(invalidated),
        "allocated": allocated, "root_state": state}, [2])


def receipt(cmd, ev):
    return signed("RECEIPT", {"v": 1, "root": R, "op_id": cmd["body"]["op_id"],
        "request_hash": D("COMMAND", cmd["body"]), "seq": ev["body"]["seq"],
        "event_hash": D("EVENT", ev["body"]), "kind": ev["body"]["kind"], "objects": ev["body"]["objects"],
        "allocated": ev["body"]["allocated"]}, [2])


E1 = event(1, "0" * 64, "RootCreated", D("ROOT", ROOT), [D("ROOT", ROOT)])
ENROLL = command(1, 3, 0, {"kind": "binding.enroll", "binding": SB})
E2 = event(2, D("EVENT", E1["body"]), "BindingEnrolled", D("COMMAND", ENROLL["body"]), [D("BINDING", B)])
ER = receipt(ENROLL, E2)
ISSUE = command(2, 5, 1, {"kind": "card.issue", "card": SC})
E3 = event(3, D("EVENT", E2["body"]), "CardIssued", D("COMMAND", ISSUE["body"]), [D("CARD", C)], 17)
CR = receipt(ISSUE, E3)
REC1 = {"v": 1, "root": R, "did": A, "revision": "1", "key_epoch": "1",
        "state": "enrolled", "binding_hash": D("BINDING", B), "current_card_hash": None, "current_key": KEYS[5][1]}
REC2 = dict(REC1, revision="2", state="active", current_card_hash=D("CARD", C))
BUNDLE = {"v": 1, "roots": [SR], "binding": SB, "card": SC, "receipt": CR, "prior_card": None, "rotation": None}


def status(ev=E3, revoked=(), state="active", at=T):
    return signed("STATUS", {"v": 1, "root": R, "root_epoch": "1", "seq": ev["body"]["seq"],
        "log_hash": D("EVENT", ev["body"]), "state": state, "issued_at": at,
        "expires_at": at + 60, "slots": 131072, "bits": bits(revoked)}, [2])


ST = status()
F = signed("FRESH", {"v": 1, "root": R, "challenge": N, "status_hash": D("STATUS", ST["body"]),
    "seq": "3", "log_hash": D("EVENT", E3["body"]), "checked_at": T, "valid_until": T + 5}, [2])
FRESH_REPLY = {"v": 1, "fresh": F, "status": ST}
C2 = copy.deepcopy(C)
C2.update(id=ident("hc", 2), previous=D("CARD", C), key=KEYS[6][1], key_epoch="2", status_index=18)
C2["gateway_bindings"][0]["caller_jkt"] = jkt(6)
SC2 = signed("CARD", C2, [4, 6])
ROT = {"v": 1, "root": R, "did": A, "from_epoch": "1", "to_epoch": "2",
       "old_card_hash": D("CARD", C), "new_card_hash": D("CARD", C2),
       "old_key_id": KEYS[5][1]["id"], "new_key": KEYS[6][1], "issued_at": T, "expires_at": T + 60, "nonce": N}
SROT = signed("ROTATION", ROT, [4, 5, 6])
ROTATE = command(3, 5, 2, {"kind": "card.rotate", "rotation": SROT, "card": SC2})
E4 = event(4, D("EVENT", E3["body"]), "CardRotated", D("COMMAND", ROTATE["body"]), [D("CARD", C2), D("ROTATION", ROT)], 18, [17])
RR = receipt(ROTATE, E4)
REC3 = dict(REC2, revision="3", key_epoch="2", current_key=KEYS[6][1], current_card_hash=D("CARD", C2))
BUNDLE_ROTATED = dict(BUNDLE, card=SC2, receipt=RR, prior_card=SC, rotation=SROT)
ST_ROTATED = status(E4, [17])
B2 = dict(B, id=ident("hb", 2), previous=D("BINDING", B), issued_at=T, expires_at=T + 2592100)
SB2 = signed("BINDING", B2, [3, 4, 5])
C3 = dict(C, id=ident("hc", 3), previous=D("CARD", C), binding_hash=D("BINDING", B2),
          issued_at=T, not_before=T, status_index=19)
SC3 = signed("CARD", C3, [4, 5])
RENEW = command(4, 3, 2, {"kind": "binding.renew", "binding": SB2, "card": SC3})
E_RENEW = event(4, D("EVENT", E3["body"]), "BindingRenewed", D("COMMAND", RENEW["body"]), [D("BINDING", B2), D("CARD", C3)], 19, [17])
REV_CARD = command(5, 4, 2, {"kind": "revoke", "target": "card", "id": C["id"], "reason": "WITHDRAWN"})
REV_AGENT = command(6, 4, 2, {"kind": "revoke", "target": "agent", "id": A, "reason": "COMPROMISE"})
REV_BINDING = command(7, 4, 2, {"kind": "revoke", "target": "binding", "id": B["id"], "reason": "WITHDRAWN"})
ROOT2 = dict(ROOT, epoch="2", previous=D("ROOT", ROOT), service_key=KEYS[7][1], created_at=T,
             cutover={"seq": "3", "log_hash": D("EVENT", E3["body"])})
SROOT2 = signed("ROOT", ROOT2, [1, 2, 3, 7])
ROOT_ROTATE = command(8, 1, 1, {"kind": "root.rotate", "document": SROOT2}, R)
FREEZE = command(9, 1, 1, {"kind": "root.freeze", "reason": "COMPROMISE"}, R)


def query(n, value):
    return signed("QUERY", {"v": 1, "root": R, "query_id": ident("hq", n), "actor": KEYS[4][1]["id"],
        "issued_at": T, "expires_at": T + 30, "query": value}, [4])


Q_RESOLVE = query(1, {"kind": "resolve", "did": A, "card_id": None})
Q_RECEIPT = query(2, {"kind": "receipt", "op_id": ident("ho", 2)})
Q_EXPORT = query(3, {"kind": "export", "did": A, "after_revision": "0", "limit": 100})

RENEW_REPLY = {"v": 1, "receipt": receipt(RENEW, E_RENEW),
    "record": dict(REC2, revision="3", binding_hash=D("BINDING", B2), current_card_hash=D("CARD", C3))}
REVOKE_REPLIES = {}
for name, cmd, kind, resulting_state in [
    ("card", REV_CARD, "CardRevoked", "enrolled"),
    ("agent", REV_AGENT, "AgentRevoked", "revoked"),
    ("binding", REV_BINDING, "BindingRevoked", "revoked")]:
    ev = event(4, D("EVENT", E3["body"]), kind, D("COMMAND", cmd["body"]), [], None, [17])
    REVOKE_REPLIES[name] = {"v": 1, "receipt": receipt(cmd, ev),
        "record": dict(REC2, revision="3", state=resulting_state, current_card_hash=None)}
E_ROOT = event(4, D("EVENT", E3["body"]), "RootRotated", D("COMMAND", ROOT_ROTATE["body"]), [D("ROOT", ROOT2)])
ROOT_REPLY = {"v": 1, "receipt": receipt(ROOT_ROTATE, E_ROOT), "record": None}
ST_ROOT = signed("STATUS", dict(ST["body"], root_epoch="2", seq="4", log_hash=D("EVENT", E_ROOT["body"])), [7])
E_FREEZE = event(4, D("EVENT", E3["body"]), "RootFrozen", D("COMMAND", FREEZE["body"]), [], state="frozen")
FREEZE_REPLY = {"v": 1, "receipt": receipt(FREEZE, E_FREEZE), "record": None}
E_REV = event(4, D("EVENT", E3["body"]), "AgentRevoked", D("COMMAND", REV_AGENT["body"]), [], None, [17])
ST_REV = status(E_REV, [17])
F_REV = signed("FRESH", dict(F["body"], status_hash=D("STATUS", ST_REV["body"]),
    seq="4", log_hash=D("EVENT", E_REV["body"])), [2])

ALLOW = {"v": 1, "decision": "allow", "code": "ACTIVE", "did": A, "card_hash": D("CARD", C),
    "principal_id": P, "key_epoch": "1", "root": R, "status_seq": "3", "checked_at": T,
    "valid_until": T + 60, "evidence_hash": D("EVIDENCE", {"bundle": BUNDLE, "status": ST, "fresh": None})}
EVIDENCE = {"bundle": BUNDLE, "status": ST, "fresh": F}
ALLOW_FRESH = dict(ALLOW, valid_until=T + 5, evidence_hash=D("EVIDENCE", EVIDENCE))
ALLOW_ROTATED = dict(ALLOW, card_hash=D("CARD", C2), key_epoch="2", status_seq="4",
    evidence_hash=D("EVIDENCE", {"bundle": BUNDLE_ROTATED, "status": ST_ROTATED, "fresh": None}))

HB = {"source": "herald_local", "card_id": C["id"], "card_hash": D("CARD", C)}
ADAPTER_REQUEST = {"v": 1, "tenant_id": TEN, "sub": SUB, "caller_jkt": jkt(5),
    "binding": HB, "challenge": "lnn_" + "B" * 32, "mode": "fresh", "now": T}
ADAPTER_RESPONSE = {"v": 1, "challenge": ADAPTER_REQUEST["challenge"], "card_hash": D("CARD", C),
    "sub": SUB, "caller_jkt": jkt(5), "status": "active", "checked_at": T, "valid_until": T + 5,
    "evidence_hash": D("EVIDENCE", EVIDENCE)}

CLIENT_CONFIG = {"v": 1, "mode": "development", "roots": [{"root": R,
    "control_fingerprint": hashlib.sha256(base64.urlsafe_b64decode(KEYS[1][1]["public_key"] + "=")).hexdigest(),
    "genesis_hash": D("ROOT", ROOT), "origin": ROOT["origin"], "enabled": True, "min_epoch": "1"}],
    "cache_dir": ".devin/herald/cache", "key_refs": [{"kid": KEYS[4][1]["id"], "path": ".devin/herald/keys/human.json"}],
    "clock_max_error_s": 2, "read_max_age_s": 60, "fresh_max_age_s": 5}
SERVER_CONFIG = {"v": 1, "root": R, "root_document_path": ".devin/herald/root.json",
    "service_secret_binding": "HERALD_SERVICE_KEY", "private_data_key_binding": "HERALD_DATA_KEY",
    "root_do_binding": "HERALD_ROOT", "production": False, "max_agents": 8192, "status_slots": 131072,
    "public_get_per_minute": 120, "public_fresh_per_minute": 120,
    "write_per_actor_per_minute": 30, "revocation_reserve_per_minute": 60}


def build_fixtures():
    """Collect every named fixture into one JSON-serializable object."""
    keys_out = {}
    for n, (sk, pub) in KEYS.items():
        keys_out[str(n)] = {
            "kid": pub["id"],
            "public_key": pub["public_key"],
            "seed_b64u": b64(bytes([n]) * 32),
            "keyfile": {"v": 1, "kid": pub["id"], "algorithm": "Ed25519", "seed_b64u": b64(bytes([n]) * 32)},
            "jkt": jkt(n),
        }
    return {
        "T": T, "R": R, "A": A, "P": P, "N": N, "G": G, "TEN": TEN, "SUB": SUB,
        "KEYS": keys_out,
        "ROOT": ROOT, "SR": SR, "ROOT2": ROOT2, "SROOT2": SROOT2,
        "B": B, "SB": SB, "B2": B2, "SB2": SB2, "CAP": CAP,
        "C": C, "SC": SC, "C2": C2, "SC2": SC2, "C3": C3, "SC3": SC3,
        "ROT": ROT, "SROT": SROT,
        "E1": E1, "E2": E2, "E3": E3, "E4": E4, "E_RENEW": E_RENEW,
        "E_ROOT": E_ROOT, "E_FREEZE": E_FREEZE, "E_REV": E_REV,
        "ENROLL": ENROLL, "ISSUE": ISSUE, "ROTATE": ROTATE, "RENEW": RENEW,
        "REV_CARD": REV_CARD, "REV_AGENT": REV_AGENT, "REV_BINDING": REV_BINDING,
        "ROOT_ROTATE": ROOT_ROTATE, "FREEZE": FREEZE,
        "Q_RESOLVE": Q_RESOLVE, "Q_RECEIPT": Q_RECEIPT, "Q_EXPORT": Q_EXPORT,
        "ER": ER, "CR": CR, "RR": RR,
        "REC1": REC1, "REC2": REC2, "REC3": REC3,
        "BUNDLE": BUNDLE, "BUNDLE_ROTATED": BUNDLE_ROTATED,
        "ST": ST, "ST_ROTATED": ST_ROTATED, "ST_ROOT": ST_ROOT, "ST_REV": ST_REV,
        "F": F, "F_REV": F_REV, "FRESH_REPLY": FRESH_REPLY,
        "RENEW_REPLY": RENEW_REPLY, "REVOKE_REPLIES": REVOKE_REPLIES,
        "ROOT_REPLY": ROOT_REPLY, "FREEZE_REPLY": FREEZE_REPLY,
        "ALLOW": ALLOW, "ALLOW_FRESH": ALLOW_FRESH, "ALLOW_ROTATED": ALLOW_ROTATED,
        "EVIDENCE": EVIDENCE,
        "HB": HB, "ADAPTER_REQUEST": ADAPTER_REQUEST, "ADAPTER_RESPONSE": ADAPTER_RESPONSE,
        "CLIENT_CONFIG": CLIENT_CONFIG, "SERVER_CONFIG": SERVER_CONFIG,
        "status_s2": status(),
        "status_at_T3600": status(at=T + 3600),
        "status_at_binding_expiry": status(at=B["expires_at"]),
        "status_frozen": status(ev=E_FREEZE, state="frozen"),
        "bits_0_7_8_17": bits([0, 7, 8, 17]),
    }


def main():
    print(J(build_fixtures()).decode())


if __name__ == "__main__":
    main()
