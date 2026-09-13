"""verifyHistory (spec §7, §9): check a root-document chain and a signed audit
event chain. Never returns live=True; historical verification is evidence,
not authorization.
"""

from .b64u import b64u_decode
from .digest import digest, digest_bytes, sha256_hex
from .ed25519 import ed25519_verify
from .proofs import verify_proof_set
from .schema import MAX_ROOT_EPOCHS, validate

ZERO_HASH = "0" * 64


def verify_history(events, root_docs, pins):
    def bad(code):
        return {"v": 1, "valid": False, "live": False, "code": code}

    if len(root_docs) < 1 or len(root_docs) > MAX_ROOT_EPOCHS:
        return bad("EVIDENCE_MISMATCH")
    root = root_docs[0]["body"]["root"]
    pin = next((p for p in pins if p["root"] == root), None)
    if pin is None or not pin["enabled"]:
        return bad("ROOT_UNTRUSTED")
    ctrl = b64u_decode(root_docs[0]["body"]["control_key"]["public_key"])
    if ctrl is None or sha256_hex(ctrl) != pin["control_fingerprint"]:
        return bad("ROOT_UNTRUSTED")
    if digest("ROOT", root_docs[0]["body"]) != pin["genesis_hash"]:
        return bad("ROOT_UNTRUSTED")

    # Root chain: schema, continuity, epoch increments, proof sets.
    for i, d in enumerate(root_docs):
        if validate("RootDocument", d["body"]) is not None:
            return bad("EVIDENCE_MISMATCH")
        if d["body"]["root"] != root:
            return bad("EVIDENCE_MISMATCH")
        if int(d["body"]["epoch"]) != i + 1:
            return bad("EVIDENCE_MISMATCH")
        if i == 0:
            g = d["body"]
            if g["previous"] is not None or g["cutover"] is not None:
                return bad("EVIDENCE_MISMATCH")
            gkeys = {k["id"]: b64u_decode(k["public_key"])
                     for k in (g["control_key"], g["service_key"], g["registrar_key"])}
            r = verify_proof_set("ROOT", d, list(gkeys.keys()),
                                 lambda kid: gkeys.get(kid))
            if r is not None:
                return bad(r)
        else:
            prev = root_docs[i - 1]["body"]
            doc = d["body"]
            if doc["previous"] != digest("ROOT", prev):
                return bad("EVIDENCE_MISMATCH")
            if (doc["control_key"]["id"] != prev["control_key"]["id"]
                    or doc["control_key"]["public_key"] != prev["control_key"]["public_key"]):
                return bad("EVIDENCE_MISMATCH")
            if doc["status_slots"] != prev["status_slots"]:
                return bad("EVIDENCE_MISMATCH")
            if doc["cutover"] is None:
                return bad("EVIDENCE_MISMATCH")
            expected = [doc["control_key"]["id"], prev["service_key"]["id"],
                        doc["service_key"]["id"], doc["registrar_key"]["id"]]
            keys = {}
            for k in (doc["control_key"], prev["service_key"], doc["service_key"],
                      doc["registrar_key"], prev["registrar_key"], prev["control_key"]):
                keys[k["id"]] = b64u_decode(k["public_key"])
            r = verify_proof_set("ROOT", d, expected, lambda kid: keys.get(kid))
            if r is not None:
                return bad(r)

    # Event chain: consecutive seqs from 1, prev links, epoch-consistent signing.
    prev_hash = ZERO_HASH
    state = "active"
    for i, e in enumerate(events):
        if validate("AuditEvent", e) is not None:
            return bad("EVIDENCE_MISMATCH")
        b = e["body"]
        if b["root"] != root:
            return bad("EVIDENCE_MISMATCH")
        if int(b["seq"]) != i + 1:
            return bad("EVIDENCE_MISMATCH")
        if b["prev"] != prev_hash:
            return bad("EVIDENCE_MISMATCH")
        expected_state = "frozen" if state == "frozen" or b["kind"] == "RootFrozen" else "active"
        if b["root_state"] != expected_state:
            return bad("EVIDENCE_MISMATCH")
        seq = int(b["seq"])
        signer = None
        lower = 1
        for j, d_env in enumerate(root_docs):
            d = d_env["body"]
            nxt = root_docs[j + 1]["body"] if j + 1 < len(root_docs) else None
            upper = None if nxt is None or nxt["cutover"] is None else int(nxt["cutover"]["seq"]) + 1
            if seq >= lower and (upper is None or seq <= upper):
                signer = {"kid": d["service_key"]["id"],
                          "public_key": d["service_key"]["public_key"],
                          "epoch": d["epoch"]}
                break
            if upper is None:
                break
            lower = upper + 1
        if signer is None:
            return bad("EVIDENCE_MISMATCH")
        if b["root_epoch"] != signer["epoch"]:
            return bad("EVIDENCE_MISMATCH")
        pk = b64u_decode(signer["public_key"])
        p0 = e["proofs"][0] if len(e["proofs"]) == 1 else None
        if p0 is None or p0["kid"] != signer["kid"] or pk is None:
            return bad("SIGNATURE_INVALID")
        sig = b64u_decode(p0["signature"])
        if sig is None or not ed25519_verify(pk, digest_bytes("EVENT", b), sig):
            return bad("SIGNATURE_INVALID")
        prev_hash = digest("EVENT", b)
        if b["kind"] == "RootRotated":
            successor = next(
                (d for d in root_docs if int(d["body"]["epoch"]) == int(b["root_epoch"]) + 1), None)
            if successor is None or digest("ROOT", successor["body"]) not in b["objects"]:
                return bad("EVIDENCE_MISMATCH")
        state = b["root_state"]
    last = events[-1] if events else None
    return {
        "v": 1,
        "valid": True,
        "live": False,
        "last_seq": last["body"]["seq"] if last else "0",
        "last_hash": digest("EVENT", last["body"]) if last else ZERO_HASH,
    }
