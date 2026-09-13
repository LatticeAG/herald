"""Offline verifier (spec §7.1) — pure function plus the context wrapper that
applies durable frontier/challenge state transitions.

Verification order: syntax/version, trusted root, root continuity and
signatures, binding/card/receipt signatures, object cross-links, status
authenticity, frontier, freshness, time intervals, root state, then bit.
"""

from .b64u import b64u_decode, b64u_encode
from .digest import digest, digest_bytes, sha256_hex
from .ed25519 import ed25519_verify
from .errors import deny
from .proofs import verify_proof_set
from .schema import MAX_ROOT_EPOCHS, validate


def _deny(code):
    return {"v": 1, "decision": "deny", "code": code}


def _event_signer_at_seq(docs, seq):
    """Service key authorized for EVENTS/RECEIPTS at seq. Doc_e's event range
    is [cutover_e + 2, cutover_{e+1} + 1]: the RootRotated event at cutover+1
    is still signed by the pre-cutover (prior epoch) service key."""
    lower = 1
    for i, d_env in enumerate(docs):
        d = d_env["body"]
        nxt = docs[i + 1]["body"] if i + 1 < len(docs) else None
        upper = None if nxt is None or nxt["cutover"] is None else int(nxt["cutover"]["seq"]) + 1
        if seq >= lower and (upper is None or seq <= upper):
            return {"id": d["service_key"]["id"],
                    "public_key": d["service_key"]["public_key"],
                    "epoch": d["epoch"]}
        if upper is None:
            return None
        lower = upper + 1
    return None


def _status_signer_at_seq(docs, seq):
    """Service key authorized for STATUS/FRESH at seq. New live status at the
    cutover uses the successor: doc_e covers [cutover_e + 1, cutover_{e+1}]."""
    for i, d_env in enumerate(docs):
        d = d_env["body"]
        lower = 1 if i == 0 else int(d["cutover"]["seq"]) + 1
        nxt = docs[i + 1]["body"] if i + 1 < len(docs) else None
        upper = None if nxt is None or nxt["cutover"] is None else int(nxt["cutover"]["seq"])
        if seq >= lower and (upper is None or seq <= upper):
            return {"id": d["service_key"]["id"],
                    "public_key": d["service_key"]["public_key"],
                    "epoch": d["epoch"]}
    return None


def _doc_for_epoch(docs, epoch):
    for d in docs:
        if d["body"]["epoch"] == epoch:
            return d
    return None


def _pub_bytes(pk):
    return b64u_decode(pk["public_key"])


def _verify_root_chain(docs, pin):
    if len(docs) < 1 or len(docs) > MAX_ROOT_EPOCHS:
        return "EVIDENCE_MISMATCH"
    genesis = docs[0]["body"]
    if genesis["epoch"] != "1" or genesis["previous"] is not None or genesis["cutover"] is not None:
        return "EVIDENCE_MISMATCH"
    if digest("ROOT", genesis) != pin["genesis_hash"]:
        return "ROOT_UNTRUSTED"
    ctrl = _pub_bytes(genesis["control_key"])
    if ctrl is None or sha256_hex(ctrl) != pin["control_fingerprint"]:
        return "ROOT_UNTRUSTED"
    gkeys = [genesis["control_key"], genesis["service_key"], genesis["registrar_key"]]

    def gbytes(kid):
        k = next((x for x in gkeys if x["id"] == kid), None)
        return _pub_bytes(k) if k else None

    r = verify_proof_set("ROOT", docs[0], [k["id"] for k in gkeys], gbytes)
    if r is not None:
        return r
    for i in range(1, len(docs)):
        prev = docs[i - 1]["body"]
        doc = docs[i]["body"]
        if doc["root"] != prev["root"]:
            return "EVIDENCE_MISMATCH"
        if int(doc["epoch"]) != int(prev["epoch"]) + 1:
            return "EVIDENCE_MISMATCH"
        if doc["previous"] != digest("ROOT", prev):
            return "EVIDENCE_MISMATCH"
        if (doc["control_key"]["id"] != prev["control_key"]["id"]
                or doc["control_key"]["public_key"] != prev["control_key"]["public_key"]):
            return "EVIDENCE_MISMATCH"
        if doc["status_slots"] != prev["status_slots"]:
            return "EVIDENCE_MISMATCH"
        if doc["cutover"] is None:
            return "EVIDENCE_MISMATCH"
        expected = [doc["control_key"]["id"], prev["service_key"]["id"],
                    doc["service_key"]["id"], doc["registrar_key"]["id"]]
        keys = {}
        for k in (doc["control_key"], prev["control_key"], doc["service_key"],
                  prev["service_key"], doc["registrar_key"], prev["registrar_key"]):
            keys[k["id"]] = k
        r = verify_proof_set("ROOT", docs[i], expected,
                             lambda kid: _pub_bytes(keys[kid]) if kid in keys else None)
        if r is not None:
            return r
    return None


def _verify_single(tag, env, key):
    """Single-signer object check: exactly one proof signing under `key`."""
    if len(env["proofs"]) != 1:
        return "SIGNATURE_INVALID"
    p = env["proofs"][0]
    if p["kid"] != key["id"]:
        return "SIGNATURE_INVALID"
    pk = _pub_bytes(key)
    sig = b64u_decode(p["signature"])
    if pk is None or sig is None:
        return "SIGNATURE_INVALID"
    if not ed25519_verify(pk, digest_bytes(tag, env["body"]), sig):
        return "SIGNATURE_INVALID"
    return None


def verify(inp, ctx):
    """inp: {bundle, status, fresh, challenge, now, mode}; ctx: {pins,
    frontiers, known_revocations, received_age_s, challenge_outstanding,
    challenge_consumed, cache_state?}. Returns a VerifyResult dict."""
    b = inp["bundle"]
    # ---- 1. syntax/version
    if validate("IdentityBundle", b) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if validate("Status", inp["status"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if inp["fresh"] is not None and validate("Fresh", inp["fresh"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    for d in b["roots"]:
        if validate("RootDocument", d["body"]) is not None:
            return _deny("EVIDENCE_MISMATCH")
    if validate("HumanBinding", b["binding"]["body"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if validate("AgentCard", b["card"]["body"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if validate("Receipt", b["receipt"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if b["prior_card"] is not None and validate("AgentCard", b["prior_card"]["body"]) is not None:
        return _deny("EVIDENCE_MISMATCH")
    if b["rotation"] is not None and validate("Rotation", b["rotation"]["body"]) is not None:
        return _deny("EVIDENCE_MISMATCH")

    # ---- 2. trusted root
    root = b["roots"][0]["body"]["root"] if b["roots"] else None
    if not root:
        return _deny("ROOT_UNTRUSTED")
    cache_state = ctx.get("cache_state")
    if cache_state in ("DISABLED", "FORKED"):
        return _deny("FORKED" if cache_state == "FORKED" else "ROOT_UNTRUSTED")
    pin = next((p for p in ctx["pins"] if p["root"] == root), None)
    if pin is None or not pin["enabled"]:
        return _deny("ROOT_UNTRUSTED")

    # ---- 3. root continuity / signatures
    chain_err = _verify_root_chain(b["roots"], pin)
    if chain_err is not None:
        return _deny(chain_err)

    binding = b["binding"]["body"]
    card = b["card"]["body"]
    receipt = b["receipt"]["body"]

    for r in (binding["root"], card["root"], receipt["root"], inp["status"]["body"]["root"]):
        if r != root:
            return _deny("EVIDENCE_MISMATCH")
    if inp["fresh"] is not None and inp["fresh"]["body"]["root"] != root:
        return _deny("EVIDENCE_MISMATCH")

    # ---- 4. binding/card/receipt signatures
    reg_doc = _doc_for_epoch(b["roots"], binding["registrar_epoch"])
    if reg_doc is None:
        return _deny("EVIDENCE_MISMATCH")
    keys = {}
    for k in (reg_doc["body"]["registrar_key"], binding["human_key"], binding["agent_key"]):
        keys[k["id"]] = k
    r = verify_proof_set(
        "BINDING", b["binding"],
        [reg_doc["body"]["registrar_key"]["id"], binding["human_key"]["id"], binding["agent_key"]["id"]],
        lambda kid: _pub_bytes(keys[kid]) if kid in keys else None)
    if r is not None:
        return _deny(r)

    keys = {card["key"]["id"]: card["key"], binding["human_key"]["id"]: binding["human_key"]}
    r = verify_proof_set("CARD", b["card"], [card["key"]["id"], binding["human_key"]["id"]],
                         lambda kid: _pub_bytes(keys[kid]) if kid in keys else None)
    if r is not None:
        return _deny(r)

    svc = _event_signer_at_seq(b["roots"], int(receipt["seq"]))
    if svc is None:
        return _deny("EVIDENCE_MISMATCH")
    r = _verify_single("RECEIPT", b["receipt"], svc)
    if r is not None:
        return _deny(r)

    if b["prior_card"] is not None:
        prior0 = b["prior_card"]["body"]
        keys = {prior0["key"]["id"]: prior0["key"], binding["human_key"]["id"]: binding["human_key"]}
        r = verify_proof_set("CARD", b["prior_card"], [prior0["key"]["id"], binding["human_key"]["id"]],
                             lambda kid: _pub_bytes(keys[kid]) if kid in keys else None)
        if r is not None:
            return _deny(r)

    # ---- 5. object cross-links (binding_hash precedes human_principal)
    binding_hash = digest("BINDING", binding)
    if card["binding_hash"] != binding_hash:
        return _deny("BINDING_MISMATCH")
    if card["human_principal"] != binding["principal_id"]:
        return _deny("BINDING_MISMATCH")
    if card["did"] != binding["did"]:
        return _deny("BINDING_MISMATCH")
    card_hash = digest("CARD", card)
    if card_hash not in receipt["objects"]:
        return _deny("EVIDENCE_MISMATCH")
    if receipt["allocated"] != card["status_index"]:
        return _deny("EVIDENCE_MISMATCH")
    if receipt["root"] != root:
        return _deny("EVIDENCE_MISMATCH")

    if receipt["kind"] == "CardRotated":
        if b["prior_card"] is None or b["rotation"] is None:
            return _deny("EVIDENCE_MISMATCH")
        prior = b["prior_card"]["body"]
        rot = b["rotation"]["body"]
        if digest("ROTATION", rot) not in receipt["objects"]:
            return _deny("EVIDENCE_MISMATCH")
        if rot["root"] != root or rot["did"] != card["did"]:
            return _deny("EVIDENCE_MISMATCH")
        if rot["old_card_hash"] != digest("CARD", prior):
            return _deny("ROTATION_MISMATCH")
        if rot["new_card_hash"] != card_hash:
            return _deny("ROTATION_MISMATCH")
        if rot["old_key_id"] != prior["key"]["id"]:
            return _deny("ROTATION_MISMATCH")
        if (rot["new_key"]["id"] != card["key"]["id"]
                or rot["new_key"]["public_key"] != card["key"]["public_key"]):
            return _deny("ROTATION_MISMATCH")
        if rot["from_epoch"] != prior["key_epoch"]:
            return _deny("ROTATION_MISMATCH")
        if rot["to_epoch"] != card["key_epoch"]:
            return _deny("ROTATION_MISMATCH")
        if int(rot["to_epoch"]) != int(rot["from_epoch"]) + 1:
            return _deny("ROTATION_MISMATCH")
        if card["previous"] != digest("CARD", prior):
            return _deny("BINDING_MISMATCH")
        if prior["did"] != card["did"] or prior["human_principal"] != card["human_principal"]:
            return _deny("BINDING_MISMATCH")
        keys = {prior["key"]["id"]: prior["key"], card["key"]["id"]: card["key"],
                binding["human_key"]["id"]: binding["human_key"]}
        r = verify_proof_set(
            "ROTATION", b["rotation"],
            [prior["key"]["id"], card["key"]["id"], binding["human_key"]["id"]],
            lambda kid: _pub_bytes(keys[kid]) if kid in keys else None)
        if r is not None:
            return _deny(r)
    elif receipt["kind"] in ("CardIssued", "BindingRenewed"):
        if b["prior_card"] is not None or b["rotation"] is not None:
            return _deny("EVIDENCE_MISMATCH")
    else:
        return _deny("EVIDENCE_MISMATCH")

    # ---- 6. status authenticity
    status = inp["status"]["body"]
    if status["slots"] != 131072:
        return _deny("EVIDENCE_MISMATCH")
    svc_status = _status_signer_at_seq(b["roots"], int(status["seq"]))
    if svc_status is None or svc_status["epoch"] != status["root_epoch"]:
        return _deny("EVIDENCE_MISMATCH")
    r = _verify_single("STATUS", inp["status"], svc_status)
    if r is not None:
        return _deny(r)
    if int(status["seq"]) < int(receipt["seq"]):
        return _deny("STATUS_ROLLBACK")

    # ---- 7. frontier
    frontier = next((f for f in ctx["frontiers"] if f["root"] == root), None)
    if frontier is not None:
        if int(status["root_epoch"]) < int(frontier["root_epoch"]):
            return _deny("ROOT_ROLLBACK")
        if int(status["seq"]) < int(frontier["seq"]):
            return _deny("STATUS_ROLLBACK")
        if status["seq"] == frontier["seq"]:
            if status["log_hash"] != frontier["log_hash"]:
                return _deny("FORKED")
            learned = next((k for k in ctx["known_revocations"] if k["root"] == root), None)
            if learned is not None and learned["bits"] != status["bits"]:
                return _deny("FORKED")
    if int(status["root_epoch"]) < int(pin["min_epoch"]):
        return _deny("ROOT_ROLLBACK")
    learned = next((k for k in ctx["known_revocations"] if k["root"] == root), None)
    if learned is not None:
        lb = b64u_decode(learned["bits"])
        nb = b64u_decode(status["bits"])
        if lb is None or nb is None:
            return _deny("EVIDENCE_MISMATCH")
        for i in range(len(lb)):
            if lb[i] & ~nb[i]:
                return _deny("STATUS_ROLLBACK")

    # ---- 8. freshness
    fresh_deadline = None
    if inp["mode"] == "bounded_cache":
        if status["issued_at"] > inp["now"] or inp["now"] >= status["expires_at"]:
            return _deny("STATUS_STALE")
        if status["expires_at"] - status["issued_at"] > 60:
            return _deny("STATUS_STALE")
        age = ctx["received_age_s"]
        if age > 60 or age < 0 or not isinstance(age, int):
            return _deny("STATUS_STALE")
        checked_at = status["issued_at"]
    else:
        fresh = inp["fresh"]["body"] if inp["fresh"] is not None else None
        if fresh is None:
            return _deny("STATUS_STALE")
        if ctx["challenge_consumed"]:
            return _deny("REPLAY")
        if (ctx["challenge_outstanding"] is None or inp["challenge"] is None
                or fresh["challenge"] != ctx["challenge_outstanding"]
                or inp["challenge"] != ctx["challenge_outstanding"]):
            return _deny("CHALLENGE_MISMATCH")
        if fresh["status_hash"] != digest("STATUS", status):
            return _deny("EVIDENCE_MISMATCH")
        if fresh["seq"] != status["seq"] or fresh["log_hash"] != status["log_hash"]:
            return _deny("EVIDENCE_MISMATCH")
        if fresh["checked_at"] != status["issued_at"]:
            return _deny("EVIDENCE_MISMATCH")
        svc_fresh = _status_signer_at_seq(b["roots"], int(fresh["seq"]))
        if svc_fresh is None or svc_fresh["epoch"] != status["root_epoch"]:
            return _deny("EVIDENCE_MISMATCH")
        r = _verify_single("FRESH", inp["fresh"], svc_fresh)
        if r is not None:
            return _deny(r)
        if fresh["checked_at"] > inp["now"] or inp["now"] >= fresh["valid_until"]:
            return _deny("STATUS_STALE")
        if fresh["valid_until"] - fresh["checked_at"] > 5:
            return _deny("STATUS_STALE")
        checked_at = fresh["checked_at"]
        fresh_deadline = fresh["valid_until"]

    # ---- 9. time intervals (card evaluated before binding)
    if inp["now"] < card["not_before"] or inp["now"] >= card["expires_at"]:
        return _deny("CARD_EXPIRED")
    if inp["now"] < binding["issued_at"] or inp["now"] >= binding["expires_at"]:
        return _deny("BINDING_EXPIRED")

    # ---- 10. root state
    if status["state"] == "frozen":
        return _deny("ROOT_FROZEN")

    # ---- 11. bit
    bits_bytes = b64u_decode(status["bits"])
    if bits_bytes is None or len(bits_bytes) != 16384:
        return _deny("EVIDENCE_MISMATCH")
    idx = card["status_index"]
    if (bits_bytes[idx >> 3] >> (idx % 8)) & 1:
        return _deny("CARD_REVOKED")

    valid_until = min(
        status["expires_at"],
        fresh_deadline if fresh_deadline is not None else 9007199254740991,
        card["expires_at"],
        binding["expires_at"],
    )

    return {
        "v": 1,
        "decision": "allow",
        "code": "ACTIVE",
        "did": card["did"],
        "card_hash": card_hash,
        "principal_id": card["human_principal"],
        "key_epoch": card["key_epoch"],
        "root": root,
        "status_seq": status["seq"],
        "checked_at": checked_at,
        "valid_until": valid_until,
        "evidence_hash": digest("EVIDENCE", {
            "bundle": b,
            "status": inp["status"],
            "fresh": inp["fresh"],
        }),
    }


def verify_with_context(inp, ctx):
    """Wrapper (§7.1): applies durable frontier advance, known-bit
    accumulation, and one-time challenge consumption around pure verify.
    Mutates ctx."""
    result = verify(inp, ctx)
    root = inp["bundle"]["roots"][0]["body"]["root"] if inp["bundle"]["roots"] else None
    if not root:
        return result

    if result["decision"] == "deny" and result["code"] == "FORKED":
        ctx["cache_state"] = "FORKED"
        return result
    if result["decision"] == "deny" and result["code"] in (
            "ROOT_UNTRUSTED", "EVIDENCE_MISMATCH", "SIGNATURE_INVALID", "PROOF_SET_INVALID"):
        return result  # inauthentic evidence never poisons frontier

    status = inp["status"]["body"]
    frontier = next((f for f in ctx["frontiers"] if f["root"] == root), None)
    new_frontier = {"root": root, "seq": status["seq"],
                    "log_hash": status["log_hash"], "root_epoch": status["root_epoch"]}
    if frontier is None:
        ctx["frontiers"].append(new_frontier)
    elif int(status["seq"]) >= int(frontier["seq"]):
        frontier.update(new_frontier)
    known = next((k for k in ctx["known_revocations"] if k["root"] == root), None)
    if known is None:
        ctx["known_revocations"].append({"root": root, "bits": status["bits"]})
    else:
        lb = b64u_decode(known["bits"])
        nb = b64u_decode(status["bits"])
        merged = bytes(lb[i] | nb[i] for i in range(16384))
        known["bits"] = b64u_encode(merged)
    if inp["mode"] == "fresh" and inp["fresh"] is not None:
        ctx["challenge_consumed"] = True
    ctx["cache_state"] = "USABLE"
    return result
