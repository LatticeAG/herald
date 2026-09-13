"""Tagged digest domain (spec §3):
    D(tag,x) = hex(SHA256(UTF8("HERALD/" + tag + "/1\\0") || J(x)))
Proofs sign the 32 raw bytes decoded from D(tag, body).
"""

import hashlib

from .jcs import canonicalize

TAGS = (
    "ROOT", "BINDING", "CARD", "ROTATION", "COMMAND", "QUERY",
    "RECEIPT", "EVENT", "STATUS", "FRESH", "CAPABILITIES", "EVIDENCE",
)
TAG_SET = frozenset(TAGS)


def is_tag(s):
    return s in TAG_SET


def digest(tag, value):
    h = hashlib.sha256()
    h.update(("HERALD/" + tag + "/1\0").encode("utf-8"))
    h.update(canonicalize(value))
    return h.hexdigest()


D = digest


def digest_bytes(tag, value):
    return bytes.fromhex(digest(tag, value))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).digest()
