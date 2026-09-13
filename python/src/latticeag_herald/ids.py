"""Identifier profile (spec §3): locked prefixes + nanoid suffixes, CSPRNG."""

import re
import secrets
from urllib.parse import urlparse

NANOID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

ID_PREFIXES = {
    "root": "hr", "agent": "ha", "card": "hc", "principal": "hp",
    "binding": "hb", "key": "hk", "op": "ho", "query": "hq",
}

_NANOID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def nanoid(length):
    return "".join(secrets.choice(NANOID_ALPHABET) for _ in range(length))


def new_id(kind):
    return ID_PREFIXES[kind] + "_" + nanoid(21)


def new_challenge():
    return "hn_" + nanoid(32)


def _has_suffix(value, prefix, length):
    if not isinstance(value, str) or not value.startswith(prefix + "_"):
        return False
    s = value[len(prefix) + 1:]
    return len(s) == length and _NANOID_RE.match(s) is not None


def is_root_id(s):    return _has_suffix(s, "hr", 21)
def is_agent_id(s):   return _has_suffix(s, "ha", 21)
def is_card_id(s):    return _has_suffix(s, "hc", 21)
def is_principal_id(s): return _has_suffix(s, "hp", 21)
def is_binding_id(s): return _has_suffix(s, "hb", 21)
def is_key_id(s):     return _has_suffix(s, "hk", 21)
def is_op_id(s):      return _has_suffix(s, "ho", 21)
def is_query_id(s):   return _has_suffix(s, "hq", 21)
def is_nonce(s):      return _has_suffix(s, "hn", 32)
def is_gateway_id(s): return _has_suffix(s, "lsg", 21)
def is_tenant_id(s):  return _has_suffix(s, "ltn", 21)
def is_sub_id(s):     return _has_suffix(s, "lsu", 21)


HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def is_hash(s):
    return isinstance(s, str) and HASH_RE.match(s) is not None


_DID_RE = re.compile(r"^did:herald:hr_[A-Za-z0-9_-]{21}:ha_[A-Za-z0-9_-]{21}$")


def is_did(s):
    return isinstance(s, str) and len(s) <= 64 and _DID_RE.match(s) is not None


def did_parts(did):
    if not is_did(did):
        return None
    _, _, root, agent = did.split(":")
    return {"root": root, "agent": agent}


def agent_id_of_did(did):
    p = did_parts(did)
    return p["agent"] if p else None


def is_origin(s, development=False):
    """HTTPS origin per §4: no path, userinfo, fragment, query, IP literal, or
    non-443 port. http://localhost[:port] in development profiles only."""
    if not isinstance(s, str):
        return False
    try:
        u = urlparse(s)
    except Exception:
        return False
    if not u.scheme or not u.hostname:
        return False
    if u.username or u.password:
        return False
    if u.path not in ("", "/") or u.query or u.fragment:
        return False
    host = u.hostname
    if ":" in host or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return False
    try:
        port = u.port
    except ValueError:
        return False
    if u.scheme == "https":
        return port is None or port == 443
    if development and u.scheme == "http" and host in ("localhost", "127.0.0.1"):
        return True
    return False
