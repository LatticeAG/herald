"""Unpadded base64url: only [A-Za-z0-9_-], must round-trip byte-for-byte."""

import base64
import re

_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    """Strict decode. Returns None when the input is not canonical unpadded
    base64url (padded, foreign characters, or non-round-trippable length)."""
    if not isinstance(s, str) or not _RE.match(s):
        return None
    if len(s) % 4 == 1:
        return None
    padded = s.replace("-", "+").replace("_", "/")
    padded += "=" * ((4 - len(padded) % 4) % 4)
    try:
        out = base64.b64decode(padded)
    except Exception:
        return None
    if b64u_encode(out) != s:
        return None
    return out


def b64u_decode_exact(s, length):
    b = b64u_decode(s)
    return b if b is not None and len(b) == length else None
