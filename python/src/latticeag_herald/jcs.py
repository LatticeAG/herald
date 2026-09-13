"""RFC 8785 JSON Canonicalization Scheme (JCS) serializer.

Input must already be a strict protocol JSON value (see strictjson): keys
sort by UTF-16 code units, numbers use ECMAScript serialization (the
protocol only admits non-negative integers <= 2^53-1), strings use minimal
escapes. Output is UTF-8 without a trailing newline.
"""


def _utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def _escape(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif c == 0x08:
            out.append("\\b")
        elif c == 0x09:
            out.append("\\t")
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x0C:
            out.append("\\f")
        elif c == 0x0D:
            out.append("\\r")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if v < 0 or v > 9007199254740991:
            raise ValueError("non-canonical number")
        return str(v)
    if isinstance(v, str):
        return _escape(v)
    if isinstance(v, list):
        return "[" + ",".join(_serialize(e) for e in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(_escape(k) + ":" + _serialize(v[k]) for k in keys) + "}"
    raise ValueError("non-JSON value: %r" % type(v))


def canonicalize(value):
    """Value → canonical UTF-8 bytes."""
    return _serialize(value).encode("utf-8")


def canonicalize_text(value):
    return _serialize(value)
