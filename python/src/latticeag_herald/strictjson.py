"""Strict protocol JSON parser (spec §3, §6.1 step 1).

Rejects: BOM, trailing data, duplicate keys, invalid Unicode (lone
surrogates), lexical negative zero, fractions, exponent notation, NaN,
Infinity, numbers outside [0, 2^53-1]. Enforces byte/depth/member/element
limits. Parsing never uses json.loads so no lax grammar can leak through.
"""

MAX_NUM = 9007199254740991  # 2^53 - 1
BIGINT_MAX_COUNTER = 9223372036854775807


class Limits:
    def __init__(self, max_bytes, max_depth, max_members, max_elements):
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.max_members = max_members
        self.max_elements = max_elements


LIMITS_ORDINARY = Limits(65536, 16, 128, 256)
LIMITS_RESPONSE = Limits(262144, 16, 128, 256)
LIMITS_DOCUMENT_HISTORY = Limits(1048576, 16, 128, 256)
LIMITS_EXPORT = Limits(8388608, 16, 128, 256)


class _Fail(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def parse_json_strict(raw, limits=LIMITS_ORDINARY):
    """Parse raw bytes/str → (value, None) or (None, code)."""
    if isinstance(raw, str):
        data = raw.encode("utf-8")
    else:
        data = bytes(raw)
    if len(data) > limits.max_bytes:
        return None, "TOO_LARGE"
    if data[:3] == b"\xef\xbb\xbf":
        return None, "JSON_INVALID"
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "JSON_INVALID"
    # Reject any code point that cannot be represented in UTF-16 without a
    # surrogate-pair escape (Python str may hold lone surrogates from the OS).
    try:
        s.encode("utf-16-be")
    except UnicodeEncodeError:
        return None, "JSON_INVALID"
    p = _Parser(s, limits)
    try:
        p.ws()
        v = p.value(0)
        p.ws()
        if not p.eof():
            raise _Fail("JSON_INVALID")
        return v, None
    except _Fail as e:
        return None, e.code


class _Parser:
    def __init__(self, s, limits):
        self.s = s
        self.limits = limits
        self.i = 0

    def eof(self):
        return self.i >= len(self.s)

    def peek(self):
        return ord(self.s[self.i]) if self.i < len(self.s) else -1

    def ws(self):
        while self.i < len(self.s):
            c = ord(self.s[self.i])
            if c in (0x20, 0x09, 0x0A, 0x0D):
                self.i += 1
            else:
                break

    def value(self, depth):
        if depth > self.limits.max_depth:
            raise _Fail("TOO_LARGE")
        c = self.peek()
        if c == 0x7B:
            return self.obj(depth)
        if c == 0x5B:
            return self.arr(depth)
        if c == 0x22:
            return self.string()
        if c == 0x74:
            return self.lit("true", True)
        if c == 0x66:
            return self.lit("false", False)
        if c == 0x6E:
            return self.lit("null", None)
        return self.number()

    def lit(self, word, val):
        if self.s.startswith(word, self.i):
            self.i += len(word)
            return val
        raise _Fail("JSON_INVALID")

    def obj(self, depth):
        self.i += 1
        out = {}
        self.ws()
        if self.peek() == 0x7D:
            self.i += 1
            return out
        while True:
            self.ws()
            if self.peek() != 0x22:
                raise _Fail("JSON_INVALID")
            k = self.string()
            if k in out:
                raise _Fail("DUPLICATE_KEY")
            self.ws()
            if self.peek() != 0x3A:
                raise _Fail("JSON_INVALID")
            self.i += 1
            self.ws()
            out[k] = self.value(depth + 1)
            if len(out) > self.limits.max_members:
                raise _Fail("TOO_LARGE")
            self.ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x7D:
                self.i += 1
                return out
            raise _Fail("JSON_INVALID")

    def arr(self, depth):
        self.i += 1
        out = []
        self.ws()
        if self.peek() == 0x5D:
            self.i += 1
            return out
        while True:
            self.ws()
            out.append(self.value(depth + 1))
            if len(out) > self.limits.max_elements:
                raise _Fail("TOO_LARGE")
            self.ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x5D:
                self.i += 1
                return out
            raise _Fail("JSON_INVALID")

    def string(self):
        self.i += 1  # opening quote
        out = []
        while True:
            if self.eof():
                raise _Fail("JSON_INVALID")
            c = ord(self.s[self.i])
            if c == 0x22:
                self.i += 1
                return "".join(out)
            if c == 0x5C:
                self.i += 1
                if self.eof():
                    raise _Fail("JSON_INVALID")
                e = ord(self.s[self.i])
                self.i += 1
                if e == 0x22:
                    out.append('"')
                elif e == 0x5C:
                    out.append("\\")
                elif e == 0x2F:
                    out.append("/")
                elif e == 0x62:
                    out.append("\b")
                elif e == 0x66:
                    out.append("\f")
                elif e == 0x6E:
                    out.append("\n")
                elif e == 0x72:
                    out.append("\r")
                elif e == 0x74:
                    out.append("\t")
                elif e == 0x75:
                    out.append(self._unicode_escape())
                else:
                    raise _Fail("JSON_INVALID")
                continue
            if c < 0x20:
                raise _Fail("JSON_INVALID")
            if 0xD800 <= c <= 0xDBFF or 0xDC00 <= c <= 0xDFFF:
                # Python str has already decoded UTF-8 to code points; a lone
                # surrogate here means invalid input.
                raise _Fail("JSON_INVALID")
            out.append(self.s[self.i])
            self.i += 1

    def _unicode_escape(self):
        def hex4():
            if self.i + 4 > len(self.s):
                raise _Fail("JSON_INVALID")
            v = 0
            for k in range(4):
                c = ord(self.s[self.i + k])
                if 0x30 <= c <= 0x39:
                    d = c - 0x30
                elif 0x61 <= c <= 0x66:
                    d = c - 0x61 + 10
                elif 0x41 <= c <= 0x46:
                    d = c - 0x41 + 10
                else:
                    raise _Fail("JSON_INVALID")
                v = v * 16 + d
            self.i += 4
            return v

        u1 = hex4()
        if 0xD800 <= u1 <= 0xDBFF:
            if (self.i + 1 < len(self.s)
                    and self.s[self.i] == "\\" and self.s[self.i + 1] == "u"):
                self.i += 2
                u2 = hex4()
                if 0xDC00 <= u2 <= 0xDFFF:
                    cp = 0x10000 + ((u1 - 0xD800) << 10) + (u2 - 0xDC00)
                    return chr(cp)
            raise _Fail("JSON_INVALID")
        if 0xDC00 <= u1 <= 0xDFFF:
            raise _Fail("JSON_INVALID")
        return chr(u1)

    def number(self):
        start = self.i
        c = self.peek()
        if c == 0x2D:
            raise _Fail("NUMBER_INVALID")
        if c < 0x30 or c > 0x39:
            raise _Fail("JSON_INVALID")
        if c == 0x30:
            self.i += 1
        else:
            while 0x30 <= self.peek() <= 0x39:
                self.i += 1
        nc = self.peek()
        if nc in (0x2E, 0x65, 0x45):
            raise _Fail("NUMBER_INVALID")
        text = self.s[start:self.i]
        if len(text) > 1 and text.startswith("0"):
            raise _Fail("NUMBER_INVALID")
        v = int(text)
        if v > MAX_NUM:
            raise _Fail("NUMBER_INVALID")
        return v


import re as _re
_COUNTER_RE = _re.compile(r"^0|[1-9][0-9]{0,18}$")


def is_counter(s):
    if not isinstance(s, str) or not _COUNTER_RE.match(s):
        return False
    return int(s) <= BIGINT_MAX_COUNTER
