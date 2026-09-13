"""Strict RFC 8032 Ed25519 (pure profile, no ph/ctx, no algorithm negotiation).

Enforces the spec's strictness profile on top of raw verification:
canonical point encodings (y < p, on-curve), rejection of identity and
small-order public keys, canonical S scalars (S < L). Implemented with
explicit field/curve arithmetic so Python and TypeScript agree byte-for-byte
on acceptance, not just on signatures.
"""

import hashlib
import secrets

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493


def _mp(a):
    return a % P


def _ml(a):
    return a % L


def _mod_inv(a, m):
    return pow(a % m, m - 2, m)


def _mod_pow(base, exp, m):
    return pow(base % m, exp, m)


I = _mod_pow(2, (P - 1) // 4, P)  # sqrt(-1)
D_CONST = (-121665 * _mod_inv(121666, P)) % P


def _recover_x(y, sign):
    y2 = _mp(y * y)
    xx = _mp((y2 - 1) * _mod_inv(_mp(D_CONST * y2) + 1, P))
    x = _mod_pow(xx, (P + 3) // 8, P)
    if _mp(x * x - xx) != 0:
        x = _mp(x * I)
        if _mp(x * x - xx) != 0:
            return None
    if x == 0 and sign == 1:
        return None  # non-canonical per RFC 8032
    if (x & 1) != sign:
        x = P - x
    return x


BY = (4 * _mod_inv(5, P)) % P
BX = _recover_x(BY, 0)


class Point:
    __slots__ = ("x", "y", "z", "t")

    def __init__(self, x, y, z=1, t=None):
        self.x = _mp(x)
        self.y = _mp(y)
        self.z = _mp(z)
        self.t = _mp(t if t is not None else x * y)


IDENTITY = Point(0, 1, 1, 0)
BASE = Point(BX, BY)


def _is_identity(q):
    zinv = _mod_inv(q.z, P)
    return _mp(q.x * zinv) == 0 and _mp(q.y * zinv) == 1


def _add(p1, p2):
    """Complete extended-coordinate addition (a = -1 twisted Edwards)."""
    A = _mp((p1.y - p1.x) * (p2.y - p2.x))
    B = _mp((p1.y + p1.x) * (p2.y + p2.x))
    C = _mp(2 * p1.t * p2.t * D_CONST)
    Dd = _mp(2 * p1.z * p2.z)
    E = _mp(B - A)
    F = _mp(Dd - C)
    G = _mp(Dd + C)
    H = _mp(B + A)
    return Point(_mp(E * F), _mp(G * H), _mp(F * G), _mp(E * H))


def _scalarmult(q, n):
    r = IDENTITY
    b = q
    e = n
    while e > 0:
        if e & 1:
            r = _add(r, b)
        b = _add(b, b)
        e >>= 1
    return r


def decode_point(data):
    """Strict point decode: canonical encoding (y < p), on-curve, x exists.
    Does not itself reject small-order points — use is_small_order."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= P:
        return None  # non-canonical
    x = _recover_x(y, sign)
    if x is None:
        return None
    return Point(x, y)


def is_small_order(q):
    return _is_identity(_scalarmult(q, 8))


def encode_point(q):
    zinv = _mod_inv(q.z, P)
    x = _mp(q.x * zinv)
    y = _mp(q.y * zinv)
    if x & 1:
        y |= 1 << 255
    return y.to_bytes(32, "little")


def public_key_valid(data):
    """Strict public-key validation: canonical, on-curve, not small-order."""
    q = decode_point(data)
    return q is not None and not is_small_order(q)


def _sha512(*parts):
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _clamp_scalar(h):
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return int.from_bytes(a, "little")


def public_key_from_seed(seed):
    return encode_point(_scalarmult(BASE, _clamp_scalar(_sha512(seed))))


def keygen():
    seed = secrets.token_bytes(32)
    return seed, public_key_from_seed(seed)


def ed25519_sign(seed, message):
    h = _sha512(seed)
    a = _clamp_scalar(h)
    pub = encode_point(_scalarmult(BASE, a))
    r = _ml(int.from_bytes(_sha512(h[32:], message), "little"))
    R = encode_point(_scalarmult(BASE, r))
    k = _ml(int.from_bytes(_sha512(R, pub, message), "little"))
    S = _ml(r + k * a)
    return R + S.to_bytes(32, "little")


def is_canonical_scalar(s_bytes):
    if len(s_bytes) != 32:
        return False
    return int.from_bytes(s_bytes, "little") < L


def ed25519_verify(public_key, message, signature):
    """Strict verify: canonical public key (not small-order), canonical R,
    canonical S, cofactorless verification equation [S]B = R + [k]A."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    A = decode_point(public_key)
    if A is None or is_small_order(A):
        return False
    Rb = signature[:32]
    R = decode_point(Rb)
    if R is None:
        return False
    s_bytes = signature[32:]
    if not is_canonical_scalar(s_bytes):
        return False
    S = int.from_bytes(s_bytes, "little")
    k = _ml(int.from_bytes(_sha512(Rb, public_key, message), "little"))
    lhs = _scalarmult(BASE, S)
    rhs = _add(R, _scalarmult(A, k))
    return encode_point(lhs) == encode_point(rhs)
