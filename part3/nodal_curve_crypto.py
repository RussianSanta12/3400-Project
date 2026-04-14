
from __future__ import annotations

from math import gcd
import secrets
from typing import Dict, List, Sequence, Tuple


Polynomial = List[int]
PublicKey = Tuple[int, int]

# Monic polynomial f(x) = x^2 + 1. Monic form keeps modular reduction simple.
DEFAULT_F: Polynomial = [1, 0, 1]
IDENTITY: Polynomial = [0]


def _lcm(a: int, b: int) -> int:
    return a * b // gcd(a, b)


def _is_probable_prime(candidate: int, rounds: int = 20) -> bool:
    if candidate < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for p in small_primes:
        if candidate == p:
            return True
        if candidate % p == 0:
            return False

    # Write candidate - 1 as d * 2^s with d odd.
    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x == 1 or x == candidate - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bit_length: int) -> int:
    if bit_length < 8:
        raise ValueError("bit_length must be at least 8")

    while True:
        candidate = secrets.randbits(bit_length) | (1 << (bit_length - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _mod_inverse(a: int, modulus: int) -> int:
    g, x, _ = _extended_gcd(a, modulus)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % modulus


def _trim(poly: Sequence[int]) -> Polynomial:
    out = list(poly)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def _poly_add(a: Sequence[int], b: Sequence[int], modulus: int) -> Polynomial:
    size = max(len(a), len(b))
    out = [0] * size
    for i in range(size):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0
        out[i] = (av + bv) % modulus
    return _trim(out)


def _poly_mul(a: Sequence[int], b: Sequence[int], modulus: int) -> Polynomial:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av == 0:
            continue
        for j, bv in enumerate(b):
            if bv == 0:
                continue
            out[i + j] = (out[i + j] + av * bv) % modulus
    return _trim(out)


def _poly_mod(poly: Sequence[int], modulus_poly: Sequence[int], modulus: int) -> Polynomial:
    modp = _trim(modulus_poly)
    if len(modp) == 1 and modp[0] == 0:
        raise ValueError("modulus polynomial cannot be zero")

    work = _trim(poly)
    mod_degree = len(modp) - 1
    mod_lead = modp[-1] % modulus
    lead_inv = _mod_inverse(mod_lead, modulus)

    while len(work) - 1 >= mod_degree and not (len(work) == 1 and work[0] == 0):
        degree_diff = (len(work) - 1) - mod_degree
        factor = (work[-1] * lead_inv) % modulus

        # Subtract factor * x^degree_diff * modp from work.
        for i in range(len(modp)):
            idx = degree_diff + i
            work[idx] = (work[idx] - factor * modp[i]) % modulus

        work = _trim(work)

    return work


def _poly_mul_mod(
    a: Sequence[int],
    b: Sequence[int],
    modulus_poly: Sequence[int],
    modulus: int,
) -> Polynomial:
    return _poly_mod(_poly_mul(a, b, modulus), modulus_poly, modulus)


def _poly_pow_mod(
    base: Sequence[int],
    exponent: int,
    modulus_poly: Sequence[int],
    modulus: int,
) -> Polynomial:
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result: Polynomial = [1]
    work = _poly_mod(base, modulus_poly, modulus)
    exp = exponent
    while exp > 0:
        if exp & 1:
            result = _poly_mul_mod(result, work, modulus_poly, modulus)
        work = _poly_mul_mod(work, work, modulus_poly, modulus)
        exp >>= 1
    return _trim(result)


def message_to_polynomial(message: str, modulus_n: int) -> Polynomial:
    raw = message.encode("utf-8")
    value = int.from_bytes(raw, byteorder="big", signed=False) if raw else 0
    if value >= modulus_n:
        raise ValueError("Message is too large for this key. Generate a larger key.")
    return [value]


def polynomial_to_message(poly: Sequence[int]) -> str:
    value = _trim(poly)[0] if poly else 0
    if value == 0:
        return ""

    byte_len = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(byte_len, byteorder="big", signed=False)
    return raw.decode("utf-8")


def generate_keys(
    bit_length: int = 128,
    e_start: int = 65537,
    include_primes: bool = False,
):
    p = _generate_prime(bit_length)
    q = _generate_prime(bit_length)
    while q == p:
        q = _generate_prime(bit_length)

    n = p * q
    totient_like = _lcm(p - 1, q - 1)

    e = e_start if e_start > 2 else 3
    if e % 2 == 0:
        e += 1
    while gcd(e, totient_like) != 1:
        e += 2

    d = _mod_inverse(e, totient_like)
    public_key = (n, e)

    if include_primes:
        details = {"p": p, "q": q, "totient_like": totient_like}
        return public_key, d, details
    return public_key, d


def encrypt(
    message: str,
    public_key: PublicKey,
    modulus_poly: Sequence[int] = DEFAULT_F,
) -> Dict[str, object]:
    n, e = public_key
    t_poly = message_to_polynomial(message, n)
    g_poly = _poly_pow_mod(t_poly, e, modulus_poly, n)
    return {
        "poly": g_poly,
        "n": n,
    }


def decrypt(
    ciphertext: Dict[str, object],
    private_key: int,
    modulus_poly: Sequence[int] = DEFAULT_F,
) -> str:
    g_poly = ciphertext["poly"]
    n = int(ciphertext["n"])
    t_poly = _poly_pow_mod(g_poly, private_key, modulus_poly, n)
    return polynomial_to_message(t_poly)


def nodal_group_operation(
    h1: Sequence[int],
    h2: Sequence[int],
    g2: Sequence[int],
    modulus_n: int,
    modulus_poly: Sequence[int] = DEFAULT_F,
) -> Polynomial:
    summed = _poly_mod(_poly_add(h1, h2, modulus_n), modulus_poly, modulus_n)
    if summed == [0]:
        return IDENTITY.copy()

    x_poly = [0, 1]
    product_plus_x = _poly_add(
        _poly_mul_mod(h1, h2, modulus_poly, modulus_n),
        x_poly,
        modulus_n,
    )
    return _poly_mul_mod(g2, product_plus_x, modulus_poly, modulus_n)


__all__ = [
    "DEFAULT_F",
    "IDENTITY",
    "generate_keys",
    "encrypt",
    "decrypt",
    "message_to_polynomial",
    "polynomial_to_message",
    "nodal_group_operation",
]
