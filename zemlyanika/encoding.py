"""Кодирование многочленов в байтовые строки (7.4, алгоритмы 3 и 4)."""

from .bits import bits_to_bytes, bytes_to_bits, substring
from .params import N
from .ring import Poly


def encode(a: Poly, s: int) -> bytes:
    """Алгоритм 3: коэффициенты по s бит подряд, затем bits_to_bytes — 32·s байт."""
    b = 0
    for deg, coef in enumerate(a):
        if not 0 <= coef < 1 << s:
            raise ValueError(f"коэффициент {coef} не помещается в {s} бит")
        b |= coef << (s * deg)
    return bits_to_bytes(b, N * s)


def decode(data: bytes, s: int) -> Poly:
    """Алгоритм 4."""
    if len(data) != 32 * s:
        raise ValueError(f"закодированный многочлен занимает {32 * s} байт, получено {len(data)}")
    b = bytes_to_bits(data)
    return [substring(b, s * deg, s * (deg + 1)) for deg in range(N)]
