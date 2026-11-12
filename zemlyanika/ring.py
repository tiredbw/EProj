"""Кольцо R_q = Z_q[x]/(x^256 + 1), векторы и матрицы над ним (разделы 5.2–5.5),
функции сжатия и восстановления (раздел 5.7).

Многочлен — список из 256 коэффициентов, a[i] — коэффициент при x^i.
"""

from .params import N

Poly = list[int]


def add(a: Poly, b: Poly, q: int) -> Poly:
    return [(x + y) % q for x, y in zip(a, b)]


def sub(a: Poly, b: Poly, q: int) -> Poly:
    return [(x - y) % q for x, y in zip(a, b)]


def scale(d: int, a: Poly, q: int) -> Poly:
    """Формула (11)."""
    return [(d * x) % q for x in a]


def mul_by_definition(a: Poly, b: Poly, q: int) -> Poly:
    """Формула (12): c_d = Σ_{i ⩽ d} a_i·b_{d−i} − Σ_{i > d} a_i·b_{256+d−i}."""
    c = []
    for d in range(N):
        acc = sum(a[i] * b[d - i] for i in range(d + 1))
        acc -= sum(a[i] * b[N + d - i] for i in range(d + 1, N))
        c.append(acc % q)
    return c


_SLOT = 64  # с запасом больше log2(256·q²) для q ⩽ 2^16


def mul(a: Poly, b: Poly, q: int) -> Poly:
    """То же, что mul_by_definition, но одним умножением целых чисел:
    коэффициенты упаковываются в 64-битные ячейки, произведение в Z[x]
    распаковывается и приводится по x^256 = −1."""
    pa = sum(x << (_SLOT * i) for i, x in enumerate(a))
    pb = sum(x << (_SLOT * i) for i, x in enumerate(b))
    p = pa * pb
    mask = (1 << _SLOT) - 1
    full = [(p >> (_SLOT * d)) & mask for d in range(2 * N - 1)] + [0]
    return [(full[d] - full[d + N]) % q for d in range(N)]


def dot(a: list[Poly], b: list[Poly], q: int) -> Poly:
    """Формула (15): aᵀ·b."""
    acc = [0] * N
    for x, y in zip(a, b):
        acc = add(acc, mul(x, y, q), q)
    return acc


def mat_vec(matrix: list[list[Poly]], v: list[Poly], q: int) -> list[Poly]:
    """Формула (16): A·b."""
    return [dot(row, v, q) for row in matrix]


def transpose(matrix: list[list[Poly]]) -> list[list[Poly]]:
    return [list(col) for col in zip(*matrix)]


def compress(a: int, d: int, t: int) -> int:
    """Формула (18): Compress_d(a) = ((a + 2^{d−1}) ≫ d) mod 2^{t−d}; при d = 0 — тождество."""
    if d == 0:
        return a
    return ((a + (1 << (d - 1))) >> d) % (1 << (t - d))


def decompress(a: int, d: int) -> int:
    """Формула (19): Decompress_d(a) = a ≪ d."""
    return a << d


def compress_poly(a: Poly, d: int, t: int) -> Poly:
    return [compress(x, d, t) for x in a]


def decompress_poly(a: Poly, d: int) -> Poly:
    return [decompress(x, d) for x in a]
