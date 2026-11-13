"""MatrixGen (7.2, алгоритм 1) и CBD (7.3, алгоритм 2)."""

from .bits import substring
from .params import N
from .ring import Poly


def matrix_gen(buf: int, buf_len: int, k: int, t: int) -> list[list[Poly]]:
    """Алгоритм 1: матрица A по 256·k²·t псевдослучайным битам, по t бит на коэффициент."""
    if buf_len < N * k * k * t:
        raise ValueError(f"MatrixGen нужно {N * k * k * t} бит, получено {buf_len}")
    num = 0
    matrix = []
    for _ in range(k):
        row = []
        for _ in range(k):
            poly = []
            for _ in range(N):
                poly.append(substring(buf, num, num + t))
                num += t
            row.append(poly)
        matrix.append(row)
    return matrix


def cbd(eta: int, count: int, buf: int, buf_len: int, q: int) -> list[Poly]:
    """Алгоритм 2: count многочленов, коэффициент — Σ по η парам бит (b[j] − b[j+1]) mod q."""
    if buf_len < 2 * N * eta * count:
        raise ValueError(f"CBD нужно {2 * N * eta * count} бит, получено {buf_len}")
    polys = []
    for i in range(count):
        poly = []
        for deg in range(N):
            base = 2 * N * eta * i + 2 * eta * deg
            coef = 0
            for j in range(0, 2 * eta, 2):
                coef += ((buf >> (base + j)) & 1) - ((buf >> (base + j + 1)) & 1)
            poly.append(coef % q)
        polys.append(poly)
    return polys
