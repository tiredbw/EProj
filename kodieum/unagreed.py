"""Режим без предварительного согласования параметров (раздел 7):
pk = (A, t), sk = (seed_2, salt, p) или (ℓ, salt, p) у KeyGen2, а n, m и t
каждая сторона выводит из ключей и шифртекста.

Здесь длины векторов несут информацию, поэтому salt, p и s хранятся
в BitVector, а A — в Matrix вместе с числом столбцов.
"""

import secrets

from .auxiliary import gen_unique_seq
from .kem import decapsulate, encapsulate, key_material
from .params import Params
from .vectors import BitVector, Matrix

PublicKey = tuple[Matrix, int]
SecretKey = tuple[int, BitVector, BitVector]
SecretKey2 = tuple[list[int], BitVector, BitVector]


def _keys(params: Params, seed1: int | None) -> tuple[list[int], int, list[int], BitVector, BitVector]:
    if seed1 is None:
        seed1 = secrets.randbits(256)
    A, seed2, ell, salt = key_material(params.n, params.m, params.t, params.p, seed1)
    return A, seed2, ell, BitVector(salt, params.n), BitVector(params.p, params.m - 1)


def keygen(params: Params, seed1: int | None = None) -> tuple[PublicKey, SecretKey]:
    """KeyGen с pk = (A, t) и sk = (seed_2, salt, p)."""
    A, seed2, _, salt, p = _keys(params, seed1)
    return (Matrix(A, params.n - params.mt), params.t), (seed2, salt, p)


def keygen2(params: Params, seed1: int | None = None) -> tuple[PublicKey, SecretKey2]:
    """KeyGen2 с pk = (A, t) и sk = (ℓ, salt, p)."""
    A, _, ell, salt, p = _keys(params, seed1)
    return (Matrix(A, params.n - params.mt), params.t), (ell, salt, p)


def encaps(pk: PublicKey, seed3: int | None = None, long_key: bool = False) -> tuple[bytes, BitVector]:
    """Encaps с добавленными шагами: k — число столбцов A, n = r + k, m = r / t."""
    A, t = pk
    r = len(A.rows)
    if t <= 0 or r % t:
        raise ValueError(f"число строк A (r = {r}) должно делиться на t = {t}")
    n, m = r + A.columns, r // t
    if not (m * t < n and n + t < 1 << m):
        raise ValueError(f"из ключа получены недопустимые параметры n = {n}, m = {m}, t = {t}")
    if seed3 is None:
        seed3 = secrets.randbits(256)
    shk, s = encapsulate(n, m, t, A.rows, seed3, long_key)
    return shk, BitVector(s, r)


def _parameters(salt: BitVector, p: BitVector, enk: BitVector) -> tuple[int, int, int]:
    """Добавленные шаги Decaps: n — длина salt, m по длине p, t = r / m.

    По тексту раздела 7 m равно длине p, но по разделу 5.3 у p только
    m − 1 координат (p_0, …, p_{m-2}); берётся m = длина p + 1.
    """
    n = salt.length
    m = p.length + 1
    if enk.length % m:
        raise ValueError(f"длина шифртекста r = {enk.length} должна делиться на m = {m}")
    return n, m, enk.length // m


def decaps(sk: SecretKey, enk: BitVector, long_key: bool = False) -> bytes:
    """Decaps по sk = (seed_2, salt, p)."""
    seed2, salt, p = sk
    n, m, t = _parameters(salt, p, enk)
    ell = gen_unique_seq(m, n + t, seed2)
    return decapsulate(n, m, t, p.value, ell, salt.value, enk.value, long_key)


def decaps2(sk: SecretKey2, enk: BitVector, long_key: bool = False) -> bytes:
    """Decaps2 по sk = (ℓ, salt, p)."""
    ell, salt, p = sk
    n, m, t = _parameters(salt, p, enk)
    if len(ell) != n + t:
        raise ValueError(f"в ℓ должно быть n + t = {n + t} элементов")
    return decapsulate(n, m, t, p.value, ell, salt.value, enk.value, long_key)
