"""Основные процессы KEM (раздел 8) в режиме с согласованием параметров:
KeyGen и KeyGen2, Encaps, Decaps и Decaps2.

Ключ инкапсуляции pk — матрица A, строка i которой хранится числом
(бит j — элемент a_{i,j}). Ключ декапсуляции — (seed_2, salt) у KeyGen
и (ℓ, salt) у KeyGen2. Общий ключ shk — 32 байта H_256 в записи
ГОСТ 34.11; при long_key=True — 64 байта Стрибога-512 (раздел 7).

Функции key_material, encapsulate и decapsulate принимают n, m, t явно:
на них же построен режим без согласования параметров (unagreed.py).
"""

import secrets

from .auxiliary import gen_unique_seq, gen_weight_vec
from .decode import decode
from .field import Field
from .goppa import goppa_syndrome, parity_check_matrix, systematic_part
from .params import Params
from .primitives import h256, h512, hkdf
from .vectors import serialize

PublicKey = list[int]
SecretKey = tuple[int, int]
SecretKey2 = tuple[list[int], int]

_MASK_256 = (1 << 256) - 1


def support_and_goppa(params: Params, seed2: int) -> tuple[list[int], list[int]]:
    """KeyGen, шаги 3–5: ℓ = gen_unique_seq(m, n + t, seed_2), a = ℓ_0…ℓ_{n-1}, g = ℓ_n…ℓ_{n+t-1}."""
    ell = gen_unique_seq(params.m, params.n + params.t, seed2)
    return ell[: params.n], ell[params.n :]


def public_matrix(params: Params, seed2: int) -> PublicKey | None:
    """KeyGen, шаги 3–7 при заданном seed_2."""
    field = Field(params.m, params.p)
    a, g = support_and_goppa(params, seed2)
    return systematic_part(parity_check_matrix(field, a, g, params.t), params.mt)


def key_material(n: int, m: int, t: int, p: int, seed1: int) -> tuple[list[int], int, list[int], int]:
    """KeyGen, шаги 2–7: (A, seed_2, ℓ, salt). Пока H не приводится
    к виду (I_mt ‖ A), шаги повторяются с seed_1 = seed′."""
    field = Field(m, p)
    while True:
        out = hkdf(seed1, 512 + n)
        seed2 = out & _MASK_256
        seed_prime = (out >> 256) & _MASK_256
        salt = out >> 512
        ell = gen_unique_seq(m, n + t, seed2)
        A = systematic_part(parity_check_matrix(field, ell[:n], ell[n:], t), m * t)
        if A is not None:
            return A, seed2, ell, salt
        seed1 = seed_prime


def syndrome(pk: PublicKey, e: int, mt: int) -> int:
    """Encaps, шаг 4: s_i = e_i ⊕ e_r·a_{i,0} ⊕ … ⊕ e_{r+n-mt-1}·a_{i,n-mt-1}, где r = mt."""
    tail = e >> mt
    s = 0
    for i, row in enumerate(pk):
        bit = ((e >> i) & 1) ^ ((row & tail).bit_count() & 1)
        s |= bit << i
    return s


def _hash(data: bytes, long_key: bool) -> bytes:
    return h512(data) if long_key else h256(data)


def shared_key(e: int, n: int, s: int, r: int, long_key: bool = False) -> bytes:
    """shk = H(e ‖ s), где e длины n и s длины r."""
    return _hash(serialize(e, n) + serialize(s, r), long_key)


def rejection_key(salt: int, n: int, s: int, r: int, long_key: bool = False) -> bytes:
    """Decaps, шаг 5: shk = H(salt ‖ s) при отказе декодирования."""
    return _hash(serialize(salt, n) + serialize(s, r), long_key)


def encapsulate(n: int, m: int, t: int, A: list[int], seed3: int, long_key: bool) -> tuple[bytes, int]:
    """Encaps, шаги 1 и 3–7 при заданном seed_3: (shk, s)."""
    r = len(A)
    e = gen_weight_vec(n, t, m, seed3)
    s = syndrome(A, e, r)
    return shared_key(e, n, s, r, long_key), s


def decapsulate(n: int, m: int, t: int, p: int, ell: list[int], salt: int, s: int, long_key: bool) -> bytes:
    """Decaps, шаги 2–7 по уже выработанной последовательности ℓ.

    Шаг 4 требует e веса t с e·(I_mt ‖ A)ᵀ = s, а Decode (6.3) это равенство
    не проверяет и изредка возвращает e с другим синдромом. Поэтому
    результат Decode сверяется с s по H, и при несовпадении это отказ ⊥.
    """
    mt = m * t
    if s >> mt:
        raise ValueError(f"шифртекст длиннее mt = {mt} бит")
    if salt >> n:
        raise ValueError(f"salt длиннее n = {n} бит")
    field = Field(m, p)
    a, g = ell[:n], ell[n:]
    e = decode(field, a, g, s, n, t)
    if e is not None and goppa_syndrome(field, a, g, e, t) != goppa_syndrome(field, a, g, s, t):
        e = None
    if e is None:
        return rejection_key(salt, n, s, mt, long_key)
    return shared_key(e, n, s, mt, long_key)


def keygen(params: Params, seed1: int | None = None) -> tuple[PublicKey, SecretKey]:
    """KeyGen: (pk, sk), sk = (seed_2, salt). seed_1 задаётся только в тестах."""
    if seed1 is None:
        seed1 = secrets.randbits(256)
    A, seed2, _, salt = key_material(params.n, params.m, params.t, params.p, seed1)
    return A, (seed2, salt)


def keygen2(params: Params, seed1: int | None = None) -> tuple[PublicKey, SecretKey2]:
    """KeyGen2 (8.1.1): то же, но sk = (ℓ, salt) — ℓ не придётся вырабатывать в Decaps2."""
    if seed1 is None:
        seed1 = secrets.randbits(256)
    A, _, ell, salt = key_material(params.n, params.m, params.t, params.p, seed1)
    return A, (ell, salt)


def encaps(params: Params, pk: PublicKey, seed3: int | None = None, long_key: bool = False) -> tuple[bytes, int]:
    """Encaps: (shk, enk), где enk = s — синдром длины mt."""
    if len(pk) != params.mt or any(row >> (params.n - params.mt) for row in pk):
        raise ValueError(f"ключ инкапсуляции должен быть матрицей {params.mt} × {params.n - params.mt}")
    if seed3 is None:
        seed3 = secrets.randbits(256)
    return encapsulate(params.n, params.m, params.t, pk, seed3, long_key)


def decaps(params: Params, sk: SecretKey, enk: int, long_key: bool = False) -> bytes:
    """Decaps: shk; при отказе декодирования — H(salt ‖ s)."""
    seed2, salt = sk
    ell = gen_unique_seq(params.m, params.n + params.t, seed2)
    return decapsulate(params.n, params.m, params.t, params.p, ell, salt, enk, long_key)


def decaps2(params: Params, sk: SecretKey2, enk: int, long_key: bool = False) -> bytes:
    """Decaps2 (8.3.1): шаги 2–7 Decaps по ℓ из ключа декапсуляции."""
    ell, salt = sk
    if len(ell) != params.n + params.t:
        raise ValueError(f"в ℓ должно быть n + t = {params.n + params.t} элементов")
    return decapsulate(params.n, params.m, params.t, params.p, ell, salt, enk, long_key)
