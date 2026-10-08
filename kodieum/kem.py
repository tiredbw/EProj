"""Основные процессы механизма инкапсуляции ключа «Кодиеум» (раздел 8 МР):
KeyGen, Encaps, Decaps.

Представления:
- pk = (A,), sk = (seed2, salt) — байтовые строки и список int-строк матрицы.
- Матрица A хранится как список из (m*t) int, бит j = элемент столбца j
  (столбцы 0..n-mt-1 относительно самой матрицы A).
- Двоичные векторы (salt, e, s, shk) — Python int, как и везде в пакете.
"""

import secrets

from bitvec import pack_bits, unpack_bits
from decode import decode
from gf import GF2m
from gost_primitives import kdf_tree_streebog256, streebog256
from kem_helpers import gen_unique_seq, gen_weight_vec


def _vec_to_bytes(value: int, n_bits: int) -> bytes:
    return value.to_bytes((n_bits + 7) // 8, "little")


def _derive_support_and_locators(m: int, n: int, t: int, seed2: bytes) -> tuple[list[int], list[int]]:
    """a, g из раздела 8.1 шаги 3-5 / 8.3 шаг 1 — общий для KeyGen и Decaps код."""
    ell = gen_unique_seq(m, n + t, seed2)
    return ell[:n], ell[n:]


def _kdf_split(seed: bytes, lengths_bits: list[int]) -> list[bytes]:
    for length in lengths_bits:
        if length % 8 != 0:
            raise ValueError("_kdf_split only supports byte-aligned part lengths")
    total_bits = sum(lengths_bits)
    out = kdf_tree_streebog256(seed, total_bits)
    parts = []
    offset = 0
    for length in lengths_bits:
        length_bytes = length // 8
        parts.append(out[offset : offset + length_bytes])
        offset += length_bytes
    return parts


def _build_parity_check_matrix(field: GF2m, a: list[int], g: list[int], n: int, t: int) -> list[int]:
    """Строит (m*t x n) двоичную матрицу H по шагу 6 раздела 8.1.
    Возвращает список из m*t строк-int (бит j = столбец j)."""
    m = field.m
    h = [[0] * n for _ in range(t)]
    for j in range(n):
        denom = 1
        for k in range(t):
            denom = field.mul(denom, field.add(a[j], g[k]))
        h[0][j] = field.inv(denom)
    for i in range(1, t):
        for j in range(n):
            h[i][j] = field.mul(a[j], h[i - 1][j])

    rows_bits = [[0] * n for _ in range(m * t)]
    for i in range(t):
        for j in range(n):
            value = h[i][j]
            for r in range(m):
                if (value >> r) & 1:
                    rows_bits[i * m + r][j] = 1
    return [pack_bits(row) for row in rows_bits]


def _row_reduce_to_systematic(rows: list[int], mt: int) -> list[int] | None:
    """Приводит двоичную матрицу (список n-битных строк-int) к виду (I_mt | A)
    сложением строк. Возвращает строки A (каждая длины n-mt бит, младший бит
    соответствует первому столбцу A) или None, если матрица не имеет такого
    представления."""
    rows = rows[:]
    for col in range(mt):
        pivot = next((r for r in range(col, mt) if (rows[r] >> col) & 1), None)
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        for r in range(mt):
            if r != col and (rows[r] >> col) & 1:
                rows[r] ^= rows[col]

    a_rows = []
    for r in range(mt):
        a_rows.append(rows[r] >> mt)
    return a_rows


def keygen(field: GF2m, n: int, t: int) -> tuple[list[int], tuple[bytes, int]]:
    """KeyGen из раздела 8.1. Возвращает (pk=A_rows, sk=(seed2, salt))."""
    m = field.m
    mt = m * t
    seed1 = secrets.token_bytes(32)

    while True:
        seed2, seed_prime, salt_bytes = _kdf_split(seed1, [256, 256, n])
        salt = int.from_bytes(salt_bytes, "little")

        a, g = _derive_support_and_locators(m, n, t, seed2)

        h_rows = _build_parity_check_matrix(field, a, g, n, t)
        a_rows = _row_reduce_to_systematic(h_rows, mt)
        if a_rows is not None:
            return a_rows, (seed2, salt)
        seed1 = seed_prime


def _compute_syndrome(pk: list[int], e: int, n: int, mt: int) -> int:
    """s_i = e_i XOR sum_col(A[i][col] * e_{mt+col}) — шаг 4 раздела 8.2,
    т.е. s = e * (I_mt | A)^T. Вынесено отдельно для независимой проверки
    этого инварианта от конкретного способа генерации e."""
    n_minus_mt = n - mt
    e_bits = unpack_bits(e, n)
    s_bits = [0] * mt
    for i in range(mt):
        acc = e_bits[i]
        row_bits = unpack_bits(pk[i], n_minus_mt)
        for col in range(n_minus_mt):
            if row_bits[col]:
                acc ^= e_bits[mt + col]
        s_bits[i] = acc
    return pack_bits(s_bits)


def encaps(field: GF2m, n: int, t: int, pk: list[int]) -> tuple[int, int]:
    """Encaps из раздела 8.2. Возвращает (shk, enk=s)."""
    m = field.m
    mt = m * t
    seed3 = secrets.token_bytes(32)
    e = gen_weight_vec(n, t, m, seed3)
    s = _compute_syndrome(pk, e, n, mt)

    shk = int.from_bytes(streebog256(_vec_to_bytes(e, n) + _vec_to_bytes(s, mt)), "little")
    return shk, s


def decaps(field: GF2m, n: int, t: int, sk: tuple[bytes, int], enk: int) -> int:
    """Decaps из раздела 8.3. Возвращает shk."""
    seed2, salt = sk
    m = field.m
    mt = m * t
    s = enk

    a, g = _derive_support_and_locators(m, n, t, seed2)
    e = decode(field, a, g, s, n, t)

    s_bytes = _vec_to_bytes(s, mt)
    if e is None:
        return int.from_bytes(streebog256(_vec_to_bytes(salt, n) + s_bytes), "little")

    return int.from_bytes(streebog256(_vec_to_bytes(e, n) + s_bytes), "little")
