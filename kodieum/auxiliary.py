"""Вспомогательные алгоритмы раздела 6: gen_unique_seq (6.1) и gen_weight_vec (6.2)."""

from .primitives import BlockCipher, hkdf

M_PRIME = 16


def gen_unique_seq(m: int, n: int, k: int) -> list[int]:
    """n попарно различных чисел из [0, 2^m): номера элементов E_k(0), …, E_k(2^m − 1)
    в порядке возрастания этих значений."""
    if not 0 < n < 1 << m:
        raise ValueError(f"нужно 0 < n < 2^m, получено n = {n}, m = {m}")
    cipher = BlockCipher(k)
    a = [cipher.encrypt(i) for i in range(1 << m)]
    order = sorted(range(1 << m), key=lambda i: a[i])
    return order[:n]


def weight_vec_from_v(n: int, t: int, m: int, v: int) -> int | None:
    """Шаги 3–7 алгоритма 6.2 для уже выработанной строки v.

    Возвращает вектор e веса t или None, если нужно перейти к seed′ (шаги 4–5).
    """
    if m > M_PRIME:
        raise ValueError(f"b_i берётся из {M_PRIME}-битных слов, поэтому нужно m ⩽ {M_PRIME}")
    ell = -(-(1 << m) // n)
    b = [(v >> (M_PRIME * i)) & ((1 << m) - 1) for i in range(ell * t)]
    a = [b_i for b_i in b if b_i < n][:t]
    if len(a) < t or len(set(a)) < t:
        return None
    return sum(1 << a_i for a_i in a)


def gen_weight_vec(n: int, t: int, m: int, seed: int) -> int:
    """Псевдослучайный двоичный вектор длины n и веса t."""
    ell = -(-(1 << m) // n)
    v_bits = ell * t * M_PRIME
    while True:
        out = hkdf(seed, 256 + v_bits)
        seed_prime, v = out & ((1 << 256) - 1), out >> 256
        e = weight_vec_from_v(n, t, m, v)
        if e is not None:
            return e
        seed = seed_prime
