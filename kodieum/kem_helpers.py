"""Вспомогательные алгоритмы механизма инкапсуляции ключа (раздел 6 МР).

Двоичные векторы здесь представлены как Python int: бит i вектора — это
бит i числа (соответствие "a = sum a_i * 2^i" из раздела 5.2), как и в
gf.py. Байтовые строки (ключи, выход KDF/шифра) конвертируются в этот вид
через int.from_bytes(data, "little") — младший байт соответствует младшим
индексам вектора."""

from bitvec import pack_bits
from gost_primitives import kuznechik_encrypt_block, kdf_tree_streebog256, streebog256


def gen_unique_seq(m: int, n: int, k: bytes) -> list[int]:
    """gen_unique_seq(m, n, k) из раздела 6.1: n попарно различных чисел
    в диапазоне [0, 2^m), полученных сортировкой E_k(0), ..., E_k(2^m - 1).

    Документ не определяет однозначно, как целое i сериализуется в 128-битный
    блок шифра Кузнечик для E_k(i) — здесь использовано big-endian представление
    как наиболее распространённое соглашение. Это расхождение не воспроизводит
    контрольный пример Б.2 и зафиксировано в анализе качества документа
    (ANALYSIS.md); на итоговый результат KEM при runtime-генерации ключей это
    не влияет, так как k там всегда берётся из HKDF, а не из примера документа.

    Числовое сравнение блоков при сортировке — little-endian, согласно
    соответствию "a = sum a_i * 2^i" из раздела 5.2.
    """
    if n >= (1 << m):
        raise ValueError("n must be < 2^m")

    size = 1 << m
    a = [kuznechik_encrypt_block(k, i.to_bytes(16, "big")) for i in range(size)]
    order = sorted(range(size), key=lambda idx: int.from_bytes(a[idx], "little"))
    return order[:n]


def gen_weight_vec(n: int, t: int, m: int, seed: bytes) -> int:
    """gen_weight_vec(n, t, m, seed) из раздела 6.2: псевдослучайный
    двоичный вектор длины n и веса t (число ненулевых координат).
    Возвращается как int, бит i = e_i.
    """
    m_prime = 16
    ell = -(-(1 << m) // n)  # наименьшее ell: n*ell >= 2^m

    sample_bytes = m_prime // 8  # m'=16 бит — всегда выровнено по байту

    while True:
        l_bits = 256 + ell * t * m_prime
        out = kdf_tree_streebog256(seed, l_bits)
        out_int = int.from_bytes(out, "little")
        seed_prime = (out_int & ((1 << 256) - 1)).to_bytes(32, "little")
        v_bytes = (out_int >> 256).to_bytes((ell * t * m_prime) // 8, "little")
        mask_m = (1 << m) - 1

        b = []
        for i in range(ell * t):
            offset = i * sample_bytes
            sample = int.from_bytes(v_bytes[offset : offset + sample_bytes], "little")
            b.append(sample & mask_m)
        indices = [j for j in range(ell * t) if b[j] < n]
        if len(indices) < t:
            seed = seed_prime
            continue

        a = [b[j] for j in indices[:t]]
        if len(set(a)) != t:
            seed = seed_prime
            continue

        bits = [0] * n
        for value in a:
            bits[value] = 1
        return pack_bits(bits)
