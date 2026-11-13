"""Двоичные и байтовые строки (раздел 5.1).

Двоичная строка b длины l хранится как число bits_to_int(b) = Σ b[i]·2^i,
то есть b[i] — бит i числа; длина передаётся отдельно.
"""


def bits_to_int(b: list[int]) -> int:
    """Формула (1) для строки, заданной списком бит."""
    return sum(bit << i for i, bit in enumerate(b))


def int_to_bits(a: int, length: int) -> list[int]:
    """Формула (2): b[i] = (a ≫ i) mod 2."""
    return [(a >> i) & 1 for i in range(length)]


def bits_to_bytes(b: int, length: int) -> bytes:
    """Формула (6): байт j — bits_to_int(b[8j : 8j + 8]), то есть младший бит байта первым."""
    if length % 8:
        raise ValueError("длина двоичной строки должна быть кратна 8")
    return b.to_bytes(length // 8, "little")


def bytes_to_bits(data: bytes) -> int:
    """Формула (5): обратное к bits_to_bytes."""
    return int.from_bytes(data, "little")


def substring(b: int, start: int, end: int) -> int:
    """b[start : end] (раздел 5.1)."""
    return (b >> start) & ((1 << (end - start)) - 1)
