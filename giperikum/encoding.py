"""Вспомогательные алгоритмы раздела 4.5.3 и алгоритм 7."""


def to_int(x: bytes) -> int:
    """Алгоритм 1: байтовая строка → число, big-endian."""
    return int.from_bytes(x, "big")


def to_byte(x: int, n: int) -> bytes:
    """Алгоритм 2: число → байтовая строка длины n, big-endian."""
    return x.to_bytes(n, "big")


def indexes(m: bytes, b: int, i: int) -> int:
    """Алгоритм 3: биты i·b … (i+1)·b − 1 строки m, старший бит байта — первый."""
    idx = 0
    for j in range(i * b, (i + 1) * b):
        idx = 2 * idx + ((m[j // 8] >> (7 - j % 8)) & 1)
    return idx


def convert16(m: bytes) -> list[int]:
    """Алгоритм 7: 64 шестнадцатеричных разряда 32-байтной строки, старший полубайт первым."""
    return [x for byte in m for x in (byte >> 4, byte & 15)]
