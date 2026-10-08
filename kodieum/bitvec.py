"""Упаковка/распаковка двоичных векторов (Python int, бит i = координата i,
раздел 5.2 МР) за время O(длина), без наращивания int побитовым `|=`/`<<`
внутри цикла — такое наращивание стоит O(j) на шаге j из-за роста битовой
длины самого int, превращая линейный проход в квадратичный."""


def pack_bits(bits: list[int]) -> int:
    length = len(bits)
    buf = bytearray((length + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            buf[i // 8] |= 1 << (i % 8)
    return int.from_bytes(buf, "little")


def unpack_bits(value: int, length: int) -> list[int]:
    buf = value.to_bytes((length + 7) // 8, "little")
    return [(buf[i // 8] >> (i % 8)) & 1 for i in range(length)]
