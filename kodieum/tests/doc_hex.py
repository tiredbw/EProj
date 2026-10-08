"""Декодер нестандартной hex-нотации Приложения Б (раздел Б.1, таблица 5).

Внутри каждой тетрады биты записаны в порядке (b0, b1, b2, b3), то есть
в обратном порядке относительно обычного hex. Проверено сквозным образом
против примера матрицы M из раздела Б.1: hex "932b2" с одним хвостовым
нулём декодируется в тот же бит-вектор и те же байты сериализации, что
приведены в документе явно.
"""


def doc_hex_to_bits(hex_str: str, pad: int = 0) -> list[int]:
    bits = []
    for ch in hex_str:
        nibble = format(int(ch, 16), "04b")
        bits.extend(int(c) for c in nibble[::-1])
    return bits[:-pad] if pad else bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Сериализация бит-вектора в байты: байт 0 = младшие 8 бит и т.д.
    (Приложение Б.1). При не кратной 8 длине старшие биты последнего байта
    дополняются нулями.
    """
    padded = list(bits) + [0] * (-len(bits) % 8)
    value = 0
    for i, b in enumerate(padded):
        value |= b << i
    return value.to_bytes(len(padded) // 8, "little")


def doc_hex_to_bytes(hex_str: str, pad: int = 0) -> bytes:
    """Декодирует hex-нотацию документа напрямую в байты. Используется только
    для значений, чья истинная длина уже кратна 8 (ключи, seed и т.п.);
    для векторов произвольной длины (например, строк матриц) используйте
    doc_hex_to_bits + bits_to_bytes."""
    bits = doc_hex_to_bits(hex_str, pad)
    if len(bits) % 8 != 0:
        raise ValueError("decoded bit length is not byte-aligned; use bits_to_bytes for serialization")
    value = 0
    for i, b in enumerate(bits):
        value |= b << i
    return value.to_bytes(len(bits) // 8, "little")
