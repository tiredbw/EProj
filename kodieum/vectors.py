"""Двоичные векторы, их сериализация и запись из приложения Б.

Двоичный вектор (b_0, …, b_{ℓ-1}) хранится как число Σ b_i·2^i (раздел 5.2);
длина передаётся отдельно или, где она несёт информацию, хранится в BitVector.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class BitVector:
    value: int
    length: int

    def __post_init__(self):
        if self.length < 0 or self.value < 0 or self.value >> self.length:
            raise ValueError(f"значение не помещается в вектор длины {self.length}")


@dataclass(frozen=True)
class Matrix:
    """Двоичная матрица: строки — числа (бит j — столбец j) и число столбцов."""

    rows: list[int]
    columns: int

    def __post_init__(self):
        if self.columns < 0 or any(row < 0 or row >> self.columns for row in self.rows):
            raise ValueError(f"строка матрицы длиннее {self.columns} столбцов")


def serialize(value: int, length: int) -> bytes:
    """Б.1: ⌈ℓ/8⌉ байт, первый байт содержит b_0 … b_7 (b_0 — младший бит байта)."""
    return value.to_bytes((length + 7) // 8, "little")


def deserialize(data: bytes, length: int) -> int:
    return int.from_bytes(data, "little") & ((1 << length) - 1)


def serialize_list(items: list[int], length: int) -> bytes:
    """Б.1: матрица (построчно) или вектор из двоичных векторов одной длины —
    каждый элемент отдельно в ⌈ℓ/8⌉ байт, затем конкатенация."""
    return b"".join(serialize(item, length) for item in items)


def from_doc_hex(text: str, pad: int = 0) -> tuple[int, int]:
    """Запись приложения Б «(…)_pad» → (вектор, длина).

    Символ j несёт биты b_{4j} … b_{4j+3}, причём b_{4j} — младший бит его
    значения (таблица 5); pad — сколько нулей было дописано справа.
    """
    value = sum(int(c, 16) << (4 * j) for j, c in enumerate(text))
    return value, 4 * len(text) - pad


def to_doc_hex(value: int, length: int) -> str:
    return "".join("%x" % ((value >> (4 * j)) & 0xF) for j in range((length + 3) // 4))
