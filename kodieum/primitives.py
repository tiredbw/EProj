"""ГОСТ-примитивы в соглашениях документа: Стрибог-256, Кузнечик и KDF_TREE из gost/.

Как векторы переводятся в байты для каждого примитива, документ явно не
говорит; соглашения ниже восстановлены по контрольным примерам приложения Б.
"""

from gost.kdf import kdf_tree_streebog256
from gost.kuznechik import Kuznechik
from gost.streebog import streebog256, streebog512

from .vectors import deserialize, serialize


def h256(data: bytes) -> bytes:
    """H_256 от сериализованных данных (Б.1).

    Байтовая строка подаётся в Стрибог как число в записи ГОСТ 34.11 —
    первым идёт старший байт, — и хэш-код возвращается в той же записи.
    Так получаются оба значения H_256 из Б.1. В gost.streebog порядок
    обратный (как в RFC 6986), отсюда развороты.
    """
    return streebog256(data[::-1])[::-1]


def h512(data: bytes) -> bytes:
    """Стрибог-512 для shk (раздел 7) в той же записи, что и h256.

    Контрольных примеров для него в МР нет, соглашение перенесено с H_256.
    """
    return streebog512(data[::-1])[::-1]


def hkdf(key: int, length_bits: int) -> int:
    """HKDF(k, L) из Б.1 — KDF_TREE_GOSTR3411_2012_256 с пустыми label и seed, R = 1.

    Ключ сериализуется по Б.1, выход читается как вектор длины L по тому же
    правилу. Контрольные значения KDF из Б.3 и Б.5 при этом не воспроизводятся
    (см. kodieum/README.md).
    """
    out = kdf_tree_streebog256(serialize(key, 256), length_bits)
    return deserialize(out, length_bits)


class BlockCipher:
    """E_K из раздела 6.1: Кузнечик, у которого ключ, блок и результат —
    числа (векторы по разделу 5.2) в записи ГОСТ 34.12 (Vec_256, Vec_128)."""

    def __init__(self, key: int):
        self._cipher = Kuznechik(key.to_bytes(32, "big"))

    def encrypt(self, block: int) -> int:
        return int.from_bytes(self._cipher.encrypt(block.to_bytes(16, "big")), "big")
