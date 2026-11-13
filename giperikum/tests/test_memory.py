"""Расход памяти «Гиперикума»: деревья не хранятся целиком, утечек нет.

Пик памяти — объём, который объекты Python занимали во время операции
сверх занятого до неё (модуль tracemalloc); утечки ищутся по числу
выделенных блоков. Обе функции — в measure.py в корне.
"""

import pytest

from giperikum import fors, hypericum
from giperikum.address import Address
from giperikum.params import B_128_20, Params
from measure import peak_memory, retained_blocks

TINY = Params("малый", h=2, d=2, b=2, k=2)  # подпись меньше секунды
SEEDS = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
KIB = 1024


@pytest.fixture(scope="module")
def keypair():
    return hypericum.keygen(TINY, *SEEDS)


def test_treehash_memory_depends_on_height_not_on_number_of_leaves():
    # treehash (алгоритм 19) держит стек не больше чем из z + 1 узлов.
    # Дерево высоты 8 в 64 раза больше дерева высоты 2, а пик растёт меньше
    # чем на 1 КиБ. Все 256 листьев как объекты bytes заняли бы около 16 КиБ.
    _, low = peak_memory(fors.treehash, SEEDS[0], SEEDS[2], 0, 2, Address())
    _, high = peak_memory(fors.treehash, SEEDS[0], SEEDS[2], 0, 8, Address())
    assert high - low < 4 * KIB


def test_sign_and_verify_peak_memory_on_tiny_set(keypair):
    pk, sk = keypair
    sig, sign_peak = peak_memory(hypericum.sign, b"message", sk, TINY)
    ok, verify_peak = peak_memory(hypericum.verify, b"message", sig, pk, TINY)
    assert ok
    # Замер: около 22 КиБ на подпись и 23 КиБ на проверку.
    assert max(sign_peak, verify_peak) < 256 * KIB


def test_repeated_verification_does_not_accumulate_memory(keypair):
    # Проверка проходит те же функции хэширования, WOTS+C, XMSS и FORS+C,
    # что и подпись, но в несколько раз быстрее, поэтому вызовов больше.
    pk, sk = keypair
    sig = hypericum.sign(b"message", sk, TINY)

    def check():
        assert hypericum.verify(b"message", sig, pk, TINY)

    # Утечка хотя бы одного объекта за проверку дала бы прирост не меньше 10 блоков.
    assert retained_blocks(check, repeats=10) < 5


@pytest.mark.slow
def test_full_signature_peak_memory():
    pk, sk = hypericum.keygen(B_128_20, *SEEDS)
    sig, peak = peak_memory(hypericum.sign, b"message", sk, B_128_20)
    assert hypericum.verify(b"message", sig, pk, B_128_20)
    # Замер: около 40 КиБ, из них 16 376 байт — сама подпись.
    assert peak < 256 * KIB
