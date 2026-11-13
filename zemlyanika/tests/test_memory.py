"""Расход памяти «Земляники»: пик каждой операции и отсутствие утечек.

Пик памяти — объём, который объекты Python занимали во время операции
сверх занятого до неё (модуль tracemalloc); утечки ищутся по числу
выделенных блоков. Обе функции — в measure.py в корне.
"""

import pytest

from measure import peak_memory, retained_blocks
from zemlyanika import kem
from zemlyanika.params import ALL, Z512

SEEDS = {"seed_a": b"\x11" * 32, "seed_s": b"\x22" * 32, "z": b"\x33" * 32}
KIB = 1024


@pytest.mark.parametrize("params", ALL, ids=lambda p: p.name)
def test_peak_memory_of_each_operation(params):
    (pk, sk), keygen_peak = peak_memory(kem.keygen, params, **SEEDS)
    (key, c), encaps_peak = peak_memory(kem.encaps, params, pk, b"\x44" * 32)
    key2, decaps_peak = peak_memory(kem.decaps, params, sk, c)
    assert key2 == key
    # Самое большое — матрица A из k² многочленов по 256 коэффициентов:
    # для Z1024 это 4096 чисел. Замер на Python 3.14: не больше 320 КиБ.
    assert max(keygen_peak, encaps_peak, decaps_peak) < 1024 * KIB


def test_repeated_encaps_and_decaps_do_not_accumulate_memory():
    pk, sk = kem.keygen(Z512, **SEEDS)

    def cycle():
        key, c = kem.encaps(Z512, pk)
        assert kem.decaps(Z512, sk, c) == key

    # Утечка хотя бы одного объекта за цикл дала бы прирост не меньше 20 блоков.
    assert retained_blocks(cycle, repeats=20) < 10
