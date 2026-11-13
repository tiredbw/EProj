"""Расход памяти «Кодиеума»: пик операций на secparam1264 и отсутствие утечек.

Пик памяти — объём, который объекты Python занимали во время операции
сверх занятого до неё (модуль tracemalloc); утечки ищутся по числу
выделенных блоков. Обе функции — в measure.py в корне.
"""

import pytest

from kodieum import kem
from kodieum.params import SECPARAM1264, Params, _p_vector
from measure import peak_memory, retained_blocks

KIB = 1024
MIB = 1024 * KIB
SMALL = Params("m10", n=600, m=10, t=12, p=_p_vector(3))


@pytest.fixture(scope="module")
def keys():
    (pk, sk), peak = peak_memory(kem.keygen, SECPARAM1264, 1)
    return pk, sk, peak


def test_keygen_peak_memory(keys):
    # Проверочная матрица H — mt × n = 768 × 3520 бит, около 330 КиБ в битах,
    # плюс таблицы степеней поля из 2¹² элементов. Замер: около 1,1 МиБ.
    assert keys[2] < 4 * MIB


def test_encaps_needs_little_memory(keys):
    pk, _, _ = keys
    _, peak = peak_memory(kem.encaps, SECPARAM1264, pk, 7)
    # Encaps не копирует матрицу A: синдром считается построчно. Замер: 10 КиБ.
    assert peak < 256 * KIB


def test_decaps_peak_memory(keys):
    pk, sk, _ = keys
    shk, enk = kem.encaps(SECPARAM1264, pk, 7)
    result, peak = peak_memory(kem.decaps, SECPARAM1264, sk, enk)
    assert result == shk
    # Больше всего занимает таблица b_{j,i} шагов 11–15 Decode:
    # mt · 2t = 768 · 128 = 98 304 элемента поля. Замер: около 4,8 МиБ.
    assert peak < 16 * MIB


def test_repeated_encaps_and_decaps_do_not_accumulate_memory():
    pk, sk = kem.keygen(SMALL, seed1=1)

    def cycle():
        shk, enk = kem.encaps(SMALL, pk)
        assert kem.decaps(SMALL, sk, enk) == shk

    # Утечка хотя бы одного объекта за цикл дала бы прирост не меньше 20 блоков.
    assert retained_blocks(cycle, repeats=20) < 10
