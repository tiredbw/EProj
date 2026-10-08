import pytest

from gf import GF2m
from kem import decaps, encaps, keygen

# Реальный примитивный многочлен secparam1264, но маленькие n, t — для
# быстрых тестов используем настоящее поле F_2^12 (проверено как примитивное
# в test_gf.py) с уменьшенными n и t, не зависящими от значений в Приложении Б.
FIELD = GF2m(m=12, p=0b00000101001)
N, T = 40, 2


def test_round_trip_shared_key_matches():
    pk, sk = keygen(FIELD, N, T)
    shk_a, enk = encaps(FIELD, N, T, pk)
    shk_b = decaps(FIELD, N, T, sk, enk)
    assert shk_a == shk_b


@pytest.mark.parametrize("trial", range(5))
def test_round_trip_is_reliable_across_random_keys(trial):
    pk, sk = keygen(FIELD, N, T)
    shk_a, enk = encaps(FIELD, N, T, pk)
    shk_b = decaps(FIELD, N, T, sk, enk)
    assert shk_a == shk_b


def test_corrupted_ciphertext_yields_different_shared_key():
    pk, sk = keygen(FIELD, N, T)
    shk_a, enk = encaps(FIELD, N, T, pk)
    shk_b = decaps(FIELD, N, T, sk, enk ^ 1)
    assert shk_a != shk_b
