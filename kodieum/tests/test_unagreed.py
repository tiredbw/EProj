"""Режим без предварительного согласования параметров (раздел 7)."""

import pytest

from kodieum import kem, unagreed
from kodieum.params import SECPARAM1264, Params, _p_vector
from kodieum.vectors import BitVector, Matrix

SMALL = Params("m8", n=120, m=8, t=5, p=_p_vector(2, 3, 4))


@pytest.mark.parametrize("params", [SMALL, SECPARAM1264], ids=lambda p: p.name)
def test_roundtrip_without_agreed_parameters(params):
    pk, sk = unagreed.keygen(params, seed1=1)
    shk, enk = unagreed.encaps(pk, seed3=2)
    assert enk.length == params.mt
    assert unagreed.decaps(sk, enk) == shk


def test_keys_carry_what_the_other_side_derives():
    pk, (seed2, salt, p) = unagreed.keygen(SMALL, seed1=1)
    A, t = pk
    assert (len(A.rows), A.columns, t) == (SMALL.mt, SMALL.n - SMALL.mt, SMALL.t)
    assert salt.length == SMALL.n
    assert p == BitVector(SMALL.p, SMALL.m - 1)


def test_same_keys_as_agreed_mode():
    pk, (seed2, salt, _) = unagreed.keygen(SMALL, seed1=4)
    pk_agreed, sk_agreed = kem.keygen(SMALL, seed1=4)
    assert pk[0].rows == pk_agreed and (seed2, salt.value) == sk_agreed
    shk, enk = unagreed.encaps(pk, seed3=5)
    assert (shk, enk.value) == kem.encaps(SMALL, pk_agreed, seed3=5)


def test_keygen2_and_decaps2_without_agreed_parameters():
    pk, sk2 = unagreed.keygen2(SMALL, seed1=1)
    shk, enk = unagreed.encaps(pk, seed3=2, long_key=True)
    assert unagreed.decaps2(sk2, enk, long_key=True) == shk


def test_corrupted_ciphertext_is_rejected():
    pk, sk = unagreed.keygen(SMALL, seed1=1)
    shk, enk = unagreed.encaps(pk, seed3=2)
    bad = BitVector(enk.value ^ 1, enk.length)
    assert unagreed.decaps(sk, bad) != shk


def test_inconsistent_lengths_are_rejected():
    pk, (seed2, salt, p) = unagreed.keygen(SMALL, seed1=1)
    with pytest.raises(ValueError):
        unagreed.encaps((pk[0], SMALL.t + 1))           # r не делится на t
    with pytest.raises(ValueError):
        unagreed.encaps((Matrix([0] * 12, 1), 6))       # n = 13, m = 2: n + t ⩾ 2^m
    with pytest.raises(ValueError):
        unagreed.decaps((seed2, salt, p), BitVector(0, SMALL.mt + 1))   # r не делится на m


def test_bit_vector_and_matrix_check_lengths():
    with pytest.raises(ValueError):
        BitVector(0b100, 2)
    with pytest.raises(ValueError):
        Matrix([0b100], 2)
