"""KeyGen, Encaps, Decaps (раздел 8) на малых и полных параметрах."""

import random

import pytest

from kodieum import goppa, kem
from kodieum.decode import decode
from kodieum.field import Field
from kodieum.params import SECPARAM1264, Params, _p_vector
from kodieum.primitives import h256, hkdf
from kodieum.vectors import serialize

SMALL = [
    Params("m6", n=40, m=6, t=2, p=_p_vector(1)),
    Params("m8", n=120, m=8, t=5, p=_p_vector(2, 3, 4)),
    Params("m10", n=600, m=10, t=12, p=_p_vector(3)),
]


def parity(x: int) -> int:
    return x.bit_count() & 1


@pytest.mark.parametrize("params", SMALL, ids=lambda p: p.name)
def test_public_matrix_is_systematic_form_of_h(params):
    field = Field(params.m, params.p)
    pk, (seed2, _) = kem.keygen(params, seed1=1)
    a, g = kem.support_and_goppa(params, seed2)
    H = goppa.parity_check_matrix(field, a, g, params.t)
    # (I_mt ‖ A) получена из H сложением строк, поэтому у них общее ядро:
    # вектор, ортогональный всем строкам (I ‖ A), ортогонален и строкам H.
    mt = params.mt
    for j in range(params.n - mt):
        x = 1 << (mt + j)
        for i, row in enumerate(pk):
            if (row >> j) & 1:
                x |= 1 << i
        assert all(parity(row & x) == 0 for row in H)


def test_systematic_part_fails_on_degenerate_matrix():
    rows = [0b0110, 0b1010, 0b1100]  # нулевой первый столбец
    assert goppa.systematic_part(rows, 3) is None


def test_syndrome_is_product_with_i_and_a():
    pk = [0b101, 0b011]  # A размера 2 × 3
    mt = 2
    for e in range(1 << 5):
        expected = 0
        for i, row in enumerate(pk):
            full_row = (1 << i) | (row << mt)
            expected |= parity(full_row & e) << i
        assert kem.syndrome(pk, e, mt) == expected


@pytest.mark.parametrize("params", SMALL, ids=lambda p: p.name)
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_roundtrip_small(params, seed):
    pk, sk = kem.keygen(params, seed1=seed)
    shk, enk = kem.encaps(params, pk, seed3=seed + 100)
    assert len(shk) == 32
    assert kem.decaps(params, sk, enk) == shk


@pytest.mark.parametrize("params", SMALL, ids=lambda p: p.name)
def test_decode_recovers_error_vector(params):
    field = Field(params.m, params.p)
    pk, (seed2, _) = kem.keygen(params, seed1=5)
    a, g = kem.support_and_goppa(params, seed2)
    e = sum(1 << i for i in range(0, 2 * params.t, 2))
    s = kem.syndrome(pk, e, params.mt)
    assert decode(field, a, g, s, params.n, params.t) == e


@pytest.mark.parametrize("params", SMALL, ids=lambda p: p.name)
def test_decaps_rejects_corrupted_ciphertext(params):
    pk, sk = kem.keygen(params, seed1=7)
    shk, enk = kem.encaps(params, pk, seed3=8)
    e = next(i for i in range(params.mt) if not (enk >> i) & 1)
    bad = enk ^ (1 << e)
    seed2, salt = sk
    field = Field(params.m, params.p)
    a, g = kem.support_and_goppa(params, seed2)
    assert decode(field, a, g, bad, params.n, params.t) is None
    rejected = kem.decaps(params, sk, bad)
    assert rejected != shk
    assert rejected == h256(serialize(salt, params.n) + serialize(bad, params.mt))


def test_decaps_rejects_too_long_ciphertext():
    params = SMALL[0]
    _, sk = kem.keygen(params, seed1=1)
    with pytest.raises(ValueError):
        kem.decaps(params, sk, 1 << params.mt)


@pytest.mark.parametrize("n, m, t, p", [(10, 6, 2, 1), (61, 6, 2, 1), (44, 6, 2, 1), (40, 6, 2, 1 << 5)])
def test_params_validation(n, m, t, p):
    # mt ≥ n; n + t ≥ 2^m; n не кратно 8; p шире m − 1 бит.
    with pytest.raises(ValueError):
        Params("bad", n=n, m=m, t=t, p=p)


@pytest.mark.parametrize("params", [
    Params("min_n", n=16, m=6, t=2, p=_p_vector(1)),   # наименьшее n > mt, кратное 8
    Params("max_n", n=56, m=6, t=2, p=_p_vector(1)),   # наибольшее n с n + t < 2^m, кратное 8
], ids=lambda p: p.name)
def test_roundtrip_boundary_lengths(params):
    pk, sk = kem.keygen(params, seed1=3)
    shk, enk = kem.encaps(params, pk, seed3=4)
    assert kem.decaps(params, sk, enk) == shk


def test_keygen_retries_with_seed_prime():
    params = SMALL[1]
    seed1 = next(x for x in range(1, 100) if kem.public_matrix(params, hkdf(x, 512 + params.n) & ((1 << 256) - 1)) is None)
    seed_prime = (hkdf(seed1, 512 + params.n) >> 256) & ((1 << 256) - 1)
    assert kem.keygen(params, seed1=seed1) == kem.keygen(params, seed1=seed_prime)


@pytest.mark.parametrize("params", SMALL, ids=lambda p: p.name)
def test_keygen2_and_decaps2(params):
    pk, (seed2, salt) = kem.keygen(params, seed1=9)
    pk2, (ell, salt2) = kem.keygen2(params, seed1=9)
    assert pk2 == pk and salt2 == salt
    assert ell == kem.support_and_goppa(params, seed2)[0] + kem.support_and_goppa(params, seed2)[1]
    shk, enk = kem.encaps(params, pk, seed3=10)
    assert kem.decaps2(params, (ell, salt), enk) == shk
    bad = enk ^ 1
    assert kem.decaps2(params, (ell, salt), bad) == kem.decaps(params, (seed2, salt), bad)


def test_long_key_uses_streebog_512():
    params = SMALL[0]
    pk, sk = kem.keygen(params, seed1=1)
    shk, enk = kem.encaps(params, pk, seed3=2, long_key=True)
    assert len(shk) == 64
    assert kem.decaps(params, sk, enk, long_key=True) == shk
    assert kem.decaps(params, sk, enk) == kem.encaps(params, pk, seed3=2)[0]


def test_zero_ciphertext_is_rejected():
    params = SMALL[1]
    pk, (seed2, salt) = kem.keygen(params, seed1=6)
    assert kem.decaps(params, (seed2, salt), 0) == kem.rejection_key(salt, params.n, 0, params.mt)


def test_decaps_rejects_decode_result_with_wrong_syndrome():
    # Decode (6.3) не проверяет синдром найденного e; на малом коде это видно на случайных s.
    params = SMALL[0]
    field = Field(params.m, params.p)
    pk, (seed2, salt) = kem.keygen(params, seed1=11)
    a, g = kem.support_and_goppa(params, seed2)
    rng = random.Random(1)
    for _ in range(1000):
        s = rng.getrandbits(params.mt)
        e = decode(field, a, g, s, params.n, params.t)
        if e is not None and kem.syndrome(pk, e, params.mt) != s:
            break
    else:
        pytest.fail("не найден синдром, на котором Decode ошибается")
    assert e.bit_count() == params.t
    assert kem.decaps(params, (seed2, salt), s) == kem.rejection_key(salt, params.n, s, params.mt)


def test_encaps_and_decaps2_validate_inputs():
    params = SMALL[0]
    pk, sk = kem.keygen2(params, seed1=1)
    with pytest.raises(ValueError):
        kem.encaps(params, pk[:-1])
    with pytest.raises(ValueError):
        kem.encaps(params, [1 << (params.n - params.mt)] + pk[1:])
    with pytest.raises(ValueError):
        kem.decaps2(params, (sk[0][:-1], sk[1]), 0)


def test_roundtrip_secparam1264():
    pk, sk = kem.keygen(SECPARAM1264, seed1=2026)
    assert len(pk) == SECPARAM1264.mt
    shk, enk = kem.encaps(SECPARAM1264, pk, seed3=10)
    assert kem.decaps(SECPARAM1264, sk, enk) == shk
