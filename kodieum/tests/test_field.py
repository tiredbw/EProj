"""Арифметика F_{2^m} (раздел 5.3)."""

import random

import pytest

from kodieum.field import Field
from kodieum.params import SECPARAM1264, SECPARAM1396, SECPARAM14128, _p_vector

ALL_PARAMS = [SECPARAM1264, SECPARAM1396, SECPARAM14128]


@pytest.mark.parametrize("params", ALL_PARAMS, ids=lambda p: p.name)
def test_polynomials_from_appendix_a_are_primitive(params):
    field = Field(params.m, params.p)
    assert len(set(field.exp[: field.order])) == field.order


def test_non_primitive_polynomial_rejected():
    # 1 + x + x^2 + x^3 + x^4 неприводим, но x имеет порядок 5, а не 15.
    with pytest.raises(ValueError):
        Field(4, _p_vector(1, 2, 3))


def test_too_wide_p_rejected():
    with pytest.raises(ValueError):
        Field(4, 0b1000)


def test_fshift_is_multiplication_by_x():
    field = Field(SECPARAM1264.m, SECPARAM1264.p)
    for a in range(1 << field.m):
        assert field.fshift(a) == field.mul_by_definition(a, 2)


def test_fshift_reduces_by_p():
    # m = 12, p(x) = 1 + x + x^4 + x^6 + x^12: x^11 · x = x^12 = 1 + x + x^4 + x^6.
    field = Field(SECPARAM1264.m, SECPARAM1264.p)
    assert field.fshift(1 << 11) == 0b1010011


def test_table_mul_matches_definition_exhaustively_small_field():
    field = Field(6, _p_vector(1))
    for a in range(64):
        for b in range(64):
            assert field.mul(a, b) == field.mul_by_definition(a, b)


@pytest.mark.parametrize("params", ALL_PARAMS, ids=lambda p: p.name)
def test_table_mul_matches_definition_random(params):
    field = Field(params.m, params.p)
    rng = random.Random(params.m)
    for _ in range(2000):
        a, b = rng.randrange(1 << params.m), rng.randrange(1 << params.m)
        assert field.mul(a, b) == field.mul_by_definition(a, b)


def test_inverse():
    field = Field(SECPARAM1264.m, SECPARAM1264.p)
    for a in range(1, 1 << field.m):
        assert field.mul(a, field.inv(a)) == 1
    with pytest.raises(ZeroDivisionError):
        field.inv(0)


def test_pow():
    field = Field(SECPARAM1264.m, SECPARAM1264.p)
    a = 0x5a3
    acc = 1
    for k in range(20):
        assert field.pow(a, k) == acc
        acc = field.mul_by_definition(acc, a)
    assert field.pow(0, 0) == 1 and field.pow(0, 5) == 0
