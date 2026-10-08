import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gf import GF2m

# secparam1264: p(x) = 1 + x + x^4 + x^6 + x^12
FIELD = GF2m(m=12, p=0b00000101001)  # p0..p10 = 1,0,0,1,0,1,0,0,0,0,0


def test_add_is_xor_and_self_inverse():
    a, b = 0x3ab, 0x5c
    assert FIELD.add(a, b) == a ^ b
    assert FIELD.add(FIELD.add(a, b), b) == a


def test_mul_by_zero_and_one():
    a = 0x3ab
    assert FIELD.mul(a, 0) == 0
    assert FIELD.mul(a, 1) == a


def test_mul_is_commutative_for_sample_elements():
    a, b = 0x3ab, 0x5c
    assert FIELD.mul(a, b) == FIELD.mul(b, a)


def test_inverse_round_trip():
    for a in (1, 2, 5, 0xabc, 0xfff):
        inv = FIELD.inv(a)
        assert FIELD.mul(a, inv) == 1


def test_inverse_of_zero_raises():
    try:
        FIELD.inv(0)
        assert False, "expected ZeroDivisionError"
    except ZeroDivisionError:
        pass
