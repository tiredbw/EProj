"""Строки, кольцо R_q, сжатие, кодирование, выборка (разделы 5 и 7.1–7.4)."""

import random

import pytest

from zemlyanika import ring
from zemlyanika.bits import bits_to_bytes, bits_to_int, bytes_to_bits, int_to_bits, substring
from zemlyanika.encoding import decode, encode
from zemlyanika.params import N
from zemlyanika.prng import r006_2017
from zemlyanika.sampling import cbd, matrix_gen

rng = random.Random(2026)


def random_poly(q):
    return [rng.randrange(q) for _ in range(N)]


def test_bit_strings_follow_section_5_1():
    b = [1, 0, 1, 1, 0, 0, 0, 0, 1]
    assert bits_to_int(b) == 0b100001101
    assert int_to_bits(0b100001101, 9) == b
    # байт — bits_to_int восьми бит, бит 0 строки — младший бит первого байта
    assert bits_to_bytes(0b1_00000001, 16) == b"\x01\x01"
    assert bytes_to_bits(b"\x01\x80") == 1 | (1 << 15)
    assert substring(0b110100, 2, 5) == 0b101
    with pytest.raises(ValueError):
        bits_to_bytes(1, 7)


@pytest.mark.parametrize("q", [1024, 2048])
def test_fast_multiplication_matches_formula_12(q):
    for _ in range(3):
        a, b = random_poly(q), random_poly(q)
        assert ring.mul(a, b, q) == ring.mul_by_definition(a, b, q)


def test_x_to_256_is_minus_one():
    x = [0] * N
    x[1] = 1
    x255 = [0] * N
    x255[255] = 1
    assert ring.mul(x, x255, 1024) == [1023] + [0] * (N - 1)


@pytest.mark.parametrize("d, t", [(0, 10), (1, 11), (5, 11), (6, 10)])
def test_compress_error_is_at_most_half_step(d, t):
    q = 1 << t
    for a in range(q):
        back = ring.decompress(ring.compress(a, d, t), d)
        err = min((back - a) % q, (a - back) % q)
        assert err <= (1 << d) // 2
        assert ring.compress(a, d, t) < 1 << (t - d)


@pytest.mark.parametrize("s", [4, 6, 10, 11])
def test_encode_decode_roundtrip(s):
    poly = [rng.randrange(1 << s) for _ in range(N)]
    data = encode(poly, s)
    assert len(data) == 32 * s
    assert decode(data, s) == poly
    with pytest.raises(ValueError):
        encode([1 << s] + poly[1:], s)
    with pytest.raises(ValueError):
        decode(data[:-1], s)


def test_matrix_gen_reads_t_bits_per_coefficient_in_order():
    k, t = 2, 10
    coefs = [rng.randrange(1 << t) for _ in range(N * k * k)]
    buf = sum(c << (t * i) for i, c in enumerate(coefs))
    matrix = matrix_gen(buf, N * k * k * t, k, t)
    assert matrix[0][0] == coefs[:N] and matrix[0][1] == coefs[N : 2 * N] and matrix[1][1] == coefs[3 * N :]
    with pytest.raises(ValueError):
        matrix_gen(buf, 256, k, t)  # буквальный шаг 1 алгоритма 6: только 256 бит seed_A


@pytest.mark.parametrize("eta", [1, 2])
def test_cbd_is_centered_binomial(eta):
    q = 2048
    length = 2 * N * eta * 4
    polys = cbd(eta, 4, r006_2017(12345, length), length, q)
    values = [x if x <= q // 2 else x - q for p in polys for x in p]
    assert all(-eta <= x <= eta for x in values)
    assert abs(sum(values) / len(values)) < 0.15
    # пара бит 10 даёт +1, 01 — −1, 11 и 00 — 0
    assert cbd(1, 1, 0b01, 2 * N, q)[0][0] == 1 and cbd(1, 1, 0b10, 2 * N, q)[0][0] == q - 1


def test_prng_prefix_and_length():
    long = r006_2017(7, 1500)
    assert long < 1 << 1500
    assert r006_2017(7, 512) == long & ((1 << 512) - 1)
    assert r006_2017(7, 700) == long & ((1 << 700) - 1)
    assert r006_2017(8, 512) != r006_2017(7, 512)
    with pytest.raises(ValueError):
        r006_2017(1 << 256, 512)
