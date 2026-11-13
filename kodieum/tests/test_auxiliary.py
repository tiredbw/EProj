"""gen_unique_seq (6.1), gen_weight_vec (6.2) и обёртки над ГОСТ-примитивами."""

import pytest

from kodieum.auxiliary import gen_unique_seq, gen_weight_vec, weight_vec_from_v
from kodieum.primitives import BlockCipher


def test_block_cipher_uses_gost_notation():
    # Контрольный пример ГОСТ 34.12-2018: ключ, блок и результат — числа Vec_256/Vec_128.
    cipher = BlockCipher(0x8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF)
    assert cipher.encrypt(0x1122334455667700FFEEDDCCBBAA9988) == 0x7F679D90BEBC24305A468D42B9D4EDCD


def test_unique_seq_is_distinct_and_in_range():
    seq = gen_unique_seq(8, 200, 12345)
    assert len(seq) == 200
    assert len(set(seq)) == 200
    assert all(0 <= x < 256 for x in seq)


def test_unique_seq_depends_on_key():
    assert gen_unique_seq(8, 50, 1) != gen_unique_seq(8, 50, 2)


@pytest.mark.parametrize("n", [0, 256])
def test_unique_seq_rejects_bad_length(n):
    with pytest.raises(ValueError):
        gen_unique_seq(8, n, 1)


def test_weight_vec_from_v_takes_first_t_values_below_n():
    # m = 4, n = 10, ℓ = 2: из 16-битных слов берутся младшие 4 бита.
    words = [3, 12, 7, 0xFFF5, 15, 1]
    v = sum(w << (16 * i) for i, w in enumerate(words))
    assert weight_vec_from_v(10, 3, 4, v) == (1 << 3) | (1 << 7) | (1 << 5)


def test_weight_vec_from_v_requests_reseed():
    assert weight_vec_from_v(10, 3, 4, 0) is None                # повторы
    assert weight_vec_from_v(10, 3, 4, 0xF000F000F000F) is None  # мало значений < n


def test_gen_weight_vec():
    e = gen_weight_vec(3520, 64, 12, 777)
    assert e.bit_count() == 64
    assert e < 1 << 3520
    assert gen_weight_vec(3520, 64, 12, 777) == e


@pytest.mark.parametrize("n", [1, 255])
def test_unique_seq_boundary_lengths(n):
    seq = gen_unique_seq(8, n, 7)
    assert len(set(seq)) == n
    assert seq == gen_unique_seq(8, 256 - 1, 7)[:n]


@pytest.mark.parametrize("n, t", [(128, 1), (128, 8), (300, 10)])
def test_weight_vec_boundaries(n, t):
    # n = 128 даёт ℓ ровно 2 (n·ℓ = 2^8), n = 300 > 2^8 даёт ℓ = 1.
    e = gen_weight_vec(n, t, 8, 5)
    assert e.bit_count() == t
    assert e < 1 << n


def test_weight_vec_requires_m_at_most_16():
    with pytest.raises(ValueError):
        weight_vec_from_v(10, 3, 17, 0)
