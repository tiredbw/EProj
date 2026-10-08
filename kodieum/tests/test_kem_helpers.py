from kem_helpers import gen_unique_seq, gen_weight_vec


def test_gen_unique_seq_returns_n_distinct_values_in_range():
    seq = gen_unique_seq(m=6, n=40, k=b"\x01" * 32)
    assert len(seq) == 40
    assert len(set(seq)) == 40
    assert all(0 <= v < (1 << 6) for v in seq)


def test_gen_unique_seq_rejects_n_not_less_than_2m():
    try:
        gen_unique_seq(m=4, n=16, k=b"\x00" * 32)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_gen_weight_vec_has_exact_weight_and_fits_length():
    n, t = 3520, 64
    e = gen_weight_vec(n=n, t=t, m=12, seed=b"\x02" * 32)
    assert bin(e).count("1") == t
    assert e.bit_length() <= n


def test_gen_unique_seq_n_zero_returns_empty():
    assert gen_unique_seq(m=6, n=0, k=b"\x00" * 32) == []


def test_gen_unique_seq_n_equals_max_valid():
    # граничное значение: n = 2^m - 1, наибольшее допустимое по условию n < 2^m
    seq = gen_unique_seq(m=6, n=63, k=b"\x01" * 32)
    assert len(seq) == 63
    assert len(set(seq)) == 63


def test_gen_weight_vec_t_zero_returns_zero_vector():
    assert gen_weight_vec(n=10, t=0, m=4, seed=b"\x00" * 32) == 0


def test_gen_weight_vec_t_equals_n_sets_every_bit():
    e = gen_weight_vec(n=8, t=8, m=4, seed=b"\x03" * 32)
    assert e == (1 << 8) - 1
