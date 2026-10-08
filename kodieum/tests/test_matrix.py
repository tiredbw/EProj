from gf import GF2m
from kem import _build_parity_check_matrix, _row_reduce_to_systematic, keygen

FIELD = GF2m(m=12, p=0b00000101001)
N, T = 40, 2
MT = FIELD.m * T


def test_build_parity_check_matrix_shape():
    from kem_helpers import gen_unique_seq

    ell = gen_unique_seq(FIELD.m, N + T, b"\x09" * 32)
    a, g = ell[:N], ell[N:]
    h_rows = _build_parity_check_matrix(FIELD, a, g, N, T)
    assert len(h_rows) == MT
    assert all(row.bit_length() <= N for row in h_rows)


def test_row_reduce_is_idempotent_on_its_own_output():
    # (I_mt | A) уже в систематическом виде: повторное приведение должно
    # вернуть ту же матрицу A без изменений.
    pk, _sk = keygen(FIELD, N, T)
    full_rows = [(1 << i) | (pk[i] << MT) for i in range(MT)]
    assert _row_reduce_to_systematic(full_rows, N, MT) == pk


def test_row_reduce_returns_none_for_singular_matrix():
    # Две одинаковые строки делают первые MT столбцов невозможными для
    # приведения к единичной матрице.
    rows = [0b11] * MT
    assert _row_reduce_to_systematic(rows, N, MT) is None
