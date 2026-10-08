from gf import GF2m
from decode import _solve_homogeneous_system

FIELD = GF2m(m=4, p=0b0011)  # p(x) = 1 + x + x^4


def test_solver_finds_nonzero_kernel_vector_for_rank_deficient_system():
    # 2 уравнения, 3 неизвестных: x0+x1=0, x1+x2=0 над F_2^4 (коэффициенты 1)
    rows = [[1, 1, 0], [0, 1, 1]]
    solution = _solve_homogeneous_system(FIELD, rows, 3)
    assert solution is not None
    assert any(x != 0 for x in solution)
    for row in rows:
        acc = 0
        for coeff, x in zip(row, solution):
            acc = FIELD.add(acc, FIELD.mul(coeff, x))
        assert acc == 0


def test_solver_returns_none_for_full_rank_system():
    rows = [[1, 0], [0, 1]]
    assert _solve_homogeneous_system(FIELD, rows, 2) is None
