from decode import _solve_homogeneous_system, decode
from gf import GF2m
from kem import _compute_syndrome, keygen
from kem_helpers import gen_unique_seq, gen_weight_vec

FIELD = GF2m(m=4, p=0b0011)  # p(x) = 1 + x + x^4

# Реальное (проверенное как примитивное в test_gf.py) поле secparam1264,
# но с уменьшенными n, t — для прямой проверки decode() без прогона
# полного KeyGen/Encaps/Decaps.
REAL_FIELD = GF2m(m=12, p=0b00000101001)
N, T = 40, 2
MT = REAL_FIELD.m * T


def test_decode_recovers_a_known_error_vector():
    pk, sk = keygen(REAL_FIELD, N, T)
    seed2, _salt = sk
    ell = gen_unique_seq(REAL_FIELD.m, N + T, seed2)
    a, g = ell[:N], ell[N:]

    e = gen_weight_vec(N, T, REAL_FIELD.m, b"\x07" * 32)
    s = _compute_syndrome(pk, e, N, MT)

    recovered = decode(REAL_FIELD, a, g, s, N, T)
    assert recovered == e


def test_decode_returns_none_for_an_arbitrary_syndrome():
    # Синдромов, соответствующих весу-t ошибке, исчезающе мало среди всех
    # 2^mt значений (C(40,2)=780 из 2^24≈16.7M) — произвольный s почти
    # наверняка не декодируется, что и проверяет путь отказа (⊥).
    pk, sk = keygen(REAL_FIELD, N, T)
    seed2, _salt = sk
    ell = gen_unique_seq(REAL_FIELD.m, N + T, seed2)
    a, g = ell[:N], ell[N:]

    arbitrary_s = 0x123456 & ((1 << MT) - 1)
    assert decode(REAL_FIELD, a, g, arbitrary_s, N, T) is None


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
