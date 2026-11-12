"""Наборы параметров из таблицы 2 приложения А."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Params:
    name: str
    n: int
    m: int
    t: int
    # Вектор (p_0, …, p_{m-2}) многочлена p(x) = 1 + p_0·x + … + p_{m-2}·x^{m-1} + x^m;
    # бит i числа — коэффициент при x^{i+1}.
    p: int

    def __post_init__(self):
        if not self.m * self.t < self.n < (1 << self.m) - self.t:
            raise ValueError(f"{self.name}: нужно mt < n и n + t < 2^m")
        if self.n % 8:
            raise ValueError(f"{self.name}: HKDF в KeyGen требует n, кратное 8")
        if self.p >> (self.m - 1):
            raise ValueError(f"{self.name}: вектор p длиннее m − 1 бит")

    @property
    def mt(self) -> int:
        return self.m * self.t


def _p_vector(*powers: int) -> int:
    """Вектор p по степеням x^k (1 ⩽ k ⩽ m-1), входящим в p(x) кроме 1 и x^m."""
    return sum(1 << (k - 1) for k in powers)


SECPARAM1264 = Params("secparam1264", n=3520, m=12, t=64, p=_p_vector(1, 4, 6))
SECPARAM1396 = Params("secparam1396", n=5504, m=13, t=96, p=_p_vector(1, 3, 4))
SECPARAM14128 = Params("secparam14128", n=7744, m=14, t=128, p=_p_vector(1, 6, 10))
