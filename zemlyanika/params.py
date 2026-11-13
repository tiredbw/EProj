"""Наборы параметров «Земляники» (раздел 9, таблица 1)."""

from dataclasses import dataclass

N = 256  # степень x^256 + 1, число коэффициентов многочлена


@dataclass(frozen=True)
class Params:
    name: str
    q: int
    k: int
    eta_s: int
    eta_e: int
    du: int
    dv: int

    def __post_init__(self):
        if self.q < 4 or self.q & (self.q - 1):
            raise ValueError(f"{self.name}: q должно быть степенью двойки 2^t, t > 1")
        if self.k < 1 or self.eta_s < 1 or self.eta_e < 1:
            raise ValueError(f"{self.name}: нужно k, η_s, η_e ⩾ 1")
        if not (0 <= self.du < self.t and 0 <= self.dv < self.t):
            raise ValueError(f"{self.name}: нужно 0 ⩽ d_u, d_v < t")

    @property
    def t(self) -> int:
        return self.q.bit_length() - 1

    @property
    def pk_size(self) -> int:
        """32 байта seed_A и k многочленов по 32·t байт (алгоритм 5)."""
        return 32 + 32 * self.k * self.t

    @property
    def ct_size(self) -> int:
        """32·(t − d_v) + 32·k·(t − d_u) байт (раздел 7.5)."""
        return 32 * (self.t - self.dv) + 32 * self.k * (self.t - self.du)

    @property
    def pke_sk_size(self) -> int:
        """sk′ = 512·k·η_s бит секретного буфера (алгоритм 5, шаг 14)."""
        return 64 * self.k * self.eta_s

    @property
    def sk_size(self) -> int:
        """sk = sk′ ‖ pk ‖ h ‖ Z (алгоритм 8)."""
        return self.pke_sk_size + self.pk_size + 32 + 32


Z512 = Params("Z512", q=1024, k=2, eta_s=1, eta_e=1, du=0, dv=6)
Z768_R = Params("Z768-R", q=1024, k=3, eta_s=1, eta_e=1, du=0, dv=0)
Z768_C = Params("Z768-C", q=2048, k=3, eta_s=2, eta_e=1, du=1, dv=5)
Z1024 = Params("Z1024", q=2048, k=4, eta_s=2, eta_e=1, du=0, dv=6)

ALL = [Z512, Z768_R, Z768_C, Z1024]

# Размеры из таблицы 1 документа: (|sk|, |pk|, |ct|) в байтах.
TABLE_1_SIZES = {"Z512": (864, 672, 768), "Z768-R": (1248, 992, 1280),
                 "Z768-C": (1440, 1088, 1152), "Z1024": (1888, 1440, 1568)}
