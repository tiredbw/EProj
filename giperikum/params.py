"""Наборы параметров «Гиперикум» (раздел 5.3, таблица 1)."""

from dataclasses import dataclass

N = 32  # n = 256 бит: длина хэш-кода, узла дерева и элемента цепочки, в байтах
W = 16  # параметр w: элементы цепочки WOTS+C от 0 до 15
CHAINS = 64  # l: 256-битное сообщение даёт 64 шестнадцатеричных разряда
# S_{w,n}: в разделе 4.6.4 написано l·w/2 = 512, но подписи приложения А
# получаются только при l·(w − 1)/2 = 480 — среднем значении суммы разрядов.
TARGET_SUM = CHAINS * (W - 1) // 2


@dataclass(frozen=True)
class Params:
    name: str
    h: int  # высота гипердерева
    d: int  # число уровней
    b: int  # высота дерева FORS+C
    k: int  # k' = k − 1 деревьев FORS+C

    def __post_init__(self):
        if self.h % self.d:
            raise ValueError(f"{self.name}: h должно делиться на d")
        if self.k < 2 or self.b < 1:
            raise ValueError(f"{self.name}: нужно k ⩾ 2 и b ⩾ 1")
        if self.h - self.h_prime > 64 or self.h_prime > 32 or self.k_prime << self.b >= 1 << 32:
            raise ValueError(f"{self.name}: номера дерева, листа или узла FORS не помещаются в поля ADRS")
        if (self.k * self.b + 7) // 8 + (self.h - self.h_prime + 7) // 8 + (self.h_prime + 7) // 8 > 64:
            raise ValueError(f"{self.name}: индексам не хватает 512 бит хэш-кода сообщения")

    @property
    def h_prime(self) -> int:
        return self.h // self.d

    @property
    def k_prime(self) -> int:
        return self.k - 1

    @property
    def signature_size(self) -> int:
        """Формула (18): 36 + k'(b + 1)·n + d·(64·n + 4 + h/d·n)."""
        return 36 + self.k_prime * (self.b + 1) * N + self.d * (CHAINS * N + 4 + self.h_prime * N)


B_256_64 = Params("Гиперикум_Б_256_64", h=66, d=22, b=9, k=38)
M_256_64 = Params("Гиперикум_М_256_64", h=68, d=4, b=18, k=15)
B_256_20 = Params("Гиперикум_Б_256_20", h=21, d=7, b=10, k=36)
M_256_20 = Params("Гиперикум_М_256_20", h=26, d=2, b=18, k=15)
B_128_20 = Params("Гиперикум_Б_128_20", h=20, d=5, b=9, k=18)
M_128_20 = Params("Гиперикум_М_128_20", h=20, d=2, b=11, k=14)

ALL = [B_256_64, M_256_64, B_256_20, M_256_20, B_128_20, M_128_20]
