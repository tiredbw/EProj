"""Арифметика в конечном поле F_2^m (раздел 5.3 МР ТК26 "Кодиеум").

Элемент поля F_2^m представлен как Python int в диапазоне [0, 2^m - 1],
где бит i числа соответствует координате x_i вектора x = (x_0, ..., x_{m-1})
из раздела 5.2: x = sum(x_i * 2^i).

Примитивный многочлен p(x) = 1 + p_0*x + ... + p_{m-2}*x^{m-1} + x^m
задаётся вектором p = (p_0, ..., p_{m-2}) длины m-1, также представленным
как int (бит i соответствует p_i).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class GF2m:
    m: int
    p: int  # вектор (p_0, ..., p_{m-2}) как битовая маска, бит i = p_i

    @property
    def order(self) -> int:
        return 1 << self.m

    def bit(self, a: int, i: int) -> int:
        return (a >> i) & 1

    def fshift(self, a: int) -> int:
        """fshift(p, a) из раздела 5.3: один шаг LFSR-сдвига."""
        m = self.m
        top = self.bit(a, m - 1)
        b = top  # b_0 = a_{m-1}
        for i in range(1, m):
            a_prev = self.bit(a, i - 1)
            p_prev = self.bit(self.p, i - 1)
            b_i = a_prev ^ (top & p_prev)
            b |= b_i << i
        return b

    def fshift_t(self, a: int, t: int) -> int:
        """fshift(p, a, t) из раздела 5.3: t последовательных применений fshift."""
        if t < 1:
            raise ValueError("t must be a positive natural number")
        b = a
        for _ in range(t):
            b = self.fshift(b)
        return b

    def add(self, a: int, b: int) -> int:
        return a ^ b

    def mul(self, a: int, b: int) -> int:
        """Произведение a*b согласно формуле раздела 5.3."""
        result = 0
        cur = b
        for i in range(self.m):
            if self.bit(a, i):
                result ^= cur
            cur = self.fshift(cur)
        return result

    def pow(self, a: int, n: int) -> int:
        if a == 0:
            if n == 0:
                raise ValueError("0^0 is undefined")
            return 0
        result = 1
        base = a
        while n > 0:
            if n & 1:
                result = self.mul(result, base)
            base = self.mul(base, base)
            n >>= 1
        return result

    def inv(self, a: int) -> int:
        """Обратный элемент a^{-1} = a^{2^m - 2}."""
        if a == 0:
            raise ZeroDivisionError("0 has no multiplicative inverse in F_2^m")
        return self.pow(a, self.order - 2)
