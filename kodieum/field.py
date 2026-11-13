"""Арифметика в конечном поле F_{2^m} (раздел 5.3).

Элемент поля — число 0 … 2^m − 1; бит i числа — коэффициент при x^i.
"""


class Field:
    def __init__(self, m: int, p: int):
        if p >> (m - 1):
            raise ValueError("вектор p длиннее m − 1 бит")
        self.m = m
        self.p = p
        self.order = (1 << m) - 1
        # Таблицы степеней примитивного элемента x: exp[k] = x^k, log[x^k] = k.
        # Строятся той же операцией fshift, что и в определении умножения.
        self.exp = [1] * (self.order + 1)
        for k in range(1, self.order + 1):
            self.exp[k] = self.fshift(self.exp[k - 1])
        if self.exp[self.order] != 1 or len(set(self.exp[: self.order])) != self.order:
            raise ValueError("многочлен p(x) не примитивный")
        self.log = [0] * (self.order + 1)
        for k in range(self.order):
            self.log[self.exp[k]] = k

    def fshift(self, a: int) -> int:
        """fshift(p, a): b_0 = a_{m-1}, b_i = a_{i-1} ⊕ a_{m-1}·p_{i-1} — умножение на x."""
        top = (a >> (self.m - 1)) & 1
        return ((a << 1) & self.order) ^ (top * (1 | (self.p << 1)))

    def mul_by_definition(self, a: int, b: int) -> int:
        """c = a_0·b ⊕ a_1·fshift(p, b, 1) ⊕ … ⊕ a_{m-1}·fshift(p, b, m-1)."""
        c = 0
        for i in range(self.m):
            if (a >> i) & 1:
                c ^= b
            b = self.fshift(b)
        return c

    def mul(self, a: int, b: int) -> int:
        """То же, что mul_by_definition, но через таблицы степеней x."""
        if a == 0 or b == 0:
            return 0
        return self.exp[(self.log[a] + self.log[b]) % self.order]

    def pow(self, a: int, k: int) -> int:
        if a == 0:
            return 0 if k else 1
        return self.exp[(self.log[a] * k) % self.order]

    def inv(self, a: int) -> int:
        """a^{-1} = a^{2^m − 2}."""
        if a == 0:
            raise ZeroDivisionError("нулевой элемент поля необратим")
        return self.pow(a, self.order - 1)
