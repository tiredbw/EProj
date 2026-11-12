"""Код Гоппы ключевой пары: проверочная матрица H (KeyGen, шаги 6–7)
и синдром по H, которым проверяется условие шага 4 Decaps."""

from .field import Field


def inverse_goppa_value(field: Field, g: list[int], x: int) -> int:
    """[Π_i (x ⊕ g_i)]^{-1} — множитель из KeyGen, шаг 6.1, и Decode, шаг 10."""
    prod = 1
    for g_i in g:
        prod = field.mul(prod, x ^ g_i)
    return field.inv(prod)


def parity_check_matrix(field: Field, a: list[int], g: list[int], t: int) -> list[int]:
    """KeyGen, шаг 6: двоичная (mt × n)-матрица H, строки — числа (бит j — столбец j).

    h_{0,j} = [Π_i (a_j ⊕ g_i)]^{-1}, h_{i,j} = a_j·h_{i-1,j}; элемент h_{i,j}
    раскладывается на m бит в столбец j блока строк H_i.
    """
    m = field.m
    h = [inverse_goppa_value(field, g, a_j) for a_j in a]
    rows = []
    for _ in range(t):
        block = [0] * m
        for j, h_j in enumerate(h):
            for bit in range(m):
                if (h_j >> bit) & 1:
                    block[bit] |= 1 << j
        rows.extend(block)
        h = [field.mul(a_j, h_j) for a_j, h_j in zip(a, h)]
    return rows


def systematic_part(rows: list[int], mt: int) -> list[int] | None:
    """KeyGen, шаг 7: приводит H сложением строк к виду (I_mt ‖ A) и возвращает
    строки A (сдвинутые на mt бит) или None, если такого вида нет."""
    rows = rows[:]
    for col in range(mt):
        pivot = next((r for r in range(col, mt) if (rows[r] >> col) & 1), None)
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        for r in range(mt):
            if r != col and (rows[r] >> col) & 1:
                rows[r] ^= rows[col]
    return [row >> mt for row in rows]


def goppa_syndrome(field: Field, a: list[int], g: list[int], x: int, t: int) -> list[int]:
    """H·xᵀ как t элементов поля: i-й равен Σ_j x_j·a_j^i·h_{0,j}.

    (I_mt ‖ A) получена из H обратимыми действиями над строками, поэтому
    синдромы двух векторов по H совпадают тогда и только тогда, когда
    совпадают их синдромы по (I_mt ‖ A).
    """
    acc = [0] * t
    while x:
        low = x & -x
        j = low.bit_length() - 1
        x ^= low
        term = inverse_goppa_value(field, g, a[j])
        for i in range(t):
            acc[i] ^= term
            term = field.mul(term, a[j])
    return acc
