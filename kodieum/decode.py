"""Алгоритм декодирования кода Гоппы, раздел 6.3 МР (модифицированный
Берлекэмп-Мэсси). Векторы a, g — списки элементов F_2^m (как int из gf.py);
s и возвращаемый e — двоичные векторы в виде Python int (бит i = координата i,
соответствие раздела 5.2), как и везде в этом пакете.
"""

from gf import GF2m


def _solve_homogeneous_system(field: GF2m, rows: list[list[int]], num_unknowns: int) -> list[int] | None:
    """Находит произвольное ненулевое решение однородной линейной системы
    над F_2^m методом Гаусса. Возвращает None, если решение только нулевое
    (матрица полного столбцового ранга)."""
    rows = [row[:] for row in rows]
    pivot_cols: list[int] = []
    r = 0
    for c in range(num_unknowns):
        pivot_row = next((rr for rr in range(r, len(rows)) if rows[rr][c] != 0), None)
        if pivot_row is None:
            continue
        rows[r], rows[pivot_row] = rows[pivot_row], rows[r]
        inv = field.inv(rows[r][c])
        rows[r] = [field.mul(inv, x) for x in rows[r]]
        for rr in range(len(rows)):
            if rr != r and rows[rr][c] != 0:
                factor = rows[rr][c]
                rows[rr] = [field.add(rows[rr][k], field.mul(factor, rows[r][k])) for k in range(num_unknowns)]
        pivot_cols.append(c)
        r += 1
        if r == len(rows):
            break

    if r == num_unknowns:
        return None

    free_col = next(c for c in range(num_unknowns) if c not in pivot_cols)
    solution = [0] * num_unknowns
    solution[free_col] = 1
    for row_idx, col in enumerate(pivot_cols):
        value = 0
        for k in range(num_unknowns):
            if k != col:
                value = field.add(value, field.mul(rows[row_idx][k], solution[k]))
        solution[col] = value
    return solution


def decode(field: GF2m, a: list[int], g: list[int], s: int, n: int, t: int) -> int | None:
    """Decode(a, g, s, p) из раздела 6.3. Возвращает e (int, бит i = e_i,
    вес t) при успехе или None (символ отказа ⊥) при неудаче."""
    mt = field.m * t

    # alpha[0..n] — коэффициенты, получаемые сверткой (a_0..a_{j}) со
    # скользящим окном убывающей ширины (2t): шаги 4-9 раздела 6.3.
    alpha = [0] * (n + 1)
    alpha[0] = a[0]
    for i in range(1, n + 1):
        alpha[i] = 1
    for j in range(1, n):
        i = j
        while True:
            alpha[i] = field.add(field.mul(alpha[i], a[j]), alpha[i - 1])
            i -= 1
            if not (i > 0 and i > j - 2 * t):
                break
        if j - 2 * t <= 1:
            alpha[0] = field.mul(alpha[0], a[j])

    r = [0] * mt
    for i in range(mt):
        if (s >> i) & 1:
            prod = 1
            for j in range(t):
                prod = field.mul(prod, field.add(a[i], g[j]))
            r[i] = field.inv(field.mul(prod, prod))

    b = [[0] * (2 * t) for _ in range(mt)]
    for j in range(mt):
        b[j][2 * t - 1] = alpha[n]
    for j in range(mt):
        for i in range(2 * t - 2, -1, -1):
            b[j][i] = field.add(alpha[i + n - 2 * t + 1], field.mul(b[j][i + 1], a[j]))

    beta = [0] * (2 * t)
    for i in range(2 * t):
        acc = 0
        for j in range(mt):
            acc = field.add(acc, field.mul(r[j], b[j][i]))
        beta[i] = acc

    num_unknowns = 2 * t + 1  # y_0..y_t (t+1), z_0..z_{t-1} (t)
    equations = []
    for k in range(2 * t, 3 * t):
        row = [0] * num_unknowns
        for i in range(k - 2 * t + 1, t + 1):
            row[i] = field.add(row[i], beta[k - i])
            z_idx = i - 1
            if 0 <= z_idx < t:
                col = (t + 1) + z_idx
                row[col] = field.add(row[col], alpha[k - i + n - 2 * t + 1])
        equations.append(row)
    for k in range(t, 2 * t):
        row = [0] * num_unknowns
        for i in range(0, t + 1):
            row[i] = field.add(row[i], beta[k - i])
        for i in range(0, t):
            col = (t + 1) + i
            row[col] = field.add(row[col], alpha[k - i + n - 2 * t])
        equations.append(row)

    solution = _solve_homogeneous_system(field, equations, num_unknowns)
    if solution is None:
        return None
    y = solution[: t + 1]
    z = solution[t + 1 :]
    del z  # z участвует только в построении системы, не в вычислении v

    if y[t] == 0:
        return None

    v = [y[t]] * n
    for j in range(t, 0, -1):
        for i in range(n):
            v[i] = field.add(field.mul(a[i], v[i]), y[j - 1])

    e = 0
    weight = 0
    for i in range(n):
        if v[i] == 0:
            e |= 1 << i
            weight += 1

    return e if weight == t else None
