"""Декодирование кода Гоппы (раздел 6.3, модифицированный алгоритм Берлекэмпа–Мэсси).

Функции соответствуют группам шагов алгоритма, чтобы промежуточные
значения можно было сверить с контрольным примером Б.4.
"""

from .field import Field
from .goppa import inverse_goppa_value


def compute_alpha(field: Field, a: list[int], n: int, t: int) -> list[int]:
    """Шаги 1–9: α_0, …, α_n."""
    alpha = [a[0]] + [1] * n
    for j in range(1, n):
        i = j
        while True:
            alpha[i] = field.mul(alpha[i], a[j]) ^ alpha[i - 1]
            i -= 1
            if not (i > 0 and i > j - 2 * t):
                break
        if j - 2 * t <= 1:
            alpha[0] = field.mul(alpha[0], a[j])
    return alpha


def compute_r(field: Field, a: list[int], g: list[int], s: int, mt: int) -> list[int]:
    """Шаг 10: r_i = Π_j (a_i ⊕ g_j)^{-2}, если s_i = 1, иначе 0."""
    r = []
    for i in range(mt):
        if (s >> i) & 1:
            w = inverse_goppa_value(field, g, a[i])
            r.append(field.mul(w, w))
        else:
            r.append(0)
    return r


def compute_b(field: Field, a: list[int], alpha: list[int], n: int, t: int, mt: int) -> list[list[int]]:
    """Шаги 11–15: b_{j,i} для j < mt, i < 2t."""
    b = []
    for j in range(mt):
        row = [0] * (2 * t - 1) + [alpha[n]]
        for i in range(2 * t - 2, -1, -1):
            row[i] = alpha[i + n - 2 * t + 1] ^ field.mul(row[i + 1], a[j])
        b.append(row)
    return b


def compute_beta(field: Field, r: list[int], b: list[list[int]], t: int) -> list[int]:
    """Шаг 16: β_i = Σ_j r_j·b_{j,i}."""
    beta = []
    for i in range(2 * t):
        acc = 0
        for r_j, row in zip(r, b):
            acc ^= field.mul(r_j, row[i])
        beta.append(acc)
    return beta


def build_system(alpha: list[int], beta: list[int], n: int, t: int) -> list[list[int]]:
    """Матрица системы шага 17: 2t уравнений, столбцы — y_0, …, y_t, z_0, …, z_{t-1}."""
    rows = []
    for k in range(2 * t, 3 * t):
        row = [0] * (2 * t + 1)
        for i in range(k - 2 * t + 1, t + 1):
            row[i] ^= beta[k - i]
            row[t + i] ^= alpha[k - i + n - 2 * t + 1]  # z_{i-1}
        rows.append(row)
    for k in range(t, 2 * t):
        row = [0] * (2 * t + 1)
        for i in range(t + 1):
            row[i] ^= beta[k - i]
        for i in range(t):
            row[t + 1 + i] ^= alpha[k - i + n - 2 * t]
        rows.append(row)
    return rows


def solve_homogeneous(field: Field, rows: list[list[int]]) -> list[int]:
    """Ненулевое решение однородной системы над F_{2^m} методом Гаусса.

    Неизвестных больше, чем уравнений, поэтому свободная переменная есть
    всегда. Последней свободной присваивается 1, остальным — 0; так
    получается то же решение, что приведено в Б.4 (там z_{t-1} = 1).
    """
    rows = [row[:] for row in rows]
    width = len(rows[0])
    pivots = []
    rank = 0
    for col in range(width):
        pivot = next((r for r in range(rank, len(rows)) if rows[r][col]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inv = field.inv(rows[rank][col])
        rows[rank] = [field.mul(x, inv) for x in rows[rank]]
        for r in range(len(rows)):
            if r != rank and rows[r][col]:
                factor = rows[r][col]
                rows[r] = [x ^ field.mul(factor, y) for x, y in zip(rows[r], rows[rank])]
        pivots.append(col)
        rank += 1
    free = [col for col in range(width) if col not in pivots]
    solution = [0] * width
    solution[free[-1]] = 1
    for r, col in enumerate(pivots):
        solution[col] = rows[r][free[-1]]  # в характеристике 2 минус совпадает с плюсом
    return solution


def evaluate_locator(field: Field, a: list[int], y: list[int], n: int, t: int) -> list[int]:
    """Шаги 19–23: v_i = y_t·a_i^t ⊕ … ⊕ y_0 (схема Горнера)."""
    v = []
    for i in range(n):
        acc = y[t]
        for j in range(t, 0, -1):
            acc = field.mul(a[i], acc) ^ y[j - 1]
        v.append(acc)
    return v


def decode(field: Field, a: list[int], g: list[int], s: int, n: int, t: int) -> int | None:
    """Decode(a, g, s, p): вектор ошибок e веса t или None вместо символа отказа ⊥."""
    mt = field.m * t
    alpha = compute_alpha(field, a, n, t)
    r = compute_r(field, a, g, s, mt)
    b = compute_b(field, a, alpha, n, t, mt)
    beta = compute_beta(field, r, b, t)
    y = solve_homogeneous(field, build_system(alpha, beta, n, t))[: t + 1]
    if y[t] == 0:
        return None
    v = evaluate_locator(field, a, y, n, t)
    roots = [i for i in range(n) if v[i] == 0]
    if len(roots) != t:
        return None
    return sum(1 << i for i in roots)
