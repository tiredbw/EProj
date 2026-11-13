"""R006-2017(seed, r): механизм выработки псевдослучайной последовательности
по Р 1323565.1.006-2017 с параметрами раздела 7.1 МР.

H — «Стрибог-512» (h = 64 байта), длина блока m = 512, начальное заполнение
K = seed длины s = 256. Шаги механизма:
U_0 = K ‖ 0^{m−s−8}; U_i = U_{i−1} + 1 mod 2^{m−8}; C_i = H(U_i);
R = LSB_{r mod 512}(C_{q+1}) ‖ C_q ‖ … ‖ C_1.

Векторы Р 1323565.1.006 записаны в нотации ГОСТ: старший разряд слева.
Как с ними соотносятся двоичные строки «Земляники» (бит 0 слева), МР не
говорит. Принято: строка b — это вектор с z_i = b[i], то есть число
bits_to_int(b); вектор U подаётся в «Стрибог» как в ГОСТ 34.11, а байтовая
строка для gost.streebog получается в порядке RFC 6986 (младший байт первым).
"""

from gost.streebog import streebog512

M = 512
STATE_BITS = M - 8


def r006_2017(seed: int, r: int, s: int = 256) -> int:
    """Псевдослучайная строка длины r бит (как число, бит i — b[i])."""
    if not 0 <= seed < 1 << s:
        raise ValueError(f"начальное заполнение должно иметь длину {s} бит")
    q, rest = divmod(r, M)
    u = seed << (STATE_BITS - s)
    out = 0
    for i in range(q + (1 if rest else 0)):
        u = (u + 1) % (1 << STATE_BITS)
        block = int.from_bytes(streebog512(u.to_bytes(STATE_BITS // 8, "little")), "little")
        if i == q:
            block &= (1 << rest) - 1
        out |= block << (M * i)
    return out
