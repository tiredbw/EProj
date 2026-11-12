"""Система асимметричного шифрования Zemlyanika.PKE (7.5, алгоритмы 5–7).

Открытый текст m и строка rnd — по 32 байта (двоичные строки длины 256,
переведённые в байты по разделу 5.1).
"""

import secrets

from .bits import bits_to_bytes, bytes_to_bits, substring
from .encoding import decode, encode
from .params import N, Params
from .prng import r006_2017
from .ring import Poly, add, compress_poly, decompress_poly, dot, mat_vec, scale, sub, transpose
from .sampling import cbd, matrix_gen


def _public_matrix(params: Params, seed_a: int) -> list[list[Poly]]:
    buf_len = N * params.k * params.k * params.t
    return matrix_gen(r006_2017(seed_a, buf_len), buf_len, params.k, params.t)


def keygen(params: Params, seed_a: bytes | None = None, seed_s: bytes | None = None) -> tuple[bytes, bytes]:
    """Алгоритм 5. Начальные значения задаются только в тестах.

    Шаг 6 МР вырабатывает s как CBD(η_e, …) из буфера длины 512k·η_s; взято
    η_s — иначе Dec, который восстанавливает s через CBD(η_s), не совпадёт с KeyGen.
    """
    k, q, t = params.k, params.q, params.t
    seed_a = secrets.token_bytes(32) if seed_a is None else seed_a
    seed_s = secrets.token_bytes(32) if seed_s is None else seed_s
    if len(seed_a) != 32 or len(seed_s) != 32:
        raise ValueError("seed_A и seed_s должны быть по 32 байта")
    a_seed, s_seed = bytes_to_bits(seed_a), bytes_to_bits(seed_s)
    matrix = _public_matrix(params, a_seed)
    s_len, e_len = 2 * N * k * params.eta_s, 2 * N * k * params.eta_e
    secret_buf = r006_2017(s_seed, s_len + e_len)
    s = cbd(params.eta_s, k, substring(secret_buf, 0, s_len), s_len, q)
    e = cbd(params.eta_e, k, substring(secret_buf, s_len, s_len + e_len), e_len, q)
    b = [add(x, y, q) for x, y in zip(mat_vec(matrix, s, q), e)]
    pk = bits_to_bytes(a_seed, 256) + b"".join(encode(poly, t) for poly in b)
    sk = bits_to_bytes(substring(secret_buf, 0, s_len), s_len)
    return pk, sk


def _unpack_pk(params: Params, pk: bytes) -> tuple[int, list[Poly]]:
    if len(pk) != params.pk_size:
        raise ValueError(f"открытый ключ {params.name} занимает {params.pk_size} байт, получено {len(pk)}")
    size = 32 * params.t
    return bytes_to_bits(pk[:32]), [decode(pk[32 + size * i : 32 + size * (i + 1)], params.t) for i in range(params.k)]


def enc(params: Params, pk: bytes, m: bytes, rnd: bytes) -> bytes:
    """Алгоритм 6.

    Шаг 1 МР — MatrixGen(bytes_to_bits(pk[0:32])), то есть 256 бит вместо
    256·k²·t: взят тот же R006-2017 от seed_A, что в KeyGen. Вектор b,
    не упомянутый в алгоритме, декодируется из pk[32:].
    """
    k, q, t = params.k, params.q, params.t
    if len(m) != 32 or len(rnd) != 32:
        raise ValueError("m и rnd должны быть по 32 байта")
    seed_a, b = _unpack_pk(params, pk)
    matrix = _public_matrix(params, seed_a)
    s_len, e_len, e2_len = 2 * N * k * params.eta_s, 2 * N * k * params.eta_e, 2 * N * params.eta_e
    buf = r006_2017(bytes_to_bits(rnd), s_len + e_len + e2_len)
    r = cbd(params.eta_s, k, substring(buf, 0, s_len), s_len, q)
    e1 = cbd(params.eta_e, k, substring(buf, s_len, s_len + e_len), e_len, q)
    e2 = cbd(params.eta_e, 1, substring(buf, s_len + e_len, s_len + e_len + e2_len), e2_len, q)[0]
    u = [add(x, y, q) for x, y in zip(mat_vec(transpose(matrix), r, q), e1)]
    m_bits = bytes_to_bits(m)
    m_poly = [(m_bits >> i) & 1 for i in range(N)]  # msg_to_poly (раздел 5.4)
    v = add(add(dot(b, r, q), e2, q), scale(q // 2, m_poly, q), q)
    c = encode(compress_poly(v, params.dv, t), t - params.dv)
    for poly in u:
        c += encode(compress_poly(poly, params.du, t), t - params.du)
    return c


def dec(params: Params, sk: bytes, c: bytes) -> bytes:
    """Алгоритм 7."""
    k, q, t, du, dv = params.k, params.q, params.t, params.du, params.dv
    if len(c) != params.ct_size:
        raise ValueError(f"шифртекст {params.name} занимает {params.ct_size} байт, получено {len(c)}")
    if len(sk) != params.pke_sk_size:
        raise ValueError(f"закрытый ключ PKE {params.name} занимает {params.pke_sk_size} байт")
    v_len = 32 * (t - dv)
    v1 = decode(c[:v_len], t - dv)
    u1 = [decode(c[v_len + 32 * i * (t - du) : v_len + 32 * (i + 1) * (t - du)], t - du) for i in range(k)]
    s = cbd(params.eta_s, k, bytes_to_bits(sk), 8 * len(sk), q)
    u2 = [decompress_poly(poly, du) for poly in u1]
    v2 = decompress_poly(v1, dv)
    m_poly = sub(v2, dot(s, u2, q), q)
    m_bits = sum(1 << i for i, x in enumerate(m_poly) if q // 4 < x <= 3 * q // 4)
    return bits_to_bytes(m_bits, N)
