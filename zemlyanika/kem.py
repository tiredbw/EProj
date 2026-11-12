"""Механизм инкапсуляции ключа Zemlyanika.KEM (раздел 8, алгоритмы 8–10).

H — «Стрибог-256», G — «Стрибог-512» (раздел 6). Двоичные строки переводятся
в байты по разделу 5.1, и байтовая строка подаётся в gost.streebog как есть
(порядок RFC 6986); результат G делится на K — первые 32 байта — и rnd.
"""

import hmac
import secrets

from gost.streebog import streebog256, streebog512

from . import pke
from .params import Params


def h(data: bytes) -> bytes:
    return streebog256(data)


def g(data: bytes) -> bytes:
    return streebog512(data)


def keygen(params: Params, seed_a: bytes | None = None, seed_s: bytes | None = None,
           z: bytes | None = None) -> tuple[bytes, bytes]:
    """Алгоритм 8: sk = sk′ ‖ pk ‖ H(pk) ‖ Z."""
    pk, sk_pke = pke.keygen(params, seed_a, seed_s)
    z = secrets.token_bytes(32) if z is None else z
    if len(z) != 32:
        raise ValueError("z должна быть 32 байта")
    return pk, sk_pke + pk + h(pk) + z


def encaps(params: Params, pk: bytes, m: bytes | None = None) -> tuple[bytes, bytes]:
    """Алгоритм 9: (K, c), K — 32 байта."""
    m = secrets.token_bytes(32) if m is None else m
    kr = g(m + h(pk))
    return kr[:32], pke.enc(params, pk, m, kr[32:])


def split_secret_key(params: Params, sk: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    if len(sk) != params.sk_size:
        raise ValueError(f"закрытый ключ {params.name} занимает {params.sk_size} байт, получено {len(sk)}")
    a = params.pke_sk_size
    b = a + params.pk_size
    return sk[:a], sk[a:b], sk[b : b + 32], sk[b + 32 :]


def decaps(params: Params, sk: bytes, c: bytes) -> bytes:
    """Алгоритм 10.

    В МР шаг 5 — «если c′ = c тогда K′ := K̃»: тогда при верном шифртексте
    возвращался бы ключ отказа. Взято обратное условие c′ ≠ c, как в схеме
    Фудзисаки — Окамото, на которую опирается алгоритм.
    """
    sk_pke, pk, h_pk, z = split_secret_key(params, sk)
    m1 = pke.dec(params, sk_pke, c)
    kr = g(m1 + h_pk)
    k_reject = h(z + c)
    if not hmac.compare_digest(pke.enc(params, pk, m1, kr[32:]), c):
        return k_reject
    return kr[:32]
