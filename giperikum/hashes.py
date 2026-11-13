"""Функции на основе «Стрибога» (раздел 4.10, формулы (11)–(17)).

В формулах аргумент STR записан как A ‖ B ‖ … ‖ X, и раздел 4.5.2 говорит,
что STR обрабатывает строку справа налево. Контрольным примерам приложения А
соответствует такое прочтение: на вход «Стрибога» в порядке байтов
RFC 6986 (gost.streebog) подаётся X ‖ … ‖ B ‖ A — поля в обратном порядке,
байты внутри каждого поля без изменений; результат не разворачивается.
"""

from gost.streebog import streebog256, streebog512

ZERO = bytes(32)  # 0^256


def _str256(*fields: bytes) -> bytes:
    return streebog256(b"".join(reversed(fields)))


def _str512(*fields: bytes) -> bytes:
    return streebog512(b"".join(reversed(fields)))


def prf_msg(sk_prf: bytes, pk_seed: bytes, opt: bytes, m: bytes) -> bytes:
    """(11) PRF_msg = STR256(M ‖ opt ‖ PK.seed ‖ 0^256 ‖ SK.prf)."""
    return _str256(m, opt, pk_seed, ZERO, sk_prf)


def prf(sk_seed: bytes, pk_seed: bytes, adrs: bytes) -> bytes:
    """(12) PRF = STR256(ADRS ‖ PK.seed ‖ 0^256 ‖ SK.seed)."""
    return _str256(adrs, pk_seed, ZERO, sk_seed)


def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, s: bytes, m: bytes) -> bytes:
    """(13) H_msg = STR512(M ‖ s ‖ PK.root ‖ PK.seed ‖ 0^256 ‖ R)."""
    return _str512(m, s, pk_root, pk_seed, ZERO, r)


def f(pk_seed: bytes, adrs: bytes, m1: bytes) -> bytes:
    """(14) F = STR256(M1 ‖ ADRS ‖ 0^256 ‖ PK.seed)."""
    return _str256(m1, adrs, ZERO, pk_seed)


def h(pk_seed: bytes, adrs: bytes, m1: bytes, m2: bytes) -> bytes:
    """(15) H(PK.seed, ADRS, M1 ‖ M2) = STR256(M2 ‖ M1 ‖ ADRS ‖ 0^256 ‖ PK.seed)."""
    return _str256(m2, m1, adrs, ZERO, pk_seed)


def h_s(pk_seed: bytes, adrs: bytes, s: bytes, m: bytes) -> bytes:
    """(16) H_s(PK.seed, ADRS, s ‖ M) = STR256(M ‖ s ‖ ADRS ‖ 0^256 ‖ PK.seed)."""
    return _str256(m, s, adrs, ZERO, pk_seed)


def th(pk_seed: bytes, adrs: bytes, blocks: list[bytes]) -> bytes:
    """(17) Th = STR256(M ‖ ADRS ‖ 0^256 ‖ PK.seed), M — конкатенация блоков."""
    return _str256(b"".join(blocks), adrs, ZERO, pk_seed)
