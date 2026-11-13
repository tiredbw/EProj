"""Одноразовая подпись WOTS+C (раздел 4.6, алгоритмы 4–10)."""

from . import address as A
from .address import Address
from .encoding import convert16
from .hashes import f, h_s, prf, th
from .params import CHAINS, TARGET_SUM, W


def chain(pk_seed: bytes, adrs: Address, x: bytes, j: int, s: int) -> bytes:
    """Алгоритм 4: s шагов цепочки от элемента с индексом j (записан итеративно)."""
    if j + s > W - 1:
        raise ValueError("выход за конец цепочки")
    for step in range(j, j + s):
        adrs.set_element(step)
        x = f(pk_seed, adrs.to_bytes(), x)
    return x


def sk_gen(sk_seed: bytes, pk_seed: bytes, adrs: Address) -> list[bytes]:
    """Алгоритм 5."""
    adrs.set_type(A.WOTS_PRF)
    adrs.set_element(0)
    sk = []
    for i in range(CHAINS):
        adrs.set_chain(i)
        sk.append(prf(sk_seed, pk_seed, adrs.to_bytes()))
    return sk


def pk_gen(sk_seed: bytes, pk_seed: bytes, adrs: Address) -> bytes:
    """Алгоритм 6."""
    sk = sk_gen(sk_seed, pk_seed, adrs)
    adrs.set_type(A.WOTS_HASH)
    pk = []
    for i in range(CHAINS):
        adrs.set_chain(i)
        pk.append(chain(pk_seed, adrs, sk[i], 0, W - 1))
    adrs.set_type(A.WOTS_PK)
    adrs.set_suffix(0)
    return th(pk_seed, adrs.to_bytes(), pk)


def hash_convert(pk_seed: bytes, adrs: Address, m: bytes) -> tuple[list[int], int]:
    """Алгоритм 8: перебор 32-битного счётчика s, пока сумма разрядов H_s(s ‖ M) не станет S_{w,n}."""
    adrs.set_type(A.SIGN_MSG_WOTS)
    adrs.set_suffix(0)
    s = 0
    while True:
        digits = convert16(h_s(pk_seed, adrs.to_bytes(), s.to_bytes(4, "big"), m))
        if sum(digits) == TARGET_SUM:
            return digits, s
        s += 1


def sign(m: bytes, sk_seed: bytes, pk_seed: bytes, adrs: Address) -> bytes:
    """Алгоритм 9: σ = σ_0 ‖ … ‖ σ_63 ‖ s, где s — 4 байта счётчика."""
    digits, s = hash_convert(pk_seed, adrs, m)
    sk = sk_gen(sk_seed, pk_seed, adrs)
    adrs.set_type(A.WOTS_HASH)
    sig = []
    for i in range(CHAINS):
        adrs.set_chain(i)
        sig.append(chain(pk_seed, adrs, sk[i], 0, digits[i]))
    return b"".join(sig) + s.to_bytes(4, "big")


def pk_from_sig(sig: bytes, m: bytes, pk_seed: bytes, adrs: Address) -> bytes | None:
    """Алгоритм 10: ключ проверки из подписи или None («Ошибка» — неверная сумма разрядов)."""
    adrs.set_type(A.SIGN_MSG_WOTS)
    adrs.set_suffix(0)
    s = sig[CHAINS * 32 :]
    digits = convert16(h_s(pk_seed, adrs.to_bytes(), s, m))
    if sum(digits) != TARGET_SUM:
        return None
    adrs.set_type(A.WOTS_HASH)
    pk = []
    for i in range(CHAINS):
        adrs.set_chain(i)
        pk.append(chain(pk_seed, adrs, sig[32 * i : 32 * (i + 1)], digits[i], W - 1 - digits[i]))
    adrs.set_type(A.WOTS_PK)
    adrs.set_suffix(0)
    return th(pk_seed, adrs.to_bytes(), pk)
