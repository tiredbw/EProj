"""Расширенная схема подписи Меркла XMSS (раздел 4.7, алгоритмы 11–14)."""

from . import address as A
from . import wots
from .address import Address
from .hashes import h
from .params import CHAINS, N


def treehash(sk_seed: bytes, pk_seed: bytes, s: int, z: int, adrs: Address) -> bytes:
    """Алгоритм 11: корень поддерева высоты z с крайним левым листом s.

    Высота узла в стеке — та, что записана в ADRS при его вычислении:
    у листа 1, у пустого стека 0 (раздел 3.2).
    """
    if s % (1 << z):
        raise ValueError("начальный индекс должен делиться на 2^z")
    stack: list[tuple[bytes, int]] = []
    for i in range(1 << z):
        adrs.set_keypair(s + i)
        node = wots.pk_gen(sk_seed, pk_seed, adrs)
        adrs.set_type(A.TREE)
        adrs.set_keypair(0)
        adrs.set_height(1)
        adrs.set_index(s + i)
        while stack and stack[-1][1] == adrs.get_height():
            adrs.set_index(adrs.get_index() >> 1)
            node = h(pk_seed, adrs.to_bytes(), stack.pop()[0], node)
            adrs.set_height(adrs.get_height() + 1)
        stack.append((node, adrs.get_height()))
    return stack.pop()[0]


def pk_gen(sk_seed: bytes, pk_seed: bytes, h_prime: int, adrs: Address) -> bytes:
    """Алгоритм 12."""
    return treehash(sk_seed, pk_seed, 0, h_prime, adrs)


def sign(m: bytes, sk_seed: bytes, pk_seed: bytes, idx: int, h_prime: int, adrs: Address) -> bytes:
    """Алгоритм 13: SIG_XMSS = подпись WOTS+C ‖ путь аутентификации из h′ узлов."""
    auth = []
    for j in range(h_prime):
        sibling = (idx >> j) ^ 1
        auth.append(treehash(sk_seed, pk_seed, sibling << j, j, adrs))
    adrs.set_type(A.WOTS_HASH)
    adrs.set_keypair(idx)
    return wots.sign(m, sk_seed, pk_seed, adrs) + b"".join(auth)


def pk_from_sig(m: bytes, sig: bytes, pk_seed: bytes, idx: int, h_prime: int, adrs: Address) -> bytes | None:
    """Алгоритм 14: корень дерева по подписи или None, если отказал WOTS+C."""
    wots_len = CHAINS * N + 4
    adrs.set_keypair(idx)
    node = wots.pk_from_sig(sig[:wots_len], m, pk_seed, adrs)
    if node is None:
        return None
    auth = sig[wots_len:]
    adrs.set_type(A.TREE)
    adrs.set_keypair(0)
    adrs.set_index(idx)
    for k in range(h_prime):
        adrs.set_height(k + 1)
        adrs.set_index(adrs.get_index() >> 1)
        sibling = auth[N * k : N * (k + 1)]
        if (idx >> k) % 2 == 0:
            node = h(pk_seed, adrs.to_bytes(), node, sibling)
        else:
            node = h(pk_seed, adrs.to_bytes(), sibling, node)
    return node
