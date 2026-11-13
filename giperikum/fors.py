"""Лес случайных подмножеств FORS+C (раздел 4.9, алгоритмы 18–21)."""

from . import address as A
from .address import Address
from .encoding import indexes
from .hashes import f, h, prf, th
from .params import N, Params


def sk_gen(sk_seed: bytes, pk_seed: bytes, adrs: Address, idx: int) -> bytes:
    """Алгоритм 18: одно секретное значение с глобальным номером листа idx."""
    adrs.set_type(A.FORS_PRF)
    adrs.set_height(0)
    adrs.set_index(idx)
    return prf(sk_seed, pk_seed, adrs.to_bytes())


def treehash(sk_seed: bytes, pk_seed: bytes, s: int, z: int, adrs: Address) -> bytes:
    """Алгоритм 19: как XMSS.treehash, но лист — F от секретного значения."""
    if s % (1 << z):
        raise ValueError("начальный индекс должен делиться на 2^z")
    stack: list[tuple[bytes, int]] = []
    for i in range(1 << z):
        sk = sk_gen(sk_seed, pk_seed, adrs, s + i)
        adrs.set_type(A.FORS_TREE)
        adrs.set_height(0)
        adrs.set_index(s + i)
        node = f(pk_seed, adrs.to_bytes(), sk)
        adrs.set_height(1)
        while stack and stack[-1][1] == adrs.get_height():
            adrs.set_index(adrs.get_index() >> 1)
            node = h(pk_seed, adrs.to_bytes(), stack.pop()[0], node)
            adrs.set_height(adrs.get_height() + 1)
        stack.append((node, adrs.get_height()))
    return stack.pop()[0]


def sign(md: bytes, sk_seed: bytes, pk_seed: bytes, adrs: Address, params: Params) -> bytes:
    """Алгоритм 20: для каждого из k′ деревьев — секретное значение и путь из b узлов."""
    t = 1 << params.b
    sig = b""
    for i in range(params.k_prime):
        idx = indexes(md, params.b, i)
        sig += sk_gen(sk_seed, pk_seed, adrs, i * t + idx)
        for j in range(params.b):
            sibling = (idx >> j) ^ 1
            sig += treehash(sk_seed, pk_seed, i * t + (sibling << j), j, adrs)
    return sig


def pk_from_sig(md: bytes, sig: bytes, pk_seed: bytes, adrs: Address, params: Params) -> bytes:
    """Алгоритм 21: корни деревьев по подписи и PK_FORS = Th_{k′} от них."""
    t, b = 1 << params.b, params.b
    roots = []
    adrs.set_type(A.FORS_TREE)
    for i in range(params.k_prime):
        part = sig[i * (b + 1) * N : (i + 1) * (b + 1) * N]
        idx = indexes(md, b, i)
        adrs.set_height(0)
        adrs.set_index(i * t + idx)
        node = f(pk_seed, adrs.to_bytes(), part[:N])
        for j in range(b):
            adrs.set_height(j + 1)
            adrs.set_index(adrs.get_index() >> 1)
            sibling = part[N * (j + 1) : N * (j + 2)]
            if (idx >> j) % 2 == 0:
                node = h(pk_seed, adrs.to_bytes(), node, sibling)
            else:
                node = h(pk_seed, adrs.to_bytes(), sibling, node)
        roots.append(node)
    adrs.set_type(A.FORS_ROOTS)
    adrs.set_suffix(0)
    return th(pk_seed, adrs.to_bytes(), roots)
