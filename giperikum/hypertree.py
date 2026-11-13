"""Гипердерево (раздел 4.8, алгоритмы 15–17)."""

from . import xmss
from .address import Address
from .params import CHAINS, N, Params


def xmss_sig_size(params: Params) -> int:
    return CHAINS * N + 4 + params.h_prime * N


def pk_gen(sk_seed: bytes, pk_seed: bytes, params: Params) -> bytes:
    """Алгоритм 15: PK.root — корень единственного дерева верхнего уровня d − 1."""
    adrs = Address()
    adrs.set_layer(params.d - 1)
    adrs.set_tree(0)
    return xmss.pk_gen(sk_seed, pk_seed, params.h_prime, adrs)


def sign(m: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, params: Params) -> bytes:
    """Алгоритм 16: d подписей XMSS от листа до верхнего дерева."""
    hp = params.h_prime
    adrs = Address()
    adrs.set_layer(0)
    adrs.set_tree(idx_tree)
    sig_ht = xmss.sign(m, sk_seed, pk_seed, idx_leaf, hp, adrs)
    root = xmss.pk_from_sig(m, sig_ht, pk_seed, idx_leaf, hp, adrs)
    for j in range(1, params.d):
        idx_leaf = idx_tree % (1 << hp)
        idx_tree >>= hp
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig_tmp = xmss.sign(root, sk_seed, pk_seed, idx_leaf, hp, adrs)
        sig_ht += sig_tmp
        if j < params.d - 1:
            root = xmss.pk_from_sig(root, sig_tmp, pk_seed, idx_leaf, hp, adrs)
    return sig_ht


def layer_roots(m: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int,
                params: Params) -> list[bytes | None]:
    """Корни XMSS, вычисленные из подписи на каждом слое (шаги 4 и 12 алгоритма 17)."""
    hp, size = params.h_prime, xmss_sig_size(params)
    adrs = Address()
    roots = []
    node: bytes | None = m
    for j in range(params.d):
        if j:
            idx_leaf = idx_tree % (1 << hp)
            idx_tree >>= hp
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        node = xmss.pk_from_sig(node, sig_ht[j * size : (j + 1) * size], pk_seed, idx_leaf, hp, adrs)
        roots.append(node)
        if node is None:
            break
    return roots


def verify(m: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes,
           params: Params) -> bool:
    """Алгоритм 17."""
    if len(sig_ht) != params.d * xmss_sig_size(params):
        return False
    roots = layer_roots(m, sig_ht, pk_seed, idx_tree, idx_leaf, params)
    return len(roots) == params.d and roots[-1] == pk_root
