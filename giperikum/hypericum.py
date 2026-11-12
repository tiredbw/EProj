"""«Гиперикум»: выработка ключей, подпись и проверка (раздел 5, алгоритмы 22–24).

PK = (PK.seed, PK.root), SK = (SK.seed, SK.prf, PK.seed, PK.root) — байтовые
строки по 32 байта. Подпись SIG = R ‖ s ‖ SIG_FORS ‖ SIG_HT (рисунок 26).
"""

import secrets
from dataclasses import dataclass

from . import address as A
from . import fors, hypertree
from .address import Address
from .hashes import h_msg, prf_msg
from .params import N, Params

# opt_const (раздел 5.5) — ASCII-строка «Turchenko|KUDINOV|Grebnev|QAPP\r\n».
OPT_CONST = bytes.fromhex("5475726368656e6b6f7c4b5544494e4f567c477265626e65767c514150500d0a")


@dataclass(frozen=True)
class PublicKey:
    seed: bytes
    root: bytes


@dataclass(frozen=True)
class SecretKey:
    seed: bytes
    prf: bytes
    pk: PublicKey


@dataclass(frozen=True)
class Indexes:
    """Результат разбора хэш-кода сообщения (шаги 10–18 алгоритма 23)."""

    md: bytes  # старшие ⌈k·b/8⌉ байт digest; индексы FORS читаются из них алгоритмом 3
    idx_tree: int
    idx_leaf: int
    last_tree_is_zero: bool  # младшие b бит из k·b равны 0 — условие FORS+C


def split_digest(digest: bytes, params: Params) -> Indexes:
    k_bits = params.k * params.b
    md_len = (k_bits + 7) // 8
    tree_bits, leaf_bits = params.h - params.h_prime, params.h_prime
    tree_len, leaf_len = (tree_bits + 7) // 8, (leaf_bits + 7) // 8
    md = digest[:md_len]
    md_value = int.from_bytes(md, "big") >> (8 * md_len - k_bits)
    tmp_tree = digest[md_len : md_len + tree_len]
    tmp_leaf = digest[md_len + tree_len : md_len + tree_len + leaf_len]
    return Indexes(
        md=md,
        idx_tree=int.from_bytes(tmp_tree, "big") >> (8 * tree_len - tree_bits),
        idx_leaf=int.from_bytes(tmp_leaf, "big") >> (8 * leaf_len - leaf_bits),
        last_tree_is_zero=md_value % (1 << params.b) == 0,
    )


def keygen(params: Params, sk_seed: bytes | None = None, sk_prf: bytes | None = None,
           pk_seed: bytes | None = None) -> tuple[PublicKey, SecretKey]:
    """Алгоритм 22. Начальные значения задаются только в тестах, по умолчанию — случайные."""
    sk_seed = secrets.token_bytes(N) if sk_seed is None else sk_seed
    sk_prf = secrets.token_bytes(N) if sk_prf is None else sk_prf
    pk_seed = secrets.token_bytes(N) if pk_seed is None else pk_seed
    if any(len(x) != N for x in (sk_seed, sk_prf, pk_seed)):
        raise ValueError(f"SK.seed, SK.prf и PK.seed должны быть по {N} байта")
    pk = PublicKey(pk_seed, hypertree.pk_gen(sk_seed, pk_seed, params))
    return pk, SecretKey(sk_seed, sk_prf, pk)


def message_digest(m: bytes, r: bytes, pk: PublicKey, params: Params) -> tuple[int, bytes, Indexes]:
    """Шаги 8–18 алгоритма 23: перебор счётчика s, пока последнее дерево FORS+C не получит индекс 0."""
    s = 0
    while True:
        digest = h_msg(r, pk.seed, pk.root, s.to_bytes(4, "big"), m)
        idx = split_digest(digest, params)
        if idx.last_tree_is_zero:
            return s, digest, idx
        s += 1


def fors_address(idx: Indexes) -> Address:
    adrs = Address()
    adrs.set_layer(0)
    adrs.set_tree(idx.idx_tree)
    adrs.set_type(A.FORS_TREE)
    adrs.set_keypair(idx.idx_leaf)
    return adrs


def sign(m: bytes, sk: SecretKey, params: Params, randomize: bool = False, opt: bytes | None = None) -> bytes:
    """Алгоритм 23. По умолчанию opt = opt_const; randomize=True — режим со
    случайностью (opt из secrets); opt задаётся явно только в тестах."""
    if opt is None:
        opt = secrets.token_bytes(N) if randomize else OPT_CONST
    r = prf_msg(sk.prf, sk.pk.seed, opt, m)
    s, _, idx = message_digest(m, r, sk.pk, params)
    adrs = fors_address(idx)
    sig_fors = fors.sign(idx.md, sk.seed, sk.pk.seed, adrs, params)
    pk_fors = fors.pk_from_sig(idx.md, sig_fors, sk.pk.seed, adrs, params)
    sig_ht = hypertree.sign(pk_fors, sk.seed, sk.pk.seed, idx.idx_tree, idx.idx_leaf, params)
    return r + s.to_bytes(4, "big") + sig_fors + sig_ht


def split_signature(sig: bytes, params: Params) -> tuple[bytes, bytes, bytes, bytes]:
    """Шаг 2 алгоритма 24: R, s, SIG_FORS, SIG_HT по смещениям из формулы (18)."""
    fors_len = params.k_prime * (params.b + 1) * N
    return sig[:N], sig[N : N + 4], sig[N + 4 : N + 4 + fors_len], sig[N + 4 + fors_len :]


def verify(m: bytes, sig: bytes, pk: PublicKey, params: Params) -> bool:
    """Алгоритм 24."""
    if len(sig) != params.signature_size:
        return False
    r, s, sig_fors, sig_ht = split_signature(sig, params)
    idx = split_digest(h_msg(r, pk.seed, pk.root, s, m), params)
    if not idx.last_tree_is_zero:
        return False
    pk_fors = fors.pk_from_sig(idx.md, sig_fors, pk.seed, fors_address(idx), params)
    return hypertree.verify(pk_fors, sig_ht, pk.seed, idx.idx_tree, idx.idx_leaf, pk.root, params)
