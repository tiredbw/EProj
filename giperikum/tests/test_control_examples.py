"""Сверка с контрольными примерами приложения А для всех шести наборов параметров."""

import json
from pathlib import Path

import pytest

from giperikum import fors, hypericum, hypertree, wots
from giperikum.address import Address
from giperikum.hashes import h_msg, prf_msg
from giperikum.params import ALL

SETS = json.loads((Path(__file__).parent.parent / "control_examples.json").read_text(encoding="utf-8"))["sets"]
CASES = list(zip(ALL, SETS))
FAST_SETS = [c for c in CASES if c[0].name.split("_")[1] == "Б"]


def ids(case):
    return case[0].name


def message(d) -> bytes:
    # Подписываемая строка подаётся вместе с завершающим нулевым байтом, как строка C.
    return d["message"].encode() + b"\0"


def keys(d) -> tuple[hypericum.PublicKey, hypericum.SecretKey]:
    pk = hypericum.PublicKey(bytes.fromhex(d["PK.seed"]), bytes.fromhex(d["PK.root"]))
    return pk, hypericum.SecretKey(bytes.fromhex(d["SK.seed"]), bytes.fromhex(d["SK.prf"]), pk)


def layer_addresses(idx_tree: int, idx_leaf: int, params):
    tree, leaf = idx_tree, idx_leaf
    for j in range(params.d):
        if j:
            leaf, tree = tree % (1 << params.h_prime), tree >> params.h_prime
        adrs = Address()
        adrs.set_layer(j)
        adrs.set_tree(tree)
        adrs.set_keypair(leaf)
        yield adrs


@pytest.mark.parametrize("case", CASES, ids=ids)
def test_parameters_and_signature_size(case):
    params, d = case
    assert (params.h, params.d, params.b, params.k) == (d["h"], d["d"], d["b"], d["k"])


@pytest.mark.parametrize("params, size", list(zip(ALL, [59132, 18932, 27392, 13484, 16376, 9772])), ids=[p.name for p in ALL])
def test_signature_size_matches_table_1(params, size):
    assert params.signature_size == size


@pytest.mark.parametrize("case", CASES, ids=ids)
def test_randomizer_r(case):
    params, d = case
    pk, sk = keys(d)
    assert prf_msg(sk.prf, pk.seed, hypericum.OPT_CONST, message(d)).hex() == d["R"]


@pytest.mark.parametrize("case", CASES, ids=ids)
def test_digest_and_indexes(case):
    params, d = case
    pk, _ = keys(d)
    digest = h_msg(bytes.fromhex(d["R"]), pk.seed, pk.root, bytes.fromhex(d["s"]), message(d))
    assert digest.hex() == d["digest"]
    idx = hypericum.split_digest(digest, params)
    assert idx.last_tree_is_zero
    assert idx.idx_leaf == d["idx_leaf"]
    if params.name != "Гиперикум_М_256_20":
        assert idx.idx_tree == d["idx_tree"]


def test_idx_tree_of_m_256_20_is_a_misprint():
    # В A.5 напечатан idx_tree из A.4 (250103). Из digest следует 2246, и именно
    # при нём сходятся WOTS_PK обоих слоёв (test_wots_pk_on_every_layer).
    params, d = CASES[3]
    pk, _ = keys(d)
    digest = h_msg(bytes.fromhex(d["R"]), pk.seed, pk.root, bytes.fromhex(d["s"]), message(d))
    assert d["idx_tree"] == SETS[2]["idx_tree"] == 250103
    assert hypericum.split_digest(digest, params).idx_tree == 2246


@pytest.mark.parametrize("case", CASES, ids=ids)
def test_wots_pk_on_every_layer(case):
    params, d = case
    pk, sk = keys(d)
    digest = h_msg(bytes.fromhex(d["R"]), pk.seed, pk.root, bytes.fromhex(d["s"]), message(d))
    idx = hypericum.split_digest(digest, params)
    for adrs, layer in zip(layer_addresses(idx.idx_tree, idx.idx_leaf, params), d["layers"], strict=True):
        assert wots.pk_gen(sk.seed, pk.seed, adrs).hex() == layer["WOTS_PK"]


@pytest.mark.parametrize("case", CASES, ids=ids)
def test_top_layer_root_is_pk_root(case):
    _, d = case
    assert d["layers"][-1]["XMSS_PK"] == d["PK.root"]


@pytest.mark.parametrize("case", FAST_SETS, ids=ids)
def test_keygen_reproduces_pk_root(case):
    params, d = case
    pk, sk = keys(d)
    assert hypertree.pk_gen(sk.seed, pk.seed, params) == pk.root


@pytest.mark.slow
@pytest.mark.parametrize("case", FAST_SETS, ids=ids)
def test_full_signature(case):
    params, d = case
    pk, sk = keys(d)
    m = message(d)
    sig = hypericum.sign(m, sk, params)
    r, s, sig_fors, sig_ht = hypericum.split_signature(sig, params)
    assert (r.hex(), s.hex()) == (d["R"], d["s"])
    assert (sig_fors[:4].hex(), sig_fors[-4:].hex()) == (d["SIG_FORS_head"], d["SIG_FORS_tail"])
    size = hypertree.xmss_sig_size(params)
    layers = [(sig_ht[j * size : j * size + 4].hex(), sig_ht[(j + 1) * size - 4 : (j + 1) * size].hex())
              for j in range(params.d)]
    expected = [tuple(x) for x in d["SIG_HT_layers"]]
    if params.name == "Гиперикум_Б_128_20":
        # В A.6 у слоя 0 напечатаны последние байты слоя 1. Верность наших байтов
        # подтверждает XMSS_PK слоя 0 ниже: он зависит от последнего узла пути.
        assert expected[0][1] == expected[1][1] != layers[0][1]
        expected[0] = (expected[0][0], layers[0][1])
    assert layers == expected
    idx = hypericum.split_digest(h_msg(r, pk.seed, pk.root, s, m), params)
    pk_fors = fors.pk_from_sig(idx.md, sig_fors, pk.seed, hypericum.fors_address(idx), params)
    assert pk_fors.hex() == d["PK_FORS"]
    roots = hypertree.layer_roots(pk_fors, sig_ht, pk.seed, idx.idx_tree, idx.idx_leaf, params)
    assert [x.hex() for x in roots] == [layer["XMSS_PK"] for layer in d["layers"]]
    assert hypericum.verify(m, sig, pk, params)


@pytest.mark.slow
def test_counter_search_reaches_document_s():
    params, d = CASES[5]
    pk, _ = keys(d)
    s, _, _ = hypericum.message_digest(message(d), bytes.fromhex(d["R"]), pk, params)
    assert s == int(d["s"], 16)
