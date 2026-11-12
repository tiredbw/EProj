"""Zemlyanika.PKE и Zemlyanika.KEM (разделы 7.5, 8, 9)."""

import json
from pathlib import Path

import pytest

from zemlyanika import kem, pke
from zemlyanika.bits import bits_to_bytes, bytes_to_bits, substring
from zemlyanika.encoding import encode
from zemlyanika.ring import add, mat_vec
from zemlyanika.params import ALL, TABLE_1_SIZES, Z768_C, Z512, Params
from zemlyanika.prng import r006_2017
from zemlyanika.sampling import cbd

VECTORS = json.loads((Path(__file__).parent.parent / "test_vectors.json").read_text(encoding="utf-8"))
SEEDS = {"seed_a": b"\x11" * 32, "seed_s": b"\x22" * 32, "z": b"\x33" * 32}


@pytest.fixture(scope="module", params=ALL, ids=lambda p: p.name)
def keys(request):
    params = request.param
    return params, *kem.keygen(params, **SEEDS)


def test_pk_and_ciphertext_sizes_match_table_1(keys):
    params, pk, _ = keys
    _, c = kem.encaps(params, pk, b"\x44" * 32)
    sk_size, pk_size, ct_size = TABLE_1_SIZES[params.name]
    assert (len(pk), len(c)) == (pk_size, ct_size)


def test_secret_key_size_against_table_1(keys):
    # Алгоритм 5 хранит в sk′ 512·k·η_s бит буфера. Для η_s = 1 это совпадает с
    # таблицей 1, для η_s = 2 таблица меньше: в ней sk′ = 32·k·3 байта, как будто
    # коэффициенты s упакованы по 3 бита.
    params, _, sk = keys
    table_sk = TABLE_1_SIZES[params.name][0]
    assert len(sk) == params.sk_size
    if params.eta_s == 1:
        assert len(sk) == table_sk
    else:
        assert table_sk == 32 * params.k * 3 + params.pk_size + 64 != len(sk)


def test_roundtrip(keys):
    params, pk, sk = keys
    for i in range(3):
        key, c = kem.encaps(params, pk, bytes([i]) * 32)
        assert len(key) == 32
        assert kem.decaps(params, sk, c) == key


def test_corrupted_ciphertext_gives_rejection_key(keys):
    params, pk, sk = keys
    key, c = kem.encaps(params, pk, b"\x55" * 32)
    bad = bytes([c[0] ^ 1]) + c[1:]
    rejected = kem.decaps(params, sk, bad)
    z = sk[-32:]
    assert rejected != key and rejected == kem.h(z + bad)


def test_pke_roundtrip_with_edge_messages(keys):
    params, pk, _ = keys
    _, sk_pke = pke.keygen(params, SEEDS["seed_a"], SEEDS["seed_s"])
    for m in (bytes(32), b"\xff" * 32, b"\x0f\xf0" * 16):
        assert pke.dec(params, sk_pke, pke.enc(params, pk, m, b"\x66" * 32)) == m


def test_literal_decaps_condition_breaks_the_kem():
    # Шаг 5 алгоритма 10 буквально: «если c′ = c тогда K′ := K̃».
    params = Z512
    pk, sk = kem.keygen(params, **SEEDS)
    key, c = kem.encaps(params, pk, b"\x77" * 32)
    sk_pke, pk_in_sk, h_pk, z = kem.split_secret_key(params, sk)
    m1 = pke.dec(params, sk_pke, c)
    kr = kem.g(m1 + h_pk)
    literal = kem.h(z + c) if pke.enc(params, pk_in_sk, m1, kr[32:]) == c else kr[:32]
    assert literal != key
    assert kem.decaps(params, sk, c) == key


def test_literal_keygen_eta_breaks_decryption_for_z768_c():
    # Шаг 6 алгоритма 5 буквально: s = CBD(η_e, …), хотя буфер длины 512k·η_s
    # и Dec восстанавливает s как CBD(η_s, …). Для Z768-C (η_s = 2, η_e = 1)
    # открытый ключ с таким s не расшифровывается своим же sk.
    params = Z768_C
    k, q = params.k, params.q
    s_len, e_len = 2 * 256 * k * params.eta_s, 2 * 256 * k * params.eta_e
    buf = r006_2017(bytes_to_bits(SEEDS["seed_s"]), s_len + e_len)
    literal_s = cbd(params.eta_e, k, substring(buf, 0, s_len), s_len, q)
    e = cbd(params.eta_e, k, substring(buf, s_len, s_len + e_len), e_len, q)
    seed_a = bytes_to_bits(SEEDS["seed_a"])
    matrix = pke._public_matrix(params, seed_a)
    b = [add(x, y, q) for x, y in zip(mat_vec(matrix, literal_s, q), e)]
    pk = SEEDS["seed_a"] + b"".join(encode(poly, params.t) for poly in b)
    sk = bits_to_bytes(substring(buf, 0, s_len), s_len)
    m = b"\x5a" * 32
    assert pke.dec(params, sk, pke.enc(params, pk, m, b"\x01" * 32)) != m


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["params"])
def test_own_regression_vectors(vector):
    params = next(p for p in ALL if p.name == vector["params"])
    pk, sk = kem.keygen(params, bytes.fromhex(vector["seed_a"]), bytes.fromhex(vector["seed_s"]), bytes.fromhex(vector["z"]))
    key, c = kem.encaps(params, pk, bytes.fromhex(vector["m"]))
    assert (kem.h(pk).hex(), kem.h(sk).hex(), kem.h(c).hex(), key.hex()) == (vector["H_pk"], vector["H_sk"], vector["H_c"], vector["K"])


def test_input_validation():
    params = Z512
    pk, sk = kem.keygen(params, **SEEDS)
    _, c = kem.encaps(params, pk)
    with pytest.raises(ValueError):
        kem.decaps(params, sk[:-1], c)
    with pytest.raises(ValueError):
        kem.decaps(params, sk, c[:-1])
    with pytest.raises(ValueError):
        kem.encaps(params, pk[:-1])
    with pytest.raises(ValueError):
        pke.enc(params, pk, b"\x00" * 31, b"\x00" * 32)
    with pytest.raises(ValueError):
        kem.keygen(params, z=b"\x00" * 16)
    with pytest.raises(ValueError):
        kem.keygen(params, seed_a=b"\x00" * 16)


@pytest.mark.parametrize("q, k, du", [(1000, 2, 0), (2, 2, 0), (1024, 0, 0), (1024, 2, 10)])
def test_parameter_validation(q, k, du):
    with pytest.raises(ValueError):
        Params("неверный", q=q, k=k, eta_s=1, eta_e=1, du=du, dv=0)
