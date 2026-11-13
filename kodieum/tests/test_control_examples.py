"""Сверка с контрольными примерами приложения Б (secparam1264)."""

import json
from pathlib import Path

import pytest

from kodieum import decode as D
from kodieum import goppa, kem
from kodieum.auxiliary import gen_unique_seq, weight_vec_from_v
from kodieum.field import Field
from kodieum.params import SECPARAM1264 as P
from kodieum.primitives import BlockCipher, h256, hkdf
from kodieum.vectors import deserialize, from_doc_hex, serialize_list, to_doc_hex

DATA = json.loads((Path(__file__).parent.parent / "control_examples.json").read_text(encoding="utf-8"))


def vec(text: str) -> int:
    return from_doc_hex(text)[0]


def items(text: str) -> list[int]:
    return [vec(x) for x in text.split("|")]


@pytest.fixture(scope="module")
def field():
    return Field(P.m, P.p)


@pytest.fixture(scope="module")
def support():
    return kem.support_and_goppa(P, vec(DATA["B5"]["seed2"]))


@pytest.fixture(scope="module")
def pk():
    return kem.public_matrix(P, vec(DATA["B5"]["seed2"]))


def test_b1_hash_of_matrix_and_list():
    b1 = DATA["B1"]
    rows = [from_doc_hex(r, 1)[0] for r in b1["M_rows"].split("|")]
    assert h256(serialize_list(rows, b1["M_row_length"])).hex() == b1["H256_M"]
    a = [from_doc_hex(x, 1)[0] for x in b1["a_items"].split("|")]
    assert h256(serialize_list(a, b1["a_item_length"])).hex() == b1["H256_a"]


def test_b2_block_cipher_and_sorting():
    b2 = DATA["B2"]
    cipher = BlockCipher(vec(b2["k"]))
    for i, expected in b2["E_k"].items():
        assert cipher.encrypt(int(i)) == vec(expected)
    ordered = sorted(cipher.encrypt(i) for i in range(1 << P.m))
    for i, expected in b2["sorted"].items():
        assert ordered[int(i)] == vec(expected)


def test_b2_gen_unique_seq():
    c = gen_unique_seq(P.m, P.n + P.t, vec(DATA["B2"]["k"]))
    assert c == items(DATA["B2"]["c"])


def test_b3_weight_vector_from_v():
    b3 = DATA["B3"]
    assert weight_vec_from_v(P.n, P.t, P.m, vec(b3["v"])) == vec(b3["e"])


def test_b4_decode_intermediate_values(field, support):
    a, g = support
    b4, n, t = DATA["B4"], P.n, P.t
    s = vec(DATA["B6"]["s"])
    alpha = D.compute_alpha(field, a, n, t)
    assert alpha == items(b4["alpha"])
    r = D.compute_r(field, a, g, s, P.mt)
    assert r == items(b4["r"])
    b = D.compute_b(field, a, alpha, n, t, P.mt)
    flat = [x for row in b for x in row]
    head, tail = items(b4["b_head"]), items(b4["b_tail"])
    assert flat[: len(head)] == head and flat[-len(tail):] == tail
    # Б.1: вектор из элементов F_{2^m} — каждый элемент отдельно в ⌈m/8⌉ байт.
    assert h256(serialize_list(flat, P.m)).hex() == b4["H256_b"]
    beta = D.compute_beta(field, r, b, t)
    assert beta == items(b4["beta"])
    solution = D.solve_homogeneous(field, D.build_system(alpha, beta, n, t))
    assert solution[: t + 1] == items(b4["y"])
    assert solution[t + 1:] == items(b4["z"])
    assert D.evaluate_locator(field, a, solution[: t + 1], n, t) == items(b4["v"])
    assert D.decode(field, a, g, s, n, t) == vec(DATA["B3"]["e"])


def test_b5_keygen_matrices(field, support):
    a, g = support
    H = goppa.parity_check_matrix(field, a, g, P.t)
    assert h256(serialize_list(H, P.n)).hex() == DATA["B5"]["H256_H"]
    A = goppa.systematic_part(H, P.mt)
    assert h256(serialize_list(A, P.n - P.mt)).hex() == DATA["B5"]["H256_A"]


def test_b6_encaps(pk):
    e, s = vec(DATA["B3"]["e"]), vec(DATA["B6"]["s"])
    assert kem.syndrome(pk, e, P.mt) == s
    # shk — байты хэш-кода; в Б.6 он записан как двоичный вектор (Б.1).
    shk = kem.shared_key(e, P.n, s, P.mt)
    assert to_doc_hex(deserialize(shk, 256), 256) == DATA["B6"]["shk"]


def test_b7_decaps():
    sk = (vec(DATA["B5"]["seed2"]), vec(DATA["B5"]["salt"]))
    shk = kem.decaps(P, sk, vec(DATA["B6"]["s"]))
    assert to_doc_hex(deserialize(shk, 256), 256) == DATA["B6"]["shk"]


@pytest.mark.xfail(strict=True, reason="KDF-значения Б.3 и Б.5 не воспроизводятся (см. README)")
def test_b5_kdf_seed1_to_seed2():
    out = hkdf(vec(DATA["B5"]["seed1"]), 512 + P.n)
    assert out & ((1 << 256) - 1) == vec(DATA["B5"]["seed2"])


@pytest.mark.xfail(strict=True, reason="KDF-значения Б.3 и Б.5 не воспроизводятся (см. README)")
def test_b3_kdf_seed_to_seed_prime():
    out = hkdf(vec(DATA["B3"]["seed"]), 256 + 2 * P.t * 16)
    assert out & ((1 << 256) - 1) == vec(DATA["B3"]["seed_prime"])
