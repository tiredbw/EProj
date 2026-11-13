"""Контрольные примеры HMAC_GOSTR3411_2012_256 и KDF_TREE_GOSTR3411_2012_256
(RFC 7836, приложение B, примеры 1 и 10)."""

import random

import pytest

from gost.kdf import hmac_streebog256, kdf_tree_streebog256


def h(hex_text: str) -> bytes:
    return bytes.fromhex("".join(hex_text.split()))


KEY = h("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f")


def test_hmac_rfc7836_example_1():
    data = h("0126bdb87800af214341456563780100")
    expected = h("a1aa5f7de402d7b3d323f2991c8d4534 013137010a83754fd0af6d7cd4922ed9")
    assert hmac_streebog256(KEY, data) == expected


def test_kdf_tree_rfc7836_example_10():
    k1 = h("22b6837845c6bef65ea71672b2658310 86d3c76aebe6dae91cad51d83f79d16b")
    k2 = h("074c9330599d7f8d712fca54392f4ddd e93751206b3584c8f43f9e6dc51531f9")
    out = kdf_tree_streebog256(KEY, 512, label=h("26bdb878"), seed=h("af21434145656378"), r=1)
    assert out == k1 + k2


def test_kdf_tree_truncates_to_requested_length():
    full = kdf_tree_streebog256(KEY, 512)
    assert kdf_tree_streebog256(KEY, 384) != full[:48]  # L входит в каждый блок
    assert len(kdf_tree_streebog256(KEY, 4032)) == 504


@pytest.mark.parametrize("length_bits", [0, 7, 513])
def test_kdf_tree_rejects_bad_length(length_bits):
    with pytest.raises(ValueError):
        kdf_tree_streebog256(KEY, length_bits)


def test_kdf_tree_rejects_too_long_output_for_r():
    with pytest.raises(ValueError):
        kdf_tree_streebog256(KEY, 256 * 256, r=1)


def test_hmac_rejects_key_longer_than_block():
    with pytest.raises(ValueError):
        hmac_streebog256(bytes(65), b"data")


# Пример в RFC один; другие длины ключа сверяются с gostcrypto, если он установлен.
@pytest.mark.parametrize("key_len", [1, 32, 63, 64])
def test_hmac_matches_gostcrypto(key_len):
    gosthmac = pytest.importorskip("gostcrypto.gosthmac")
    rng = random.Random(key_len)
    key, data = rng.randbytes(key_len), rng.randbytes(100)
    reference = gosthmac.new("HMAC_GOSTR3411_2012_256", key=bytearray(key), data=bytearray(data))
    assert hmac_streebog256(key, data) == bytes(reference.digest())
