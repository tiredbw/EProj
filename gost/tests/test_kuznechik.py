"""Контрольные примеры ГОСТ 34.12-2018 (раздел 5 RFC 7801)."""

import random

import pytest

from gost.kuznechik import (
    ROUND_CONSTANTS,
    Kuznechik,
    _xor,
    expand_key,
    transform_l,
    transform_l_inv,
    transform_r,
    transform_s,
    transform_s_inv,
)


def h(hex_text: str) -> bytes:
    return bytes.fromhex("".join(hex_text.split()))


KEY = h("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
PLAINTEXT = h("1122334455667700ffeeddccbbaa9988")
CIPHERTEXT = h("7f679d90bebc24305a468d42b9d4edcd")


def _chain_pairs(values):
    return list(zip(values, values[1:]))


S_CHAIN = [
    "ffeeddccbbaa99881122334455667700",
    "b66cd8887d38e8d77765aeea0c9a7efc",
    "559d8dd7bd06cbfe7e7b262523280d39",
    "0c3322fed531e4630d80ef5c5a81c50b",
    "23ae65633f842d29c5df529c13f5acda",
]
R_CHAIN = [
    "00000000000000000000000000000100",
    "94000000000000000000000000000001",
    "a5940000000000000000000000000000",
    "64a59400000000000000000000000000",
    "0d64a594000000000000000000000000",
]
L_CHAIN = [
    "64a59400000000000000000000000000",
    "d456584dd0e3e84cc3166e4b7fa2890d",
    "79d26221b87b584cd42fbc4ffea5de9a",
    "0e93691a0cfc60408b7b68f66b513c13",
    "e6a8094fee0aa204fd97bcb0b44b8580",
]


@pytest.mark.parametrize("before, after", _chain_pairs(S_CHAIN))
def test_s(before, after):
    assert transform_s(h(before)) == h(after)
    assert transform_s_inv(h(after)) == h(before)


@pytest.mark.parametrize("before, after", _chain_pairs(R_CHAIN))
def test_r(before, after):
    assert transform_r(h(before)) == h(after)


@pytest.mark.parametrize("before, after", _chain_pairs(L_CHAIN))
def test_l(before, after):
    assert transform_l(h(before)) == h(after)
    assert transform_l_inv(h(after)) == h(before)


def test_round_constants_c1_to_c8():
    expected = [
        "6ea276726c487ab85d27bd10dd849401",
        "dc87ece4d890f4b3ba4eb92079cbeb02",
        "b2259a96b4d88e0be7690430a44f7f03",
        "7bcd1b0b73e32ba5b79cb140f2551504",
        "156f6d791fab511deabb0c502fd18105",
        "a74af7efab73df160dd208608b9efe06",
        "c9e8819dc73ba5ae50f5b570561a6a07",
        "f6593616e6055689adfba18027aa2a08",
    ]
    assert [c.hex() for c in ROUND_CONSTANTS[:8]] == expected


def test_round_keys():
    expected = [
        "8899aabbccddeeff0011223344556677",
        "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44",
        "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac",
        "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1",
        "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517",
        "72e9dd7416bcf45b755dbaa88e4a4043",
    ]
    assert [k.hex() for k in expand_key(KEY)] == expected


def test_encryption_trace():
    expected_after_round = [
        "e297b686e355b0a1cf4a2f9249140830",
        "285e497a0862d596b36f4258a1c69072",
        "0187a3a429b567841ad50d29207cc34e",
        "ec9bdba057d4f4d77c5d70619dcad206",
        "1357fd11de9257290c2a1473eb6bcde1",
        "28ae31e7d4c2354261027ef0b32897df",
        "07e223d56002c013d3f5e6f714b86d2d",
        "cd8ef6cd97e0e092a8e4cca61b38bf65",
        "0d8e40e4a800d06b2f1b37ea379ead8e",
    ]
    round_keys = expand_key(KEY)
    state = PLAINTEXT
    for k, expected in zip(round_keys, expected_after_round):
        state = transform_l(transform_s(_xor(k, state)))
        assert state.hex() == expected


def test_decryption_trace():
    expected_after_round = [
        "76ca149eef27d1b10d17e3d5d68e5a72",
        "5d9b06d41b9d1d2d04df7755363e94a9",
        "79487192aa45709c115559d6e9280f6e",
        "ae506924c8ce331bb918fc5bdfb195fa",
        "bbffbfc8939eaaffafb8e22769e323aa",
        "3cc2f07cc07a8bec0f3ea0ed2ae33e4a",
        "f36f01291d0b96d591e228b72d011c36",
        "1c4b0c1e950182b1ce696af5c0bfc5df",
        "99bb99ff99bb99ffffffffffffffffff",
    ]
    round_keys = expand_key(KEY)
    state = CIPHERTEXT
    for k, expected in zip(reversed(round_keys[1:]), expected_after_round):
        state = transform_s_inv(transform_l_inv(_xor(k, state)))
        assert state.hex() == expected


def test_encrypt():
    assert Kuznechik(KEY).encrypt(PLAINTEXT) == CIPHERTEXT


def test_decrypt():
    assert Kuznechik(KEY).decrypt(CIPHERTEXT) == PLAINTEXT


def test_decrypt_inverts_encrypt_on_random_data():
    rng = random.Random(1)
    for _ in range(20):
        cipher = Kuznechik(rng.randbytes(32))
        block = rng.randbytes(16)
        assert cipher.decrypt(cipher.encrypt(block)) == block


@pytest.mark.parametrize("key_len", [0, 16, 31, 33])
def test_rejects_wrong_key_length(key_len):
    with pytest.raises(ValueError):
        Kuznechik(bytes(key_len))


@pytest.mark.parametrize("block_len", [0, 15, 17, 32])
def test_rejects_wrong_block_length(block_len):
    cipher = Kuznechik(KEY)
    with pytest.raises(ValueError):
        cipher.encrypt(bytes(block_len))
    with pytest.raises(ValueError):
        cipher.decrypt(bytes(block_len))


# Контрольный пример один, поэтому случайные ключи сверяются с gostcrypto, если он установлен.
def test_matches_gostcrypto_on_random_keys():
    gostcipher = pytest.importorskip("gostcrypto.gostcipher")
    rng = random.Random(2)
    for _ in range(20):
        key, block = rng.randbytes(32), rng.randbytes(16)
        reference = gostcipher.new("kuznechik", bytearray(key), gostcipher.MODE_ECB)
        assert Kuznechik(key).encrypt(block) == bytes(reference.encrypt(bytearray(block)))
