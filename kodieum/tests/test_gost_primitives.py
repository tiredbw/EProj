"""Регрессионные тесты внешних ГОСТ-примитивов против официальных
контрольных векторов. Без них сверка с RFC делалась вручную в сессии и
не воспроизводилась автоматически."""

from gost_primitives import kdf_tree_streebog256, kuznechik_encrypt_block, streebog256


def test_kuznechik_matches_official_gost_34_12_2018_vector():
    # ГОСТ Р 34.12-2018 / RFC 7801, раздел 5.4-5.5
    key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    expected = bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd")
    assert kuznechik_encrypt_block(key, plaintext) == expected


def test_kdf_tree_matches_rfc7836_appendix_b_item_10():
    k_in = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    label = bytes.fromhex("26bdb878")
    seed = bytes.fromhex("af21434145656378")
    k1 = bytes.fromhex(
        "22 b6 83 78 45 c6 be f6 5e a7 16 72 b2 65 83 10 86 d3 c7 6a eb e6 da e9 1c ad 51 d8 3f 79 d1 6b".replace(" ", "")
    )
    k2 = bytes.fromhex(
        "07 4c 93 30 59 9d 7f 8d 71 2f ca 54 39 2f 4d dd e9 37 51 20 6b 35 84 c8 f4 3f 9e 6d c5 15 31 f9".replace(" ", "")
    )
    expected = k1 + k2
    assert kdf_tree_streebog256(k_in, 512, label=label, seed=seed, r=1) == expected


def test_streebog256_of_empty_message():
    # Контрольное значение H_256("") из ГОСТ 34.11-2018
    expected = bytes.fromhex("3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
    assert streebog256(b"") == expected
