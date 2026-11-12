"""Контрольные примеры ГОСТ 34.11-2018 (раздел 10 RFC 6986).

Промежуточные значения сравниваются с Int_512 напрямую, сообщения и
хэш-коды — с развёрнутой записью (см. модуль streebog).
"""

import random

import pytest

from gost.streebog import C, g, lps, lps_table, streebog256, streebog512, transform_l, transform_p, transform_s


def vec(hex_text: str) -> int:
    return int("".join(hex_text.split()), 16)


def std_bytes(hex_text: str) -> bytes:
    return bytes.fromhex("".join(hex_text.split()))[::-1]


M1 = b"012345678901234567890123456789012345678901234567890123456789012"
M2 = "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы".encode("cp1251")


def test_messages_match_standard_notation():
    assert M1 == std_bytes("""
        32313039383736353433323130393837 36353433323130393837363534333231
        30393837363534333231303938373635 343332313039383736353433323130""")
    assert M2 == std_bytes("""
        fbe2e5f0eee3c820fbeafaebef20fffb f0e1e0f0f520e0ed20e8ece0ebe5f0f2
        f120fff0eeec20f120faf2fee5e2202c e8f6f3ede220e8e6eee1e8f0f2d1202c
        e8f0f2e5e220e5d1""")


# Пример 1, 512 бит: первая итерация E(K, m) поэлементно

M1_PADDED = vec("""
    01323130393837363534333231303938 37363534333231303938373635343332
    31303938373635343332313039383736 35343332313039383736353433323130""")
K1 = vec("b383fc2eced4a574" * 8)


def test_padding_of_short_message():
    assert int.from_bytes(M1, "little") | (1 << (8 * len(M1))) == M1_PADDED


def test_s_of_zero_vector():
    assert transform_s(0) == vec("fc" * 64)


def test_lps_of_zero_vector():
    assert lps(0) == K1


def test_table_lps_matches_literal_lps():
    rng = random.Random(34112018)
    for a in [0, K1, (1 << 512) - 1] + [rng.getrandbits(512) for _ in range(200)]:
        assert lps_table(a) == lps(a)


def test_first_round_s_p_l_separately():
    x = K1 ^ M1_PADDED
    assert x == vec("""
        b2b1cd1ef7ec924286b7cf1cffe49c4c 84b5c91afde694448abbcb18fbe09646
        82b3c516f9e2904080b1cd1ef7ec9242 86b7cf1cffe49c4c84b5c91afde69444""")
    sx = transform_s(x)
    assert sx == vec("""
        4645d95fc0beec2c432f8914b62d4efd 3e5e37f14b097aead67de417c220b048
        2492ac996667e0ebdf45d95fc0beec2c 432f8914b62d4efd3e5e37f14b097aea""")
    psx = transform_p(sx)
    assert psx == vec("""
        46433ed624df433e452f5e7d92452f5e d98937e4acd989375f14f117995f14f1
        c0b64bc266c0b64bbe2d092067be2d09 ec4e7ab0e0ec4e7a2cfdea48eb2cfdea""")
    assert transform_l(psx) == vec("""
        e60059d4d8e0758024c73f6f3183653f 56579189602ae4c21e7953ebc0e212a0
        ce78a8df475c2fd4fc43fc4b71c01e35 be465fb20dad2cf690cdf65028121bb9""")


def test_first_iteration_constant():
    assert K1 ^ C[0] == vec("""
        028ba7f4d01e7f9d5848d3af0eb1d96b 9ce98a6de0917562c2cd44a3bb516188
        f8ff1cbf5cb3cc7511c1d6266ab47661 b6f5881802a0e8576e0399773c72e073""")


def test_compression_steps_example_1():
    h = g(0, 0, M1_PADDED)
    assert h == vec("""
        fd102cf8812ccb1191ea34af21394f38 17a86641445aa9a626488adb33738ebd
        2754f6908cbbbac5d3ed0f522c50815c 954135793fb1f5d905fee4736b3bdae2""")
    h = g(0, h, 8 * len(M1))
    assert h == vec("""
        5c881fd924695cf196c2e4fec20d14b6 42026f2a0b1716ebaabb7067d4d59752
        3d2db69d6d3794622147a14f19a66e7f 9037e1d662d34501a8901a5de7771d7c""")


# Пример 2, 512 бит: сообщение длиннее блока (этап 2 процедуры)

def test_compression_steps_example_2_multiblock():
    m = vec("""
        fbeafaebef20fffbf0e1e0f0f520e0ed 20e8ece0ebe5f0f2f120fff0eeec20f1
        20faf2fee5e2202ce8f6f3ede220e8e6 eee1e8f0f2d1202ce8f0f2e5e220e5d1""")
    assert int.from_bytes(M2[:64], "little") == m
    h = g(0, 0, m)
    assert h == vec("""
        cd7f602312faa465e3bb4ccd9795395d e2914e938f10f8e127b7ac459b0c517b
        98ef779ef7c7a46aa7843b8889731f48 2e5d221e8e2cea852e816cdac407c7af""")

    tail = vec("0000000000000001fbe2e5f0eee3c820")
    assert int.from_bytes(M2[64:], "little") | (1 << 64) == tail
    h = g(512, h, tail)
    assert h == vec("""
        c544ae6efdf14404f089c72d5faf8dc6 aca1db5e28577fc07818095f1df70661
        e8b84d0706811cf92dffb8f96e61493d c382795c6ed7a17b64685902cbdc878e""")

    sigma = vec("""
        fbeafaebef20fffbf0e1e0f0f520e0ed 20e8ece0ebe5f0f2f120fff0eeec20f1
        20faf2fee5e2202ce8f6f3ede220e8e6 eee1e8f0f2d1202ee4d3d8d6d104adf1""")
    assert (m + tail) % (1 << 512) == sigma
    h = g(0, h, 0x240)
    assert h == vec("""
        4deb6649ffa5caf4163d9d3f9967fbbd 6eb3da68f916b6a09f41f2518b81292b
        703dc5d74e1ace5bcd3458af43bb456e 837326088f2b5df14bf83997a0b1ad8d""")
    assert g(0, h, sigma) == vec("""
        28fbc9bada033b1460642bdcddb90c3f b3e56c497ccd0f62b8a2ad4935e85f03
        7613966de4ee00531ae60f3b5a47f8da e06915d5f2f194996fcabf2622e6881e""")


def test_example_1_512():
    assert streebog512(M1) == std_bytes("""
        486f64c1917879417fef082b3381a4e2 11c324f074654c38823a7b76f830ad00
        fa1fbae42b1285c0352f227524bc9ab1 6254288dd6863dccd5b9f54a1ad0541b""")


def test_example_1_256():
    assert streebog256(M1) == std_bytes("""
        00557be5e584fd52a449b16b0251d05d 27f94ab76cbaa6da890b59d8ef1e159d""")


def test_example_2_512():
    assert streebog512(M2) == std_bytes("""
        28fbc9bada033b1460642bdcddb90c3f b3e56c497ccd0f62b8a2ad4935e85f03
        7613966de4ee00531ae60f3b5a47f8da e06915d5f2f194996fcabf2622e6881e""")


def test_example_2_256():
    assert streebog256(M2) == std_bytes("""
        508f7e553c06501d749a66fc28c6cac0 b005746d97537fa85d9e40904efed29d""")


# Контрольные примеры покрывают только 63 и 72 байта; границы блока
# (0, 64, 128 байт) сверяются с gostcrypto, если он установлен.

@pytest.mark.parametrize("length", [0, 1, 32, 63, 64, 65, 127, 128, 129, 200])
def test_matches_gostcrypto_on_block_boundaries(length):
    gosthash = pytest.importorskip("gostcrypto.gosthash")
    message = random.Random(length).randbytes(length)
    for name, ours in (("streebog256", streebog256), ("streebog512", streebog512)):
        reference = bytes(gosthash.new(name, data=bytearray(message)).digest())
        assert ours(message) == reference, (name, length)
