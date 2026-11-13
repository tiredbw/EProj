"""Отдельные части схемы и полный цикл на малых параметрах."""

import pytest

from giperikum import address as A
from giperikum import fors, hypericum, wots, xmss
from giperikum.address import Address
from giperikum.encoding import convert16, indexes, to_byte, to_int
from giperikum.hashes import th
from giperikum.params import TARGET_SUM, Params

SMALL = Params("тест", h=4, d=2, b=3, k=4)
SEEDS = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)


@pytest.fixture(scope="module")
def keypair():
    return hypericum.keygen(SMALL, *SEEDS)


@pytest.fixture(scope="module")
def signature(keypair):
    return hypericum.sign(b"message", keypair[1], SMALL)


def test_address_layout():
    adrs = Address()
    adrs.set_layer(0x01020304)
    adrs.set_tree(0x05060708090A0B0C)
    adrs.set_type(A.FORS_PRF)
    adrs.set_keypair(0x0D0E0F10)
    adrs.set_height(0x11121314)
    adrs.set_index(0x15161718)
    assert adrs.to_bytes() == bytes(range(1, 9)) + bytes(range(9, 13)) + b"\x00\x00\x00\x07" + bytes(range(13, 25))
    adrs.set_suffix(0)
    assert len(adrs.to_bytes()) == 28 and adrs.to_bytes()[-8:] == bytes(8)


def test_byte_conversions():
    assert to_int(b"\x01\x00") == 256
    assert to_byte(256, 3) == b"\x00\x01\x00"
    assert indexes(b"\xa5\x0f", 4, 0) == 0xA and indexes(b"\xa5\x0f", 4, 3) == 0xF
    assert indexes(b"\xa5\x0f", 3, 1) == 0b001  # биты 3–5: 0, 0, 1
    assert convert16(b"\xa5" + bytes(31))[:3] == [10, 5, 0]


def test_wots_signature_gives_public_key():
    adrs = Address()
    adrs.set_keypair(3)
    m = bytes(range(32))
    sig = wots.sign(m, SEEDS[0], SEEDS[2], adrs)
    assert len(sig) == 64 * 32 + 4
    digits, _ = wots.hash_convert(SEEDS[2], adrs, m)
    assert sum(digits) == TARGET_SUM
    assert wots.pk_from_sig(sig, m, SEEDS[2], adrs) == wots.pk_gen(SEEDS[0], SEEDS[2], adrs)
    wrong_counter = sig[:-4] + (int.from_bytes(sig[-4:], "big") + 1).to_bytes(4, "big")
    assert wots.pk_from_sig(wrong_counter, m, SEEDS[2], adrs) != wots.pk_gen(SEEDS[0], SEEDS[2], adrs)


def test_chain_bounds():
    adrs = Address()
    x = bytes(32)
    assert wots.chain(SEEDS[2], adrs, x, 5, 0) == x
    with pytest.raises(ValueError):
        wots.chain(SEEDS[2], adrs, x, 10, 6)


def test_treehash_rejects_unaligned_start():
    with pytest.raises(ValueError):
        xmss.treehash(SEEDS[0], SEEDS[2], 1, 1, Address())
    with pytest.raises(ValueError):
        fors.treehash(SEEDS[0], SEEDS[2], 2, 2, Address())


def test_xmss_signature_gives_root():
    adrs = Address()
    m = bytes(32)
    root = xmss.pk_gen(SEEDS[0], SEEDS[2], 2, adrs)
    for idx in range(4):
        sig = xmss.sign(m, SEEDS[0], SEEDS[2], idx, 2, adrs)
        assert xmss.pk_from_sig(m, sig, SEEDS[2], idx, 2, adrs) == root


def test_fors_signature_gives_public_key():
    adrs = Address()
    adrs.set_keypair(1)
    md = bytes([0b10110010, 0b01000000])
    sig = fors.sign(md, SEEDS[0], SEEDS[2], adrs, SMALL)
    assert len(sig) == SMALL.k_prime * (SMALL.b + 1) * 32
    roots = [fors.treehash(SEEDS[0], SEEDS[2], i << SMALL.b, SMALL.b, adrs) for i in range(SMALL.k_prime)]
    adrs.set_type(A.FORS_ROOTS)
    adrs.set_suffix(0)
    expected = th(SEEDS[2], adrs.to_bytes(), roots)
    assert fors.pk_from_sig(md, sig, SEEDS[2], adrs, SMALL) == expected


def test_sign_and_verify(keypair, signature):
    assert len(signature) == SMALL.signature_size
    assert hypericum.verify(b"message", signature, keypair[0], SMALL)


def test_empty_message(keypair):
    pk, sk = keypair
    assert hypericum.verify(b"", hypericum.sign(b"", sk, SMALL), pk, SMALL)


def test_randomized_mode(keypair):
    pk, sk = keypair
    assert hypericum.sign(b"m", sk, SMALL, randomize=True)[:32] != hypericum.sign(b"m", sk, SMALL)[:32]
    sig1 = hypericum.sign(b"message", sk, SMALL, opt=bytes(32))
    sig2 = hypericum.sign(b"message", sk, SMALL, opt=b"\xff" * 32)
    assert sig1[:32] != sig2[:32]
    assert hypericum.verify(b"message", sig1, pk, SMALL) and hypericum.verify(b"message", sig2, pk, SMALL)


@pytest.mark.parametrize("offset", [0, 32, 40, 36 + 3 * 4 * 32 + 10, -1])
def test_any_changed_byte_breaks_signature(keypair, signature, offset):
    # R, счётчик s, SIG_FORS, начало и конец SIG_HT.
    sig = bytearray(signature)
    sig[offset] ^= 1
    assert not hypericum.verify(b"message", bytes(sig), keypair[0], SMALL)


def test_wrong_message_length_or_key(keypair, signature):
    pk, sig = keypair[0], signature
    assert not hypericum.verify(b"messagf", sig, pk, SMALL)
    assert not hypericum.verify(b"message", sig[:-1], pk, SMALL)
    assert not hypericum.verify(b"message", sig + b"\0", pk, SMALL)
    other, _ = hypericum.keygen(SMALL, b"\x09" * 32, SEEDS[1], SEEDS[2])
    assert not hypericum.verify(b"message", sig, other, SMALL)


def test_seed_length_is_checked():
    with pytest.raises(ValueError):
        hypericum.keygen(SMALL, b"\x01" * 16, SEEDS[1], SEEDS[2])


@pytest.mark.parametrize("h, d, b, k", [(5, 2, 3, 4), (4, 2, 3, 1), (4, 2, 0, 4), (66, 1, 60, 10), (70, 1, 4, 4), (8, 2, 30, 8)])
def test_parameter_validation(h, d, b, k):
    with pytest.raises(ValueError):
        Params("неверный", h=h, d=d, b=b, k=k)
