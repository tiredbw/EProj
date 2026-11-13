"""HMAC_GOSTR3411_2012_256 и KDF_TREE_GOSTR3411_2012_256 из Р 50.1.113-2016
(английский перевод — RFC 7836, разделы 4.1.1 и 4.4) на собственном Стрибоге-256."""

from .streebog import streebog256

BLOCK_SIZE = 64


def hmac_streebog256(key: bytes, data: bytes) -> bytes:
    """HMAC(K, T) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ T)) по RFC 2104, H — Стрибог-256,
    размер блока 64 байта. Ключ — не длиннее блока."""
    if len(key) > BLOCK_SIZE:
        raise ValueError(f"ключ HMAC должен быть не длиннее {BLOCK_SIZE} байт, получено {len(key)}")
    key = key.ljust(BLOCK_SIZE, b"\x00")
    inner = streebog256(bytes(b ^ 0x36 for b in key) + data)
    return streebog256(bytes(b ^ 0x5C for b in key) + inner)


def kdf_tree_streebog256(key: bytes, length_bits: int, label: bytes = b"", seed: bytes = b"", r: int = 1) -> bytes:
    """K(1) ‖ K(2) ‖ …, обрезанное до L бит, где
    K(i) = HMAC(K_in, [i]_b ‖ label ‖ 0x00 ‖ seed ‖ [L]_b).

    [i]_b занимает R байт, [L]_b — без ведущих нулевых байтов; оба big-endian.
    """
    if length_bits <= 0 or length_bits % 8:
        raise ValueError(f"длина L должна быть положительной и кратной 8, получено {length_bits}")
    if not 1 <= r <= 4:
        raise ValueError(f"R должно быть от 1 до 4, получено {r}")
    block_count = (length_bits // 8 + 31) // 32
    if block_count >= 1 << (8 * r):
        raise ValueError(f"при R = {r} нельзя выработать {length_bits} бит")
    length_field = length_bits.to_bytes((length_bits.bit_length() + 7) // 8, "big")
    blocks = [
        hmac_streebog256(key, i.to_bytes(r, "big") + label + b"\x00" + seed + length_field)
        for i in range(1, block_count + 1)
    ]
    return b"".join(blocks)[: length_bits // 8]
