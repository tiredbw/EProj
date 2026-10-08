"""Внешние криптопримитивы, используемые алгоритмом «Кодиеум», но не являющиеся
предметом реализации по заданию (раздел "Зависимости" МР): Стрибог-256
(ГОСТ 34.11-2018), Кузнечик (ГОСТ 34.12-2018) и KDF_TREE_GOSTR3411_2012_256
(Р 50.1.113-2016, §4.5). Обёртка над пакетом `gostcrypto`.
"""

from gostcrypto import gosthash, gosthmac, gostcipher


def streebog256(data: bytes) -> bytes:
    """H_256(data) из раздела 3.2 МР."""
    h = gosthash.new("streebog256", data=bytearray(data))
    return bytes(h.digest())


def kuznechik_encrypt_block(key: bytes, block: bytes) -> bytes:
    """E_K(block) из раздела 6.1 МР: одноблочное шифрование Кузнечик (128 бит)."""
    cipher = gostcipher.new("kuznechik", bytearray(key), gostcipher.MODE_ECB)
    return bytes(cipher.encrypt(bytearray(block)))


def kdf_tree_streebog256(k_in: bytes, l_bits: int, label: bytes = b"", seed: bytes = b"", r: int = 1) -> bytes:
    """KDF_TREE_GOSTR3411_2012_256(K_in, label, seed, R), формула из RFC 7836 §4.4
    (тот же алгоритм, что в Р 50.1.113-2016 §4.5, на который ссылается документ).

    K(i) = HMAC_Стрибог256(K_in, [i]_R_байт || label || 0x00 || seed || [L]_мин.байт)
    Выход = K(1) || K(2) || ... обрезанный до l_bits.
    """
    if l_bits % 8 != 0:
        raise NotImplementedError("non-byte-aligned L is not needed by this project")
    l_bytes_needed = l_bits // 8
    l_encoded = l_bits.to_bytes((l_bits.bit_length() + 7) // 8 or 1, "big")

    blocks = []
    i = 1
    produced = 0
    while produced < l_bytes_needed:
        counter = i.to_bytes(r, "big")
        msg = counter + label + b"\x00" + seed + l_encoded
        mac = gosthmac.new("HMAC_GOSTR3411_2012_256", key=bytearray(k_in), data=bytearray(msg))
        block = bytes(mac.digest())
        blocks.append(block)
        produced += len(block)
        i += 1

    return b"".join(blocks)[:l_bytes_needed]
