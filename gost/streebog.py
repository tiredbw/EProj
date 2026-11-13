"""Хэш-функция «Стрибог» по ГОСТ 34.11-2018 (длина хэш-кода 256 и 512 бит).

Вектор из V_512 хранится как число Int_512(a), чтобы формулы стандарта
переносились без перестановок. Первый байт строки — младший байт a_0,
поэтому значения из стандарта (старший байт слева) равны байтовым строкам,
прочитанным задом наперёд.
"""

from .sbox import PI

TAU = (
     0,  8, 16, 24, 32, 40, 48, 56,
     1,  9, 17, 25, 33, 41, 49, 57,
     2, 10, 18, 26, 34, 42, 50, 58,
     3, 11, 19, 27, 35, 43, 51, 59,
     4, 12, 20, 28, 36, 44, 52, 60,
     5, 13, 21, 29, 37, 45, 53, 61,
     6, 14, 22, 30, 38, 46, 54, 62,
     7, 15, 23, 31, 39, 47, 55, 63,
)

# Строки 0..63 матрицы A линейного преобразования l
A = (
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
)

# Итерационные константы C_1..C_12; C[0] — это C_1
C = tuple(int(c, 16) for c in (
    "b1085bda1ecadae9ebcb2f81c0657c1f"
    "2f6a76432e45d016714eb88d7585c4fc"
    "4b7ce09192676901a2422a08a460d315"
    "05767436cc744d23dd806559f2a64507",
    "6fa3b58aa99d2f1a4fe39d460f70b5d7"
    "f3feea720a232b9861d55e0f16b50131"
    "9ab5176b12d699585cb561c2db0aa7ca"
    "55dda21bd7cbcd56e679047021b19bb7",
    "f574dcac2bce2fc70a39fc286a3d8435"
    "06f15e5f529c1f8bf2ea7514b1297b7b"
    "d3e20fe490359eb1c1c93a376062db09"
    "c2b6f443867adb31991e96f50aba0ab2",
    "ef1fdfb3e81566d2f948e1a05d71e4dd"
    "488e857e335c3c7d9d721cad685e353f"
    "a9d72c82ed03d675d8b71333935203be"
    "3453eaa193e837f1220cbebc84e3d12e",
    "4bea6bacad4747999a3f410c6ca92363"
    "7f151c1f1686104a359e35d7800fffbd"
    "bfcd1747253af5a3dfff00b723271a16"
    "7a56a27ea9ea63f5601758fd7c6cfe57",
    "ae4faeae1d3ad3d96fa4c33b7a3039c0"
    "2d66c4f95142a46c187f9ab49af08ec6"
    "cffaa6b71c9ab7b40af21f66c2bec6b6"
    "bf71c57236904f35fa68407a46647d6e",
    "f4c70e16eeaac5ec51ac86febf240954"
    "399ec6c7e6bf87c9d3473e33197a93c9"
    "0992abc52d822c3706476983284a0504"
    "3517454ca23c4af38886564d3a14d493",
    "9b1f5b424d93c9a703e7aa020c6e4141"
    "4eb7f8719c36de1e89b4443b4ddbc49a"
    "f4892bcb929b069069d18d2bd1a5c42f"
    "36acc2355951a8d9a47f0dd4bf02e71e",
    "378f5a541631229b944c9ad8ec165fde"
    "3a7d3a1b258942243cd955b7e00d0984"
    "800a440bdbb2ceb17b2b8a9aa6079c54"
    "0e38dc92cb1f2a607261445183235adb",
    "abbedea680056f52382ae548b2e4f3f3"
    "8941e71cff8a78db1fffe18a1b336103"
    "9fe76702af69334b7a1e6c303b7652f4"
    "3698fad1153bb6c374b4c7fb98459ced",
    "7bcd9ed0efc889fb3002c6cd635afe94"
    "d8fa6bbbebab07612001802114846679"
    "8a1d71efea48b9caefbacd1d7d476e98"
    "dea2594ac06fd85d6bcaa4cd81f32d1b",
    "378ee767f11631bad21380b00449b17a"
    "cda43c32bcdf1d77f82012d430219f9b"
    "5d80ef9d1891cc86e71da4aa88e12852"
    "faf417d5d9b21b9948bc924af11bd720",
))

MASK_64 = (1 << 64) - 1
MASK_512 = (1 << 512) - 1

IV_512 = 0
IV_256 = int.from_bytes(bytes([1] * 64), "little")  # (00000001)^64


def transform_s(a: int) -> int:
    """S(a_63||...||a_0) = π(a_63)||...||π(a_0)."""
    return int.from_bytes(bytes(PI[x] for x in a.to_bytes(64, "little")), "little")


def transform_p(a: int) -> int:
    """P(a_63||...||a_0) = a_τ(63)||...||a_τ(0)."""
    b = a.to_bytes(64, "little")
    return int.from_bytes(bytes(b[TAU[i]] for i in range(64)), "little")


def transform_l64(b: int) -> int:
    """l(b) — умножение b_63...b_0 справа на матрицу A над GF(2):
    бит b_(63-i) выбирает строку A[i]."""
    c = 0
    for i in range(64):
        if (b >> (63 - i)) & 1:
            c ^= A[i]
    return c


def transform_l(a: int) -> int:
    """L(a_7||...||a_0) = l(a_7)||...||l(a_0), a_i из V_64."""
    result = 0
    for j in range(8):
        result |= transform_l64((a >> (64 * j)) & MASK_64) << (64 * j)
    return result


def lps(a: int) -> int:
    return transform_l(transform_p(transform_s(a)))


# LPS одной таблицей на байт: P переносит байт 8q + j входа в байт q слова j,
# а l линейно по байтам слова, поэтому вклад этого байта — l(π(x) << 8q).
_LPS_TABLES = [[transform_l64(PI[x] << (8 * q)) for x in range(256)] for q in range(8)]


def lps_table(a: int) -> int:
    """То же, что lps, но в 12 раз быстрее; используется при хэшировании."""
    t0, t1, t2, t3, t4, t5, t6, t7 = _LPS_TABLES
    b = a.to_bytes(64, "little")
    result = 0
    for j in range(8):
        word = (t0[b[j]] ^ t1[b[8 + j]] ^ t2[b[16 + j]] ^ t3[b[24 + j]]
                ^ t4[b[32 + j]] ^ t5[b[40 + j]] ^ t6[b[48 + j]] ^ t7[b[56 + j]])
        result |= word << (64 * j)
    return result


def transform_e(k: int, m: int) -> int:
    """E(K, m) = X[K_13]LPSX[K_12]...LPSX[K_1](m),
    где K_1 = K, K_i = LPS(K_(i-1) xor C_(i-1))."""
    state = m
    for i in range(12):
        state = lps_table(k ^ state)
        k = lps_table(k ^ C[i])
    return k ^ state


def g(n: int, h: int, m: int) -> int:
    """Функция сжатия g_N(h, m) = E(LPS(h xor N), m) xor h xor m."""
    return transform_e(lps_table(h ^ n), m) ^ h ^ m


def _hash(message: bytes, iv: int) -> int:
    h = iv
    n = 0
    sigma = 0

    # Этап 2: пока |M| >= 512, отщепляем младшие 512 бит — первые 64 байта строки
    offset = 0
    while len(message) - offset >= 64:
        m = int.from_bytes(message[offset:offset + 64], "little")
        h = g(n, h, m)
        n = (n + 512) & MASK_512
        sigma = (sigma + m) & MASK_512
        offset += 64

    # Этап 3: m = 0^(511-|M|) || 1 || M
    rest = message[offset:]
    m = int.from_bytes(rest, "little") | (1 << (8 * len(rest)))
    h = g(n, h, m)
    n = (n + 8 * len(rest)) & MASK_512
    sigma = (sigma + m) & MASK_512
    h = g(0, h, n)
    return g(0, h, sigma)


def streebog512(message: bytes) -> bytes:
    return _hash(message, IV_512).to_bytes(64, "little")


def streebog256(message: bytes) -> bytes:
    """H_256(M) = MSB_256 от результата с IV = (00000001)^64."""
    return (_hash(message, IV_256) >> 256).to_bytes(32, "little")
