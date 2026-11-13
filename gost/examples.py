"""Наглядный прогон контрольных примеров ГОСТ 34.11-2018 и ГОСТ 34.12-2018:
входные данные, значение из стандарта и результат программы."""

import sys

from .kuznechik import Kuznechik, expand_key, transform_l, transform_s
from .streebog import streebog256, streebog512

M1 = b"012345678901234567890123456789012345678901234567890123456789012"
M2 = "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы".encode("cp1251")

STREEBOG_EXAMPLES = [
    ("Пример 1, хэш-код 512 бит", M1, streebog512,
     "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
     "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"),
    ("Пример 1, хэш-код 256 бит", M1, streebog256,
     "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d"),
    ("Пример 2, хэш-код 512 бит", M2, streebog512,
     "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
     "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e"),
    ("Пример 2, хэш-код 256 бит", M2, streebog256,
     "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"),
]

KEY = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
PLAINTEXT = "1122334455667700ffeeddccbbaa9988"
CIPHERTEXT = "7f679d90bebc24305a468d42b9d4edcd"
ROUND_KEYS = [
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
STATE_AFTER_ROUND = [
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

checks = []


def mark(expected: str, actual: str) -> str:
    checks.append(expected == actual)
    return "✓ совпадает" if expected == actual else "✗ НЕ СОВПАДАЕТ"


def show_hex(label: str, value: str) -> None:
    lines = [value[i:i + 64] for i in range(0, len(value), 64)]
    print(f"    {label:<11}{lines[0]}")
    for line in lines[1:]:
        print(f"    {'':<11}{line}")


def compare(expected: str, actual: str) -> None:
    show_hex("стандарт:", expected)
    show_hex("программа:", actual)
    print(f"    {mark(expected, actual)}")


def run_streebog() -> None:
    print("=" * 78)
    print("СТРИБОГ, ГОСТ 34.11-2018")
    print("Значения записаны как в стандарте: старший байт слева.")
    print("=" * 78)
    for title, message, hash_fn, expected in STREEBOG_EXAMPLES:
        print(f"\n  {title}")
        print(f"    сообщение: «{message.decode('cp1251')}» ({len(message)} байт)")
        compare(expected, hash_fn(message)[::-1].hex())


def run_kuznechik() -> None:
    print("\n" + "=" * 78)
    print("КУЗНЕЧИК, ГОСТ 34.12-2018")
    print("=" * 78)
    print(f"    ключ K:          {KEY}")
    print(f"    открытый текст:  {PLAINTEXT}")

    print("\n  Раундовые ключи (развёртывание ключа)")
    for i, (expected, actual) in enumerate(zip(ROUND_KEYS, expand_key(bytes.fromhex(KEY))), 1):
        print(f"    K{i:<3}{actual.hex()}   {mark(expected, actual.hex())}")

    print("\n  Состояние после каждого раунда LSX зашифрования")
    state = bytes.fromhex(PLAINTEXT)
    for i, (k, expected) in enumerate(zip(expand_key(bytes.fromhex(KEY)), STATE_AFTER_ROUND), 1):
        state = transform_l(transform_s(bytes(x ^ y for x, y in zip(k, state))))
        print(f"    раунд {i}  {state.hex()}   {mark(expected, state.hex())}")

    cipher = Kuznechik(bytes.fromhex(KEY))
    print("\n  Зашифрование E(a)")
    compare(CIPHERTEXT, cipher.encrypt(bytes.fromhex(PLAINTEXT)).hex())
    print("\n  Расшифрование D(b)")
    compare(PLAINTEXT, cipher.decrypt(bytes.fromhex(CIPHERTEXT)).hex())


if __name__ == "__main__":
    run_streebog()
    run_kuznechik()
    print("\n" + "=" * 78)
    print(f"ИТОГ: совпало со стандартом {sum(checks)} из {len(checks)} значений")
    print("=" * 78)
    sys.exit(0 if all(checks) else 1)
