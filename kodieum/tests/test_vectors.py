"""Векторы, их запись и сериализация (раздел 5.2, приложение Б.1)."""

from kodieum.vectors import deserialize, from_doc_hex, serialize, serialize_list, to_doc_hex


def bits(text: str) -> int:
    return sum(int(c) << i for i, c in enumerate(text))


def test_doc_hex_example_from_b1():
    # Б.1: (99eb1)_3 = (10011001011111011).
    assert from_doc_hex("99eb1", 3) == (bits("10011001011111011"), 17)
    assert to_doc_hex(bits("10011001011111011"), 17) == "99eb1"


def test_matrix_serialization_example_from_b1():
    rows = [
        "1001110001001101010", "0011110001001101101", "0110111011000000000",
        "0101100101010010000", "0111100000101100110",
    ]
    assert [to_doc_hex(bits(r), 19) for r in rows] == ["932b2", "c32b5", "67300", "a9a40", "e1433"]
    expected = bytes([0x39, 0xB2, 0x02, 0x3C, 0xB2, 0x05, 0x76, 0x03, 0x00,
                      0x9A, 0x4A, 0x00, 0x1E, 0x34, 0x03])
    assert serialize_list([bits(r) for r in rows], 19) == expected


def test_list_serialization_example_from_b1():
    items = ["1001000", "0010010", "1101000", "1010111", "1111111"]
    assert serialize_list([bits(x) for x in items], 7) == bytes([0x09, 0x24, 0x0B, 0x75, 0x7F])


def test_serialize_roundtrip():
    value = (1 << 3519) | 0b1011
    data = serialize(value, 3520)
    assert len(data) == 440
    assert deserialize(data, 3520) == value
    assert serialize(0b101, 3) == b"\x05"
