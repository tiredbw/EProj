from doc_hex import bits_to_bytes, doc_hex_to_bits, doc_hex_to_bytes


def test_matches_matrix_m_row_from_appendix_b1():
    # Приложение Б.1: строка матрицы M, hex "932b2" (1 хвостовой ноль),
    # документ явно приводит и бит-вектор (длина 19, не кратна 8), и
    # сериализованные для хэш-функции байты.
    bits = doc_hex_to_bits("932b2", pad=1)
    assert len(bits) == 19
    assert bits_to_bytes(bits) == bytes.fromhex("39b202")


def test_matches_primitive_polynomial_p_from_section_7():
    # p(x) = 1 + x + x^4 + x^6 + x^12 для secparam1264, задаётся как p=(920)1
    expected_bits = [1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0]  # p0..p10
    assert doc_hex_to_bits("920", pad=1) == expected_bits


def test_empty_hex_string_decodes_to_empty():
    assert doc_hex_to_bits("", pad=0) == []
    assert doc_hex_to_bytes("", pad=0) == b""
    assert bits_to_bytes([]) == b""


def test_full_pad_removes_entire_last_nibble():
    # pad=4 убирает ровно одну (последнюю) тетраду целиком
    assert doc_hex_to_bits("90", pad=4) == doc_hex_to_bits("9", pad=0)
