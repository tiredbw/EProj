"""Наглядный прогон контрольных примеров приложения Б МР «Кодиеум» (secparam1264):
для каждого значения — исходные данные, ожидаемое по документу, результат
программы и итог PASS/FAIL."""

import json
from pathlib import Path

from . import decode as D
from . import kem
from .auxiliary import M_PRIME, gen_unique_seq, weight_vec_from_v
from .field import Field
from .goppa import parity_check_matrix, systematic_part
from .params import SECPARAM1264 as P
from .primitives import BlockCipher, h256, hkdf
from .vectors import deserialize, from_doc_hex, serialize_list, to_doc_hex

DATA = json.loads((Path(__file__).parent / "control_examples.json").read_text(encoding="utf-8"))
MASK_256 = (1 << 256) - 1

results: list[tuple[str, bool]] = []
section = ""


def vec(text: str) -> int:
    return from_doc_hex(text)[0]


def items(text: str) -> list[int]:
    return [vec(x) for x in text.split("|")]


def hexes(values: list[int]) -> list[str]:
    return [to_doc_hex(x, P.m) for x in values]


def short(value: str) -> str:
    return value if len(value) <= 64 else f"{value[:28]}…{value[-28:]} ({len(value)} символов)"


def verdict(title: str, ok: bool, note: str = "") -> None:
    results.append((f"{section} {title}", ok))
    print(f"    {'PASS' if ok else 'FAIL'}{note}")


def check(title: str, expected: str, actual: str, note: str = "") -> None:
    print(f"\n  {title}")
    print(f"    документ:  {short(expected)}")
    print(f"    программа: {short(actual)}")
    verdict(title, expected == actual, note if expected != actual else "")


def check_list(title: str, expected: list[str], actual: list[str]) -> None:
    print(f"\n  {title}: {len(expected)} значений")
    print(f"    документ:  {' '.join(expected[:3])} … {' '.join(expected[-3:])}")
    print(f"    программа: {' '.join(actual[:3])} … {' '.join(actual[-3:])}")
    mismatches = sum(x != y for x, y in zip(expected, actual)) + abs(len(expected) - len(actual))
    verdict(title, mismatches == 0, f": не совпало {mismatches}")


def header(title: str, inputs: str) -> None:
    global section
    section = title.split(" ")[0].rstrip(".")
    print("\n" + "=" * 78)
    print(title)
    print(f"Вход: {inputs}")
    print("=" * 78)


KDF_NOTE = " — значение документа не воспроизводится (README, раздел «Почему не сходится HKDF»)"


def run() -> None:
    results.clear()
    b1, b2, b3, b4, b5, b6 = (DATA[k] for k in ("B1", "B2", "B3", "B4", "B5", "B6"))
    field = Field(P.m, P.p)

    header("Б.1. Сериализация и H_256", "матрица M 5 × 19 и список a из 5 векторов длины 7")
    rows = [from_doc_hex(r, 1)[0] for r in b1["M_rows"].split("|")]
    check("H_256(M)", b1["H256_M"], h256(serialize_list(rows, b1["M_row_length"])).hex())
    a_list = [from_doc_hex(x, 1)[0] for x in b1["a_items"].split("|")]
    check("H_256(a)", b1["H256_a"], h256(serialize_list(a_list, b1["a_item_length"])).hex())

    k = vec(b2["k"])
    header("Б.2. gen_unique_seq(12, 3584, k)", f"k = {b2['k']}")
    cipher = BlockCipher(k)
    for i, expected in b2["E_k"].items():
        check(f"Шаг 1: a_{i} = E_k({i})", expected, to_doc_hex(cipher.encrypt(int(i)), 128))
    ordered = sorted(cipher.encrypt(i) for i in range(1 << P.m))
    for i, expected in b2["sorted"].items():
        check(f"Шаг 2: b_{i}", expected, to_doc_hex(ordered[int(i)], 128))
    ell = gen_unique_seq(P.m, P.n + P.t, k)
    check_list("Шаг 3: c_0 … c_3583", b2["c"].split("|"), hexes(ell))

    header("Б.3. gen_weight_vec(3520, 64, 12, seed)", f"seed = {b3['seed']}")
    v_bits = -(-(1 << P.m) // P.n) * P.t * M_PRIME
    out = hkdf(vec(b3["seed"]), 256 + v_bits)
    check("Шаг 2: seed′", b3["seed_prime"], to_doc_hex(out & MASK_256, 256), KDF_NOTE)
    check("Шаг 2: v", b3["v"], to_doc_hex(out >> 256, v_bits), KDF_NOTE)
    e_doc = vec(b3["e"])
    check("Шаги 3–7: e по v из документа", b3["e"],
          to_doc_hex(weight_vec_from_v(P.n, P.t, P.m, vec(b3["v"])), P.n))

    a, g = ell[: P.n], ell[P.n :]
    s = vec(b6["s"])
    header("Б.4. Decode(a, g, s, p)", "a, g из Б.2 (= Б.5), s из Б.6")
    alpha = D.compute_alpha(field, a, P.n, P.t)
    check_list("Шаги 1–9: α_0 … α_3520", b4["alpha"].split("|"), hexes(alpha))
    r = D.compute_r(field, a, g, s, P.mt)
    check_list("Шаг 10: r_0 … r_767", b4["r"].split("|"), hexes(r))
    b = D.compute_b(field, a, alpha, P.n, P.t, P.mt)
    flat = [x for row in b for x in row]
    head, tail = b4["b_head"].split("|"), b4["b_tail"].split("|")
    check_list("Шаги 11–15: b, первые 254", head, hexes(flat[: len(head)]))
    check_list("Шаги 11–15: b, последние 254", tail, hexes(flat[-len(tail):]))
    check("H_256(b)", b4["H256_b"], h256(serialize_list(flat, P.m)).hex())
    beta = D.compute_beta(field, r, b, P.t)
    check_list("Шаг 16: β_0 … β_127", b4["beta"].split("|"), hexes(beta))
    solution = D.solve_homogeneous(field, D.build_system(alpha, beta, P.n, P.t))
    check_list("Шаг 17: y_0 … y_64", b4["y"].split("|"), hexes(solution[: P.t + 1]))
    check_list("Шаг 17: z_0 … z_63", b4["z"].split("|"), hexes(solution[P.t + 1 :]))
    v = D.evaluate_locator(field, a, solution[: P.t + 1], P.n, P.t)
    check_list("Шаги 19–23: v_0 … v_3519", b4["v"].split("|"), hexes(v))
    check("Шаг 28: e", b3["e"], to_doc_hex(D.decode(field, a, g, s, P.n, P.t), P.n))

    header("Б.5. KeyGen", f"seed_1 = {b5['seed1']}")
    out = hkdf(vec(b5["seed1"]), 512 + P.n)
    check("Шаг 2: seed_2", b5["seed2"], to_doc_hex(out & MASK_256, 256), KDF_NOTE)
    check("Шаг 2: seed′", b5["seed_prime"], to_doc_hex((out >> 256) & MASK_256, 256), KDF_NOTE)
    check("Шаг 2: salt", b5["salt"], to_doc_hex(out >> 512, P.n), KDF_NOTE)
    print("\n  Дальше — по seed_2 из документа.")
    H = parity_check_matrix(field, a, g, P.t)
    check("Шаг 6: H_256(H)", b5["H256_H"], h256(serialize_list(H, P.n)).hex())
    A = systematic_part(H, P.mt)
    check("Шаг 7: H_256(A)", b5["H256_A"], h256(serialize_list(A, P.n - P.mt)).hex())

    header("Б.6. Encaps", "pk = A из Б.5, e из Б.3 (выработан по seed_3)")
    check("Шаг 4: s", b6["s"], to_doc_hex(kem.syndrome(A, e_doc, P.mt), P.mt))
    shk = kem.shared_key(e_doc, P.n, s, P.mt)
    check("Шаг 5: shk", b6["shk"], to_doc_hex(deserialize(shk, 256), 256))

    header("Б.7. Decaps", "sk = (seed_2, salt) из Б.5, enk = s из Б.6")
    shk = kem.decaps(P, (vec(b5["seed2"]), vec(b5["salt"])), s)
    check("Шаг 7: shk", b6["shk"], to_doc_hex(deserialize(shk, 256), 256))

    failed = [title for title, ok in results if not ok]
    print("\n" + "=" * 78)
    print(f"ИТОГ: PASS {len(results) - len(failed)}, FAIL {len(failed)} из {len(results)} проверок")
    for title in failed:
        print(f"  FAIL: {title}")
    print("=" * 78)


if __name__ == "__main__":
    run()
