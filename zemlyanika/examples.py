"""Наглядный прогон «Земляники». Контрольных примеров в МР нет, поэтому
сверяется то, что документ всё же задаёт: размеры из таблицы 1, совпадение
ключей у сторон, неявный отказ и собственные регрессионные векторы."""

import json
from pathlib import Path

from . import kem
from .params import ALL, TABLE_1_SIZES

VECTORS = {v["params"]: v for v in json.loads((Path(__file__).parent / "test_vectors.json").read_text(encoding="utf-8"))["vectors"]}

results: list[tuple[str, bool]] = []


def check(title: str, expected: object, actual: object, note: str = "") -> None:
    ok = expected == actual
    results.append((title, ok))
    print(f"\n  {title}")
    print(f"    ожидается: {expected}")
    print(f"    программа: {actual}")
    print(f"    {'PASS' if ok else 'FAIL'}{note if not ok else ''}")


def run() -> None:
    results.clear()
    for params in ALL:
        print("\n" + "=" * 78)
        print(f"{params.name}: q = {params.q}, k = {params.k}, η_s = {params.eta_s}, η_e = {params.eta_e}, "
              f"d_u = {params.du}, d_v = {params.dv}")
        print("=" * 78)
        v = VECTORS[params.name]
        pk, sk = kem.keygen(params, bytes.fromhex(v["seed_a"]), bytes.fromhex(v["seed_s"]), bytes.fromhex(v["z"]))
        key, c = kem.encaps(params, pk, bytes.fromhex(v["m"]))
        sk_size, pk_size, ct_size = TABLE_1_SIZES[params.name]
        check(f"{params.name}: |pk| по таблице 1", pk_size, len(pk))
        check(f"{params.name}: |ct| по таблице 1", ct_size, len(c))
        check(f"{params.name}: |sk| по таблице 1", sk_size, len(sk),
              " — таблица расходится с алгоритмом 5: в ней коэффициенты s упакованы по 3 бита")
        check(f"{params.name}: Decaps возвращает тот же K, что Encaps", key.hex(), kem.decaps(params, sk, c).hex())
        bad = bytes([c[0] ^ 1]) + c[1:]
        check(f"{params.name}: при изменённом шифртексте — ключ отказа H(Z ‖ c)",
              kem.h(sk[-32:] + bad).hex(), kem.decaps(params, sk, bad).hex())
        check(f"{params.name}: собственный регрессионный вектор, K", v["K"], key.hex())
    failed = [title for title, ok in results if not ok]
    print("\n" + "=" * 78)
    print(f"ИТОГ: PASS {len(results) - len(failed)}, FAIL {len(failed)} из {len(results)} проверок")
    for title in failed:
        print(f"  FAIL: {title}")
    print("Контрольных примеров в МР нет: совпадение с документом проверить нельзя.")
    print("=" * 78)


if __name__ == "__main__":
    run()
