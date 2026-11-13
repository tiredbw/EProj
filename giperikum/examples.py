"""Наглядный прогон контрольных примеров приложения А МР «Гиперикум»:
для каждого значения — ожидаемое по документу, результат программы и PASS/FAIL.

python -m giperikum.examples         — все шесть наборов без построения деревьев (около 20 с);
python -m giperikum.examples --full  — ещё PK.root, полная подпись и проверка для наборов «Б» (несколько минут).
"""

import json
import sys
from pathlib import Path

from . import fors, hypericum, hypertree, wots
from .address import Address
from .hashes import h_msg, prf_msg
from .params import ALL, Params

SETS = json.loads((Path(__file__).parent / "control_examples.json").read_text(encoding="utf-8"))["sets"]

results: list[tuple[str, bool]] = []


def short(value: str) -> str:
    return value if len(value) <= 64 else f"{value[:28]}…{value[-28:]}"


def check(title: str, expected: object, actual: object, note: str = "") -> None:
    ok = expected == actual
    results.append((title, ok))
    print(f"\n  {title}")
    print(f"    документ:  {short(str(expected))}")
    print(f"    программа: {short(str(actual))}")
    print(f"    {'PASS' if ok else 'FAIL'}{note if not ok else ''}")


def run_set(params: Params, d: dict, full: bool) -> None:
    print("\n" + "=" * 78)
    print(f"{params.name}: h = {params.h}, d = {params.d}, b = {params.b}, k = {params.k}")
    print(f"Сообщение: «{d['message']}» и завершающий нулевой байт")
    print("=" * 78)
    name = params.name
    m = d["message"].encode() + b"\0"
    pk = hypericum.PublicKey(bytes.fromhex(d["PK.seed"]), bytes.fromhex(d["PK.root"]))
    sk = hypericum.SecretKey(bytes.fromhex(d["SK.seed"]), bytes.fromhex(d["SK.prf"]), pk)

    r = prf_msg(sk.prf, pk.seed, hypericum.OPT_CONST, m)
    check(f"{name}: R = PRF_msg(SK.prf, PK.seed, opt_const, M)", d["R"], r.hex())
    digest = h_msg(r, pk.seed, pk.root, bytes.fromhex(d["s"]), m)
    check(f"{name}: digest = H_msg(R, PK.seed, PK.root, s ‖ M), s = {d['s']}", d["digest"], digest.hex())
    idx = hypericum.split_digest(digest, params)
    check(f"{name}: младшие b бит md равны 0 (условие FORS+C)", True, idx.last_tree_is_zero)
    note = " — в документе повторено значение из A.4; WOTS_PK ниже сходятся при значении программы" \
        if name == "Гиперикум_М_256_20" else ""
    check(f"{name}: idx_tree", d["idx_tree"], idx.idx_tree, note)
    check(f"{name}: idx_leaf", d["idx_leaf"], idx.idx_leaf)

    tree, leaf = idx.idx_tree, idx.idx_leaf
    for j, layer in enumerate(d["layers"]):
        if j:
            leaf, tree = tree % (1 << params.h_prime), tree >> params.h_prime
        adrs = Address()
        adrs.set_layer(j)
        adrs.set_tree(tree)
        adrs.set_keypair(leaf)
        check(f"{name}: слой {j}, WOTS_PK", layer["WOTS_PK"], wots.pk_gen(sk.seed, pk.seed, adrs).hex())

    if not full or params.name.split("_")[1] != "Б":
        return
    check(f"{name}: PK.root = HT.PKgen(SK.seed, PK.seed)", d["PK.root"], hypertree.pk_gen(sk.seed, pk.seed, params).hex())
    sig = hypericum.sign(m, sk, params)
    _, s, sig_fors, sig_ht = hypericum.split_signature(sig, params)
    check(f"{name}: s в подписи", d["s"], s.hex())
    check(f"{name}: SIG_FORS (первые и последние 4 байта)", (d["SIG_FORS_head"], d["SIG_FORS_tail"]),
          (sig_fors[:4].hex(), sig_fors[-4:].hex()))
    size = hypertree.xmss_sig_size(params)
    for j, (head, tail) in enumerate(d["SIG_HT_layers"]):
        part = sig_ht[j * size : (j + 1) * size]
        note = " — в документе повторены последние байты слоя 1; XMSS_PK слоя 0 ниже сходится" \
            if name == "Гиперикум_Б_128_20" and j == 0 else ""
        check(f"{name}: SIG_HT, слой {j} (первые и последние 4 байта)", (head, tail),
              (part[:4].hex(), part[-4:].hex()), note)
    pk_fors = fors.pk_from_sig(idx.md, sig_fors, pk.seed, hypericum.fors_address(idx), params)
    check(f"{name}: PK_FORS", d["PK_FORS"], pk_fors.hex())
    roots = hypertree.layer_roots(pk_fors, sig_ht, pk.seed, idx.idx_tree, idx.idx_leaf, params)
    for j, (root, layer) in enumerate(zip(roots, d["layers"])):
        check(f"{name}: слой {j}, XMSS_PK", layer["XMSS_PK"], root.hex())
    check(f"{name}: Hypericum.Verify", True, hypericum.verify(m, sig, pk, params))


def run(full: bool) -> None:
    results.clear()
    for params, d in zip(ALL, SETS):
        run_set(params, d, full)
    failed = [title for title, ok in results if not ok]
    print("\n" + "=" * 78)
    print(f"ИТОГ: PASS {len(results) - len(failed)}, FAIL {len(failed)} из {len(results)} проверок")
    for title in failed:
        print(f"  FAIL: {title}")
    print("=" * 78)


if __name__ == "__main__":
    run(full="--full" in sys.argv)
