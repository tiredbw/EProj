"""Сравнение «Кодиеума» и «Земляники» на одних и тех же входных данных.

python compare_kem.py           — пара secparam1264 и Z512, 3 прогона (около 30 с);
python compare_kem.py --full    — все три уровня стойкости (около 10 минут);
python compare_kem.py --runs N  — число прогонов на каждый набор.

Одинаковые входы. Оба механизма получают одни и те же случайные данные из
генератора с фиксированным начальным значением, поэтому результат
воспроизводим (для настоящих ключей такой генератор не годится):
- KeyGen — блок R из 96 байт. «Кодиеум» берёт seed₁ = R[0:32], остальное он
  вырабатывает из seed₁ сам функцией HKDF. «Земляника» берёт
  seed_A = R[0:32], seed_s = R[32:64] и z = R[64:96].
- Encaps — одна и та же 32-байтная строка: seed₃ у «Кодиеума» и сообщение m
  у «Земляники».
- Неявный отказ — в обоих шифртекстах инвертируется первый бит.

Пары наборов. Уровни стойкости «Кодиеума» заданы в таблице 2 МР: 128, 192 и
256 бит. В МР «Земляники» уровней нет, поэтому пары составлены по аналогии
со схемой Kyber, на которую она похожа: Z512 — 128, Z768-R и Z768-C — 192,
Z1024 — 256. Это наше допущение, а не утверждение документа.

Время — медиана по прогонам без tracemalloc; пик памяти — на первом прогоне
(см. measure.py).
"""

from __future__ import annotations

import random
import statistics
import sys
from dataclasses import dataclass, field

from kodieum import kem as kodieum_kem
from kodieum.params import SECPARAM1264, SECPARAM1396, SECPARAM14128
from kodieum.vectors import deserialize
from measure import elapsed, kib, peak_memory, seconds
from zemlyanika import kem as zemlyanika_kem
from zemlyanika.params import Z512, Z768_C, Z768_R, Z1024

LEVELS = [
    (128, SECPARAM1264, [Z512]),
    (192, SECPARAM1396, [Z768_R, Z768_C]),
    (256, SECPARAM14128, [Z1024]),
]
OPERATIONS = ("KeyGen", "Encaps", "Decaps")


@dataclass
class Inputs:
    keygen: bytes  # 96 байт
    encaps: bytes  # 32 байта


@dataclass
class Result:
    name: str
    sizes: dict[str, int]
    times: dict[str, list[float]] = field(default_factory=lambda: {op: [] for op in OPERATIONS})
    peaks: dict[str, int] = field(default_factory=dict)
    keys_match: int = 0
    rejections: int = 0
    runs: int = 0


def make_inputs(runs: int, seed: int = 2026) -> list[Inputs]:
    rng = random.Random(seed)
    return [Inputs(rng.randbytes(96), rng.randbytes(32)) for _ in range(runs)]


class Kodieum:
    def __init__(self, params):
        self.params = params
        self.name = params.name

    def sizes(self) -> dict[str, int]:
        p = self.params
        return {
            "pk": p.mt * ((p.n - p.mt + 7) // 8),  # строки A по Б.1
            "sk": 32 + p.n // 8,  # seed₂ ‖ salt
            "ct": p.mt // 8,  # синдром s
            "K": 32,
        }

    def keygen(self, inputs: Inputs):
        return kodieum_kem.keygen(self.params, deserialize(inputs.keygen[:32], 256))

    def encaps(self, pk, inputs: Inputs):
        return kodieum_kem.encaps(self.params, pk, deserialize(inputs.encaps, 256))

    def decaps(self, sk, ct):
        return kodieum_kem.decaps(self.params, sk, ct)

    @staticmethod
    def corrupt(ct: int) -> int:
        return ct ^ 1


class Zemlyanika:
    def __init__(self, params):
        self.params = params
        self.name = params.name

    def sizes(self) -> dict[str, int]:
        p = self.params
        return {"pk": p.pk_size, "sk": p.sk_size, "ct": p.ct_size, "K": 32}

    def keygen(self, inputs: Inputs):
        r = inputs.keygen
        return zemlyanika_kem.keygen(self.params, seed_a=r[:32], seed_s=r[32:64], z=r[64:96])

    def encaps(self, pk, inputs: Inputs):
        return zemlyanika_kem.encaps(self.params, pk, inputs.encaps)

    def decaps(self, sk, ct):
        return zemlyanika_kem.decaps(self.params, sk, ct)

    @staticmethod
    def corrupt(ct: bytes) -> bytes:
        return bytes([ct[0] ^ 1]) + ct[1:]


def run(scheme, all_inputs: list[Inputs]) -> Result:
    result = Result(scheme.name, scheme.sizes())
    for i, inputs in enumerate(all_inputs):
        if i == 0:
            _, result.peaks["KeyGen"] = peak_memory(scheme.keygen, inputs)
        (pk, sk), dt = elapsed(scheme.keygen, inputs)
        result.times["KeyGen"].append(dt)
        if i == 0:
            _, result.peaks["Encaps"] = peak_memory(scheme.encaps, pk, inputs)
        (key, ct), dt = elapsed(scheme.encaps, pk, inputs)
        result.times["Encaps"].append(dt)
        if i == 0:
            _, result.peaks["Decaps"] = peak_memory(scheme.decaps, sk, ct)
        key2, dt = elapsed(scheme.decaps, sk, ct)
        result.times["Decaps"].append(dt)
        result.keys_match += key2 == key
        result.rejections += scheme.decaps(sk, scheme.corrupt(ct)) != key
        result.runs += 1
    return result


def fmt_bytes(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def print_level(level: int, results: list[Result]) -> None:
    width = 18
    print(f"\nУровень {level} бит: " + " / ".join(r.name for r in results))
    print(f"{'':28s}" + "".join(f"{r.name:>{width}s}" for r in results))
    rows: list[tuple[str, list[str]]] = []
    for key, title in [("pk", "открытый ключ, байт"), ("sk", "закрытый ключ, байт"),
                       ("ct", "шифртекст, байт"), ("K", "общий ключ, байт")]:
        rows.append((title, [fmt_bytes(r.sizes[key]) for r in results]))
    for op in OPERATIONS:
        rows.append((f"{op}, время (медиана)", [seconds(statistics.median(r.times[op])) for r in results]))
    for op in OPERATIONS:
        rows.append((f"{op}, пик памяти", [kib(r.peaks[op]) for r in results]))
    rows.append(("ключи сторон совпали", [f"{r.keys_match} из {r.runs}" for r in results]))
    rows.append(("неявный отказ сработал", [f"{r.rejections} из {r.runs}" for r in results]))
    for title, cells in rows:
        print(f"{title:28s}" + "".join(f"{c:>{width}s}" for c in cells))


def main() -> None:
    args = sys.argv[1:]
    full = "--full" in args
    runs = int(args[args.index("--runs") + 1]) if "--runs" in args else 3
    print(f"Python {sys.version.split()[0]}; прогонов на набор: {runs}; входы одинаковы для обеих схем")
    all_inputs = make_inputs(runs)
    for level, kodieum_params, zemlyanika_sets in LEVELS if full else LEVELS[:1]:
        results = [run(Kodieum(kodieum_params), all_inputs)]
        results += [run(Zemlyanika(p), all_inputs) for p in zemlyanika_sets]
        print_level(level, results)


if __name__ == "__main__":
    main()
