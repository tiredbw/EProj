"""Замер времени и пиковой памяти операций всех схем.

python measure.py         — «Кодиеум» secparam1264, все наборы «Земляники»,
                            «Гиперикум» на малом наборе (около минуты);
python measure.py --full  — плюс остальные наборы «Кодиеума» и подписи
                            наборов «Б» «Гиперикума» (около получаса).

Память считает модуль tracemalloc стандартной библиотеки: это наибольший
объём памяти, который объекты Python занимали во время операции сверх уже
занятого до неё. Сам интерпретатор и загруженные модули в это число не входят.
Под tracemalloc программа работает медленнее, поэтому время замеряется
отдельным прогоном без него.
"""

from __future__ import annotations

import gc
import sys
import time
import tracemalloc
from collections.abc import Callable
from typing import Any


def peak_memory(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, int]:
    """Результат fn и пиковая память в байтах, выделенная во время вызова."""
    gc.collect()
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    tracemalloc.reset_peak()
    before, _ = tracemalloc.get_traced_memory()
    try:
        result = fn(*args, **kwargs)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    return result, peak - before


def elapsed(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Результат fn и время вызова в секундах."""
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - start


def retained_blocks(fn: Callable[[], Any], repeats: int) -> int:
    """На сколько блоков памяти больше занято после repeats вызовов fn.

    Считает sys.getallocatedblocks(): число блоков, выделенных интерпретатором.
    В отличие от tracemalloc, этот счётчик не замедляет программу. Один вызов
    делается до замера: он заполняет кэши, которые и должны оставаться в
    памяти. Затем прирост измеряется в двух окнах по repeats вызовов, и
    возвращается меньший. Разовые выделения интерпретатора (их бывает до
    десятка блоков) попадают только в первое окно, а утечка хотя бы одного
    объекта за вызов даёт не меньше repeats блоков в каждом.
    """
    fn()
    growth = []
    for _ in range(2):
        gc.collect()
        before = sys.getallocatedblocks()
        for _ in range(repeats):
            fn()
        gc.collect()
        growth.append(sys.getallocatedblocks() - before)
    return min(growth)


def kib(n_bytes: int) -> str:
    return f"{n_bytes / 1024:,.0f} КиБ".replace(",", " ")


def seconds(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f} мс"
    return f"{s:.1f} с".replace(".", ",") if s < 10 else f"{s:.0f} с"


def _row(scheme: str, name: str, operation: str, fn: Callable[..., Any], *args: Any) -> Any:
    _, peak = peak_memory(fn, *args)
    result, dt = elapsed(fn, *args)
    print(f"{scheme:11s} {name:20s} {operation:8s} {seconds(dt):>8s} {kib(peak):>12s}", flush=True)
    return result


def _kodieum(full: bool) -> None:
    from kodieum import kem
    from kodieum.params import SECPARAM1264, SECPARAM1396, SECPARAM14128

    for params in [SECPARAM1264, SECPARAM1396, SECPARAM14128] if full else [SECPARAM1264]:
        pk, sk = _row("Кодиеум", params.name, "KeyGen", kem.keygen, params, 1)
        _, enk = _row("Кодиеум", params.name, "Encaps", kem.encaps, params, pk, 7)
        _row("Кодиеум", params.name, "Decaps", kem.decaps, params, sk, enk)


def _zemlyanika() -> None:
    from zemlyanika import kem
    from zemlyanika.params import ALL

    seeds = {"seed_a": b"\x11" * 32, "seed_s": b"\x22" * 32, "z": b"\x33" * 32}
    for params in ALL:
        pk, sk = _row("Земляника", params.name, "KeyGen", lambda p: kem.keygen(p, **seeds), params)
        _, c = _row("Земляника", params.name, "Encaps", kem.encaps, params, pk, b"\x44" * 32)
        _row("Земляника", params.name, "Decaps", kem.decaps, params, sk, c)


def _giperikum(full: bool) -> None:
    from giperikum import hypericum
    from giperikum.params import B_128_20, B_256_20, B_256_64, Params

    small = Params("малый (h=4, d=2)", h=4, d=2, b=3, k=4)
    seeds = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
    for params in [small, B_128_20, B_256_20, B_256_64] if full else [small]:
        pk, sk = _row("Гиперикум", params.name, "KeyGen", hypericum.keygen, params, *seeds)
        sig = _row("Гиперикум", params.name, "Sign", hypericum.sign, b"message", sk, params)
        _row("Гиперикум", params.name, "Verify", hypericum.verify, b"message", sig, pk, params)


def main() -> None:
    full = "--full" in sys.argv[1:]
    print(f"Python {sys.version.split()[0]}; время — отдельный прогон без tracemalloc")
    print(f"{'Схема':11s} {'Набор':20s} {'Операция':8s} {'Время':>8s} {'Пик памяти':>12s}")
    _kodieum(full)
    _zemlyanika()
    _giperikum(full)


if __name__ == "__main__":
    main()
