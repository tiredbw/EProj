"""Единая точка входа: наглядные прогоны контрольных примеров всех частей проекта.

python main.py         — «Стрибог» и «Кузнечик», «Кодиеум», «Гиперикум», «Земляника» (около 15 с);
python main.py --full  — то же, с полной подписью наборов «Б» «Гиперикума» (несколько минут).
Автотесты запускаются отдельно: python -m pytest.
"""

import subprocess
import sys

MODULES = [
    ("gost.examples", "«Стрибог» и «Кузнечик»"),
    ("kodieum.examples", "«Кодиеум»"),
    ("giperikum.examples", "«Гиперикум»"),
    ("zemlyanika.examples", "«Земляника»"),
]


def main() -> None:
    full = "--full" in sys.argv[1:]
    summary = []
    for module, title in MODULES:
        args = [sys.executable, "-m", module]
        if full and module == "giperikum.examples":
            args.append("--full")
        output = subprocess.run(args, capture_output=True, text=True, check=False).stdout
        print(output, end="")
        total = next((line for line in output.splitlines() if line.startswith("ИТОГ")), "ИТОГ не получен")
        summary.append(f"{title}: {total.removeprefix('ИТОГ: ')}")
    print("\n" + "=" * 78)
    print("СВОДКА")
    for line in summary:
        print(f"  {line}")
    print("Причины каждого FAIL разобраны в ANALYSIS.md соответствующей папки.")
    print("=" * 78)


if __name__ == "__main__":
    main()
