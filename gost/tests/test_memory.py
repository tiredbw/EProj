"""Расход памяти «Стрибога»: сообщение обрабатывается блоками по 64 байта.

Пик памяти — объём, который объекты Python занимали во время операции
сверх занятого до неё (модуль tracemalloc, см. measure.py в корне).
"""

from gost.streebog import streebog256
from measure import peak_memory


def test_streebog_memory_does_not_depend_on_message_length():
    short = bytes(64)
    long = bytes(64 * 1024)  # в 1024 раза длиннее
    _, short_peak = peak_memory(streebog256, short)
    _, long_peak = peak_memory(streebog256, long)
    # Замер: около 1,3 КиБ на любой длине. Копия всего сообщения заняла бы 64 КиБ.
    assert long_peak < 8 * 1024
    assert abs(long_peak - short_peak) < 1024
