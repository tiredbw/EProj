import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: долгий тест, запускается при GIPERIKUM_SLOW=1")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("GIPERIKUM_SLOW") == "1":
        return
    skip = pytest.mark.skip(reason="долгий тест, запуск с GIPERIKUM_SLOW=1")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)
