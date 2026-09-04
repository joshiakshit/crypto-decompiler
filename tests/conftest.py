from pathlib import Path

import pytest

from cryptscan.loader import load

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def samples_ctx():
    return load(FIXTURES / "samples.dex")


@pytest.fixture(scope="session")
def samples_apk_ctx():
    return load(FIXTURES / "samples.apk")
