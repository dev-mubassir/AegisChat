import pytest
from app.auth import reset_rate_limits


@pytest.fixture(autouse=True)
def clear_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()
