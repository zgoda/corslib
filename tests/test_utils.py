import pytest

from corslib.utils import is_request_credentialed


@pytest.mark.parametrize(
    "headers",
    [
        {"Cookie": "xxx"},
        {"Authorization": "Basic xxx"},
        {"Cookie": "xxx", "Authorization": "Basic xxx"},
        ["Cookie"],
        ["Authorization"],
        ["Cookie", "Authorization"],
    ],
    ids=[
        "cookie-dict",
        "auth-dict",
        "both-dict",
        "cookie-list",
        "auth-list",
        "both-list",
    ],
)
def test_credentialed_true(headers):
    assert is_request_credentialed(headers) is True


@pytest.mark.parametrize(
    "headers", [{"Field": "value"}, ["Field"]], ids=["dict", "list"]
)
def test_credentialed_false(headers):
    assert is_request_credentialed(headers) is False
