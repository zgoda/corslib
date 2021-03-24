from typing import Any, Mapping


def is_request_credentialed(headers: Mapping[str, Any]) -> bool:
    return 'Cookie' in headers or 'Authorization' in headers
