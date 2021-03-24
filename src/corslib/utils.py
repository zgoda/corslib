from typing import Any, Mapping, Sequence, Union


def is_request_credentialed(headers: Union[Mapping[str, Any], Sequence[str]]) -> bool:
    """Utility function that checks if headers indicate credentialed request.

    This is done only by inspecting header fields so it does not takes SSL
    client certificate authentication into account. The argument may be either
    headers dictionary-like object or a sequence of headers field names.

    :param headers: header fields
    :type headers: Union[Mapping[str, Any], Sequence[str]]
    :return: flag indicating credentialed status
    :rtype: bool
    """
    return 'Cookie' in headers or 'Authorization' in headers
