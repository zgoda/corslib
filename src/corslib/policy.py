import fnmatch
import re
from dataclasses import dataclass
from typing import ClassVar, List, Mapping, Optional, Sequence


@dataclass
class OriginRule:
    """A rule for origin check.

    Rule consists of string representing rule and kind. Supported kinds of
    rules are ``str``, ``path`` and ``regex``. This allows for describing a
    wide range of rules.

    * ``str`` kind of rule should be used if the rule describes exact host name
      or allows all hosts (``*``)
    * ``path`` kind uses filename pattern matching provided by :mod:`fnmatch`,
      this is fastest non-exact matching method
    * ``regex`` allows matching against arbitrary regular expressions supported
      by Python :mod:`re` module

    Matching is done in :meth:`~corslib.policy.OriginRule.allow_origin` method
    that matches origin specification from HTTP request against rule using
    appropriate procedure.
    """

    rule: str
    kind: str = 'str'

    ALLOWED_KINDS: ClassVar[List[str]] = [
        'str', 'path', 'regex'
    ]

    def __post_init__(self):
        self.kind = self.kind.lower()
        if self.kind not in self.ALLOWED_KINDS:
            raise ValueError(
                f'Unknown kind {self.kind}, allowed kinds: {self.ALLOWED_KINDS}'
            )

    def allow_origin(self, request_origin: str) -> Optional[str]:
        """Match origin spec from request against rule.

        The matching is done using method specified in :attr:`kind`. If
        :attr:`kind` is ``str`` then rule value is returned, otherwise the
        spec from request (if matches) or None (if not).

        :param request_origin: origin spec from request
        :type request_origin: str
        :return: allowed origin spec or None
        :rtype: Optional[str]
        """
        if self.kind == 'str':
            return self.rule
        if self.kind == 'path' and fnmatch.fnmatch(request_origin, self.rule):
            return request_origin
        if re.match(self.rule, request_origin):
            return request_origin


@dataclass
class Policy:
    name: str
    allow_credentials: bool = False
    alow_origin: Optional[Sequence[OriginRule]] = None
    allow_headers: Optional[Sequence[str]] = None
    allow_methods: Optional[Sequence[str]] = None
    expose_headers: Optional[Sequence[str]] = None
    max_age: Optional[int] = None

    def __post_init__(self):
        self._preflight_sent = False
        self._preflight_headers = None

    def preflight_response_headers(
                self, request_headers: Mapping[str, str]
            ) -> Mapping[str, str]:
        if self._preflight_sent:
            return self._preflight_headers
        resp_headers = {}
        req_origin = request_headers['Origin']
        if self.allow_origin:
            for rule in self.allow_origin:
                if req_origin == rule.allow_origin(req_origin):
                    resp_headers['Access-Control-Allow-Origin'] = req_origin
                    resp_headers['Vary'] = 'Origin'
                    break
        else:
            resp_headers['Access-Control-Allow-Origin'] = '*'
        if self.allow_headers:
            resp_headers['Access-Control-Allow-Headers'] = ', '.join(self.allow_headers)
        if self.allow_methods:
            resp_headers['Access-Control-Allow-Methods'] = ', '.join(self.allow_methods)
        if self.allow_credentials:
            resp_headers['Access-Control-Allow-Credentials'] = 'true'
        if self.max_age:
            resp_headers['Access-Control-Max-Age'] = self.max_age
        self._preflight_sent = True
        self._preflight_headers = resp_headers
        return resp_headers
