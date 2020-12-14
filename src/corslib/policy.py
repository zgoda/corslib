import re
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Mapping, Optional, Sequence, Union


class RuleKind(Enum):
    """Enumeration of supported rule kinds.

    * ``str`` kind of rule should be used if the rule describes exact host name
      or allows all hosts (``*``)
    * ``path`` kind uses filename pattern matching provided by :mod:`fnmatch`,
      this allows for example to match all subdomains (``*.mydomain.com``) or
      sets of specific hosts (``myapp-prod-??.mydomain.com``)
    * ``regex`` allows matching against arbitrary regular expressions supported
      by Python :mod:`re` module
    """
    STR = 'str'
    PATH = 'path'
    REGEX = 'regex'


@dataclass
class OriginRule:
    """A rule for origin check.

    Rule consists of string representing rule and kind (default is
    :attr:`~corslib.policy.RuleKind.STR`). Matching is done in
    :meth:`~corslib.policy.OriginRule.allow_origin` method
    that matches origin specification from HTTP request against rule using
    appropriate procedure for selected kind.

    :ivar rule: rule specification as string
    :vartype rule: str
    :ivar kind: kind of rule, determines matching against origin specification
                provided in request headers
    :vartype kind: RuleKind
    """

    rule: str
    kind: RuleKind = RuleKind.STR

    def allow_origin(self, request_origin: str) -> Optional[str]:
        """Match origin spec from request against rule.

        The matching is done using method specified in :attr:`kind`. If
        :attr:`kind` is :attr:`~corslib.policy.RuleKind.STR` then rule value is
        returned. In any other case returned is the spec from request (if
        matches) or None (if not).

        :param request_origin: origin spec from request
        :type request_origin: str
        :return: allowed origin spec or None
        :rtype: Optional[str]
        """
        if self.kind == RuleKind.STR:
            return self.rule
        if self.kind == RuleKind.PATH and fnmatch(request_origin, self.rule):
            return request_origin
        if self.kind == RuleKind.REGEX and re.match(self.rule, request_origin):
            return request_origin


@dataclass
class Policy:
    """Policy to be applied to incoming requests.

    All arguments except name are optional. The default behaviour is to allow
    all traffic from 3rd party but limited to "web safe" parameters (methods,
    headers, credentials).

    :ivar name: name of the rule
    :vartype name: str
    :ivar allow_credentials: allow credentialed requests, default is to not
                             allow
    :vartype allow_credentials: bool
    :ivar allow_origin: optional sequence of OriginRule objects that will be
                        checked to match client-provided origin in request
                        headers
    :vartype allow_origin: Optional[Sequence[OriginRule]]
    :ivar allow_headers: optional sequence of allowed HTTP request headers
    :vartype allow_headers: Optional[Sequence[str]]
    :ivar allow_methods: optional sequence of allowed HTTP methods
    :vartype allow_methods: Optional[Sequence[str]]
    :ivar expose_headers: optional sequence of HTTP headers that may be
                          accessed in client code
    :vartype expose_headers: Optional[Sequence[str]]
    :ivar max_age: optional number of seconds that response may be cached by
                   client
    :vartype max_age: Optional[int]
    """

    name: str
    allow_credentials: bool = False
    alow_origin: Optional[Sequence[OriginRule]] = None
    allow_headers: Optional[Sequence[str]] = None
    allow_methods: Optional[Sequence[str]] = None
    expose_headers: Optional[Sequence[str]] = None
    max_age: Optional[int] = None

    _preflight_sent: bool = field(default=False, init=False, repr=False)
    _preflight_headers: Mapping[str, Union[str, int]] = field(
        default=None, init=False, repr=False
    )

    def preflight_response_headers(
                self, request_headers: Mapping[str, Union[str, int]]
            ) -> Mapping[str, Union[str, int]]:
        """Generate preflight response headers.

        This method takes request headers as any mapping compatible structure.
        Since only Origin is being read from request and it's single-value, the
        structure may be any object that implements basic mapping protocol.

        Returned value is also generic dict. If multiple values are returned
        for any key, they are returned as list so the result needs to be
        adapted to framework/library specific implementation of HTTP headers
        structure.

        :param request_headers: headers from preflight requests
        :type request_headers: Mapping[str, Union[str, int]]
        :return: generated headers values as Python dict
        :rtype: Mapping[str, Union[str, int]]
        """
        if self._preflight_sent:
            return self._preflight_headers
        resp_headers = {}
        req_origin = request_headers['Origin']
        if self.allow_origin:
            for rule in self.allow_origin:
                allow_origin = rule.allow_origin(req_origin)
                if req_origin == allow_origin:
                    resp_headers['Access-Control-Allow-Origin'] = allow_origin
                    if allow_origin != '*':
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
