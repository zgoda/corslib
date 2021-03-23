import re
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatch
from typing import ClassVar, List, Mapping, Optional, Sequence, Union


class PolicyError(ValueError):
    pass


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
    allow_origin: Optional[Sequence[OriginRule]] = None
    allow_headers: Optional[Sequence[str]] = None
    allow_methods: Optional[Sequence[str]] = None
    expose_headers: Optional[Sequence[str]] = None
    max_age: Optional[int] = None

    ACCESS_CONTROL_ALLOW_ORIGIN: ClassVar[str] = 'Access-Control-Allow-Origin'
    ACCESS_CONTROL_ALLOW_CREDENTIALS: ClassVar[str] = 'Access-Control-Allow-Credentials'

    def __post_init__(self):
        if self.allow_credentials:
            allow_any = (
                not self.allow_origin or
                any(r.rule == '*' for r in self.allow_origin if r.kind == RuleKind.STR)
            )
            if allow_any:
                raise PolicyError('Open policy not allowed for credentialed requests')

    def preflight_response_headers(
                self, origin: str, request_credentials: bool = False,
            ) -> Mapping[str, Union[str, int, List[str]]]:
        """Generate preflight response headers.

        This method takes request headers as any mapping compatible structure.
        Since only Origin is being read from request and it's single-value, the
        structure may be any object that implements basic mapping protocol.

        Returned value is also generic dict. If multiple values are returned
        for any key, they are returned as list so the result needs to be
        adapted to framework/library specific implementation of HTTP headers
        structure.

        :param origin: value of the Origin request header
        :type origin: str
        :param request_credentials: indicates response to credentialed
                                    request, defaults to False
        :type request_credentials: bool, optional
        :return: generated header values as Python dict
        :rtype: Mapping[str, Union[str, int, List[str]]]
        """
        resp_headers = {}
        resp_headers.update(self.access_control_allow_origin(origin))
        if self.allow_headers:
            resp_headers['Access-Control-Allow-Headers'] = ', '.join(self.allow_headers)
        if self.allow_methods:
            resp_headers['Access-Control-Allow-Methods'] = ', '.join(self.allow_methods)
        resp_headers.update(
            self.access_control_allow_credentials(
                request_credentials, resp_headers[self.ACCESS_CONTROL_ALLOW_ORIGIN]
            )
        )
        if self.allow_credentials or request_credentials:
            if resp_headers[self.ACCESS_CONTROL_ALLOW_ORIGIN] != '*':
                resp_headers[self.ACCESS_CONTROL_ALLOW_CREDENTIALS] = 'true'
        if self.max_age:
            resp_headers['Access-Control-Max-Age'] = self.max_age
        return resp_headers

    def response_headers(
                self, origin: str, request_credentials: bool = False
            ) -> Mapping[str, str]:
        """Generate regular response headers.

        :param origin: value of the Origin request header
        :type origin: str
        :param request_credentials: indicates response to credentialed
                                    request, defaults to False
        :type request_credentials: bool, optional
        :return: generated header values as Python dict
        :rtype: Mapping[str, str]
        """
        resp_headers = {}
        resp_headers.update(self.access_control_allow_origin(origin))
        resp_headers.update(
            self.access_control_allow_credentials(
                request_credentials, resp_headers[self.ACCESS_CONTROL_ALLOW_ORIGIN]
            )
        )
        return resp_headers

    def access_control_allow_credentials(
                self, request_credentials: bool, allow_origin: str
            ) -> Mapping[str, str]:
        """Generate Access-Control-Allow-Credentials header entry.

        If request is to be denied then this method returns empty dict.

        :param request_credentials: indicates response to credentialed request
        :type request_credentials: bool
        :param allow_origin: calculated allowed origin
        :type allow_origin: str
        :return: Access-Control-Allow-Credentials header entry or empty dict
        :rtype: Mapping[str, str]
        """
        if self.allow_credentials or request_credentials:
            if allow_origin != '*':
                return {self.ACCESS_CONTROL_ALLOW_CREDENTIALS: 'true'}
        return {}

    def access_control_allow_origin(self, origin: str) -> Mapping[str, str]:
        """Generate Access-Control-Allow-Origin header entry.

        Additionally if value is not ``*`` then ``Vary`` header value is
        generated.

        :param origin: value of the Origin header
        :type origin: str
        :return: Access-Control-Allow-Origin header entry, and optionally also
                 Vary header entry
        :rtype: Mapping[str, str]
        """
        if self.allow_origin:
            headers = {}
            for rule in self.allow_origin:
                allow_origin = rule.allow_origin(origin)
                if origin == allow_origin:
                    headers[self.ACCESS_CONTROL_ALLOW_ORIGIN] = allow_origin
                    if allow_origin != '*':
                        headers['Vary'] = 'Origin'
                    break
            return headers
        return {self.ACCESS_CONTROL_ALLOW_ORIGIN: '*'}
