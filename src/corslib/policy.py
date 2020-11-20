import fnmatch
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence


@dataclass
class OriginRule:
    rule: str
    kind: Optional[str] = None

    def allow_origin(self, request_origin: str) -> str:
        kind = self.kind.lower()
        if self.kind is None or kind.lower() in ['str', 'string']:
            return self.rule
        if kind == 'path' and fnmatch.fnmatch(request_origin, self.rule):
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


class DefaultAllowAllPolicy(Policy):

    def __init__(self):
        super().__init__(name='DefaultAllowAll')
