import pytest

from corslib.policy import OriginRule, Policy, PolicyError, RuleKind


def test_default_create():
    p = Policy(name='policy1')
    assert p.allow_credentials is False
    assert not any(
        [p.allow_origin, p.allow_headers, p.allow_methods, p.expose_headers, p.max_age]
    )


def test_allow_credentials_setup_valid():
    p = Policy(
        name='policy1',
        allow_credentials=True, allow_origin=[OriginRule(rule='website.com')],
    )
    assert p


@pytest.mark.parametrize(
    'origin', [None, [OriginRule(rule='*')]], ids=['empty', 'star']
)
def test_allow_credentials_setup_invalid_empty_origin(origin):
    with pytest.raises(PolicyError, match='policy not allowed'):
        Policy(name='policy1', allow_credentials=True, allow_origin=origin)


@pytest.mark.parametrize(
    'origin', ['', None], ids=['empty-str', 'none']
)
def test_preflight_headers_empty_origin(origin):
    policy = Policy(name='policy1')
    rv = policy.preflight_response_headers(origin)
    assert rv == {}


def test_preflight_headers_null_origin_loose():
    policy = Policy(name='policy1')
    rv = policy.preflight_response_headers('null')
    assert '*' in rv.values()


def test_preflight_headers_null_origin_strict():
    policy = Policy(name='policy1')
    rv = policy.preflight_response_headers('null', strict=True)
    assert rv == {}


def test_preflight_headers_no_max_age():
    policy = Policy(name='policy1')
    rv = policy.preflight_response_headers('http://website.com')
    assert Policy.ACCESS_CONTROL_MAX_AGE not in rv


def test_preflight_headers_max_age():
    max_age = 60 * 60
    policy = Policy(name='policy1', max_age=max_age)
    rv = policy.preflight_response_headers('http://website.com')
    assert rv[Policy.ACCESS_CONTROL_MAX_AGE] == max_age


@pytest.mark.parametrize(
    'rule',
    [
        OriginRule(rule='http://my.website.com'),
        OriginRule(rule='http://??.website.com', kind=RuleKind.PATH),
        OriginRule(rule=r'^http://\S{2}\.website\.com$', kind=RuleKind.REGEX)
    ],
    ids=['str', 'path', 'regex']
)
def test_preflight_headers_allow_credentials(rule):
    policy = Policy(name='policy1', allow_credentials=True, allow_origin=[rule])
    rv = policy.preflight_response_headers(
        'http://my.website.com', request_credentials=True
    )
    assert rv[Policy.ACCESS_CONTROL_ALLOW_CREDENTIALS] == 'true'


def test_preflight_headers_disallow_credentials_no_request():
    policy = Policy(
        name='policy1', allow_credentials=True,
        allow_origin=[OriginRule(rule='http://website.com')],
    )
    rv = policy.preflight_response_headers('http://website.com')
    assert Policy.ACCESS_CONTROL_ALLOW_CREDENTIALS not in rv
