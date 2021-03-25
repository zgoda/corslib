import pytest
from corslib.policy import Policy, OriginRule, PolicyError


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
