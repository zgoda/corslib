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
    with pytest.raises(PolicyError):
        Policy(name='policy1', allow_credentials=True, allow_origin=origin)
