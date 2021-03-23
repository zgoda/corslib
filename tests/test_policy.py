from corslib.policy import Policy


def test_default_create():
    p = Policy(name='policy1')
    assert p.allow_credentials is False
    assert not any(
        [p.allow_origin, p.allow_headers, p.allow_methods, p.expose_headers, p.max_age]
    )
