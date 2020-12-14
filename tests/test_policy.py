import pytest

from corslib.policy import OriginRule, RuleKind


def test_origin_rule_default_create():
    """Verify that default rule kind is ``str``.
    """
    r = OriginRule(rule='*')
    assert r.kind == RuleKind.STR


@pytest.mark.parametrize('allow', ['*', 'test.somewhere.net'], ids=['all', 'host'])
def test_origin_rule_str(allow):
    """Verify that ``str`` kind of rule allows only defined spec.
    """
    r = OriginRule(rule=allow)
    assert r.allow_origin('dummy.net') == r.rule


@pytest.mark.parametrize('allow', [
    '*.somewhere.net', 'test?.somewhere.net',
    'test[1234].somewhere.net', 'test[!56].somewhere.net',
], ids=['multichar', 'singlechar', 'range-incl', 'range-excl'])
def test_origin_rule_path_allow(allow):
    r = OriginRule(rule=allow, kind=RuleKind.PATH)
    for hostname in ['test1', 'test2', 'test3', 'test4']:
        req_allow = f'{hostname}.somewhere.net'
        assert r.allow_origin(req_allow) == req_allow
