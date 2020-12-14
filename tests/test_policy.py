import pytest

from corslib.policy import OriginRule, RuleKind


def test_origin_rule_default_create():
    r = OriginRule(rule='*')
    assert r.kind == RuleKind.STR


@pytest.mark.parametrize('allow', ['*', 'test.somewhere.net'], ids=['all', 'host'])
def test_origin_rule_str_allow(allow):
    r = OriginRule(rule=allow)
    assert r.allow_origin('dummy.net') == r.rule
