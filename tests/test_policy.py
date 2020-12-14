from corslib.policy import OriginRule, RuleKind


def test_origin_rule_default_create():
    r = OriginRule(rule='*')
    assert r.kind == RuleKind.STR
