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


@pytest.mark.parametrize('test', ['test1', 'test1.test'], ids=['single', 'multiple'])
def test_origin_rule_path_allow_star(test):
    domain = 'website.com'
    r = OriginRule(rule=f'*.{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


def test_origin_rule_path_disallow_star():
    r = OriginRule(rule='*.website.com', kind=RuleKind.PATH)
    req_allow = 'website.com'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['test1', 'testy'], ids=['num', 'alpha'])
def test_origin_rule_path_allow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test?.{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['test11', 'test'], ids=['more', 'none'])
def test_origin_rule_path_disallow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test?.{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['testy', 'test1'], ids=['alpha', 'num'])
def test_origin_rule_path_allow_range_incl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test[1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['testa', 'test2'], ids=['alpha', 'num'])
def test_origin_rule_path_disallow_range_incl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test[1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['testa', 'test2'], ids=['alpha', 'num'])
def test_origin_rule_path_allow_range_excl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test[!1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['testy', 'test1'], ids=['alpha', 'num'])
def test_origin_rule_path_disallow_range_excl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'test[!1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) is None
