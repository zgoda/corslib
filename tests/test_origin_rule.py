import pytest

from corslib.policy import OriginRule, RuleKind, InsecureRule


def test_default_create():
    r = OriginRule(rule='*')
    assert r.kind == RuleKind.STR


@pytest.mark.parametrize(
    'allow', ['*', 'http://test.somewhere.net'], ids=['all', 'host']
)
def test_str(allow):
    r = OriginRule(rule=allow)
    assert r.allow_origin('dummy.net') == r.rule


@pytest.mark.parametrize('test', ['test1', 'test1.test'], ids=['single', 'multiple'])
def test_path_allow_star(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://*.{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize(
    'test', ['http://website.com', 'http://www.othersite.com'], ids=['bare', 'other']
)
def test_path_disallow_star(test):
    r = OriginRule(rule='http://*.website.com', kind=RuleKind.PATH)
    assert r.allow_origin(test) is None


@pytest.mark.parametrize('test', ['test1', 'testy'], ids=['num', 'alpha'])
def test_path_allow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test?.{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['test11', 'test'], ids=['more', 'none'])
def test_path_disallow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test?.{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['testy', 'test1'], ids=['alpha', 'num'])
def test_path_allow_range_incl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test[1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['testa', 'test2'], ids=['alpha', 'num'])
def test_path_disallow_range_incl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test[1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['testa', 'test2'], ids=['alpha', 'num'])
def test_path_allow_range_excl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test[!1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'http://{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['testy', 'test1'], ids=['alpha', 'num'])
def test_path_disallow_range_excl(test):
    domain = 'website.com'
    r = OriginRule(rule=f'http://test[!1y].{domain}', kind=RuleKind.PATH)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) is None


@pytest.mark.parametrize('test', ['testa', 'test1'], ids=['alpha', 'num'])
def test_regex_allow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=r'^test\S\.website\.com$', kind=RuleKind.REGEX)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) == req_allow


@pytest.mark.parametrize('test', ['testaa', 'test12'], ids=['alpha', 'num'])
def test_regex_disallow_singlechar(test):
    domain = 'website.com'
    r = OriginRule(rule=r'^test\S\.website\.com$', kind=RuleKind.REGEX)
    req_allow = f'{test}.{domain}'
    assert r.allow_origin(req_allow) is None


def test_null_str_allowed():
    r = OriginRule(rule='null', kind=RuleKind.STR)
    req_allow = 'null'
    assert r.allow_origin(req_allow) == req_allow


def test_null_path_not_allowed():
    r = OriginRule(rule='null', kind=RuleKind.PATH)
    req_allow = 'null'
    assert r.allow_origin(req_allow) is None


def test_null_regex_not_allowed():
    r = OriginRule(rule='^null$', kind=RuleKind.REGEX)
    req_allow = 'null'
    assert r.allow_origin(req_allow) is None



@pytest.mark.parametrize(
    'rule',
    [r'website.com', r'^website.com', r'website.com$'],
    ids=['none', 'missing-end', 'missing-beginning'],
)
def test_invalid_regex_rule_partial_regex(rule):
    with pytest.raises(InsecureRule, match='partial match regex') as e:
        OriginRule(rule=rule, kind=RuleKind.REGEX)
    assert e.value.rule == rule


@pytest.mark.parametrize(
    'rule',
    [r'^.*\.website\.com$', r'^http://www\..*site\com$', r'^http://some\.site\..*$'],
    ids=['beginning', 'middle', 'end'],
)
def test_invalid_regex_rule_too_broad(rule):
    with pytest.raises(InsecureRule, match='too broad') as e:
        OriginRule(rule=rule, kind=RuleKind.REGEX)
    assert e.value.rule == rule


@pytest.mark.parametrize(
    'rule', ['*.site.com', 'http://site.*'], ids=['beginning', 'end']
)
def test_invalid_path_rule_open_ended(rule):
    with pytest.raises(InsecureRule, match='open ended') as e:
        OriginRule(rule=rule, kind=RuleKind.PATH)
    assert e.value.rule == rule
