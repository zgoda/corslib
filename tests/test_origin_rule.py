import pytest

from corslib.policy import OriginRule, RuleKind


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
