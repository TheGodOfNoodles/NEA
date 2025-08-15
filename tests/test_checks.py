import pytest
from config import CONFIG
from crawler import PageData, FormInfo, FormField
from scanner.checks.xss_check import XSSCheck
from scanner.checks.sqli_check import SQLiCheck
from scanner.checks.open_redirect_check import OpenRedirectCheck
from scanner.checks.dir_traversal_check import DirectoryTraversalCheck
from scanner.checks.csrf_check import CSRFCheck
from scanner.checks.cookie_check import CookieSecurityCheck
from scanner.checks.headers_check import HeaderCheck
from scanner.checks.info_disclosure_check import InfoDisclosureCheck
from scanner.checks.dom_xss_check import DOMXSSCheck

# Reuse fake_http fixture from conftest


def assert_enriched(f):
    assert f.description, f"Missing description for {f.issue}"
    assert f.recommendation, f"Missing recommendation for {f.issue}"
    assert f.references, f"Missing references for {f.issue}"


def test_xss_check_query(fake_http):
    page = PageData(url="http://test.local/app?name=abc")
    findings = XSSCheck().scan(fake_http, page, config=CONFIG)
    assert findings, "Expected XSS finding"
    f = findings[0]
    assert f.parameter == 'name'
    assert 'script' in f.payload.lower() or 'svg' in f.payload.lower()
    assert_enriched(f)


def test_sqli_check_error_based(fake_http):
    page = PageData(url="http://test.local/app?item=1")
    findings = SQLiCheck().scan(fake_http, page, config=CONFIG)
    assert any('SQL Injection' in f.issue for f in findings)
    f = findings[0]
    assert f.parameter == 'item'
    assert_enriched(f)


def test_open_redirect(fake_http):
    page = PageData(url="http://test.local/login?redirect=/home")
    findings = OpenRedirectCheck().scan(fake_http, page, config=CONFIG)
    # Will only detect if server echoes redirect; our fake sets header on test payload
    assert findings, "Expected open redirect finding"
    f = findings[0]
    assert f.parameter.lower() == 'redirect'
    assert_enriched(f)


def test_dir_traversal(fake_http):
    page = PageData(url="http://test.local/download?file=note.txt")
    findings = DirectoryTraversalCheck().scan(fake_http, page, config=CONFIG)
    assert findings, "Expected traversal finding"
    f = findings[0]
    assert f.parameter == 'file'
    assert '../' in f.payload or 'win.ini' in f.payload
    assert_enriched(f)


def test_csrf(fake_http):
    form = FormInfo(action='http://test.local/post', method='post', inputs=[FormField(name='username', field_type='text')])
    page = PageData(url='http://test.local/form', forms=[form])
    findings = CSRFCheck().scan(fake_http, page, config=CONFIG)
    assert findings, "Expected CSRF finding"
    assert_enriched(findings[0])


def test_cookie_security():
    page = PageData(url='https://test.local/home')
    page.raw_set_cookies = ['SESSIONID=abc123; Path=/']  # missing security attrs
    findings = CookieSecurityCheck().scan(None, page, config=CONFIG)  # http client unused
    assert findings, "Expected cookie attr finding"
    f = findings[0]
    assert f.parameter == 'SESSIONID'
    assert_enriched(f)


def test_headers_check():
    # Provide minimal header so scanner evaluates missing ones
    page = PageData(url='https://test.local/home', headers={'content-type': 'text/html'})
    findings = HeaderCheck().scan(None, page, config=CONFIG)
    assert findings, "Expected header findings"
    for f in findings:
        assert_enriched(f)


def test_info_disclosure():
    # 16 char key after AKIA to match pattern AKIA[0-9A-Z]{16}
    body = 'const KEY = "AKIA1234567890ABCDEF"; // secret'  # 10 digits + 6 letters = 16
    page = PageData(url='http://test.local/', body=body)
    findings = InfoDisclosureCheck().scan(None, page, config=CONFIG)
    assert findings, "Expected info disclosure finding"
    assert_enriched(findings[0])


def test_dom_xss():
    body = '<script>document.write(location.hash)</script>'
    page = PageData(url='http://test.local/#x', body=body)
    findings = DOMXSSCheck().scan(None, page, config=CONFIG)
    assert findings, "Expected DOM XSS finding"
    assert_enriched(findings[0])
