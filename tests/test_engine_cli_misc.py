import sys, os, importlib, json, logging
import pytest
from scanner.engine import VulnerabilityScanner
from crawler import PageData, FormInfo, FormField
from scanner.vulnerability import Finding
from config import reload_config, CONFIG
import logging_util

# Reuse fake_http fixture from conftest.py


def build_page():
    body = """
    <html><head><script>document.write(location.hash)</script></head>
    <body>AKIA1234567890ABCDEF <!-- potential secret -->
    </body></html>
    """.strip()
    forms = [FormInfo(action='http://test.local/post', method='post', inputs=[FormField(name='username', field_type='text')])]
    page = PageData(
        url='http://test.local/app?name=abc&item=1&redirect=/home&file=note.txt',
        headers={'content-type':'text/html'},
        body=body,
        forms=forms,
    )
    page.raw_set_cookies = ['SESSIONID=abc123; Path=/']
    return page


def test_engine_full_scan(fake_http):
    page = build_page()
    engine = VulnerabilityScanner(fake_http)
    findings = engine.scan_pages({'http://test.local/app?name=abc&item=1&redirect=/home&file=note.txt': page})
    assert findings, 'Expected findings produced'
    cats = {f.category for f in findings}
    expected = {'Cross-Site Scripting','SQL Injection','Open Redirect','Directory Traversal','CSRF','Cookies','Security Headers','Information Disclosure'}
    missing = expected - cats
    assert not missing, f'Missing categories: {missing}'
    # Dedup behavior: re-scan same pages should not duplicate
    count_before = len(engine.findings)
    engine.scan_pages({'http://test.local/app?name=abc&item=1&redirect=/home&file=note.txt': page})
    assert len(engine.findings) == count_before, 'Findings duplicated on second scan'


def test_config_environment_overrides(monkeypatch):
    monkeypatch.setenv('SCANNER_REQUEST_TIMEOUT','3')
    monkeypatch.setenv('SCANNER_CRAWL_DELAY','0.2')
    monkeypatch.setenv('SCANNER_INCLUDE_RE','include')
    monkeypatch.setenv('SCANNER_EXCLUDE_RE','exclude')
    cfg = reload_config()
    assert cfg.REQUEST_TIMEOUT == 3 and abs(cfg.CRAWL_DELAY - 0.2) < 1e-6
    assert cfg.INCLUDE_RE == 'include' and cfg.EXCLUDE_RE == 'exclude'


def test_logging_idempotent_and_json(capsys):
    # Reset logging root state manually
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    if hasattr(root, '_nea_configured'):
        delattr(root, '_nea_configured')
    logging_util.configure_logging(level='INFO', json_mode=True)
    first_handlers = list(logging.getLogger().handlers)
    logging_util.configure_logging(level='DEBUG', json_mode=False)
    second_handlers = list(logging.getLogger().handlers)
    assert first_handlers == second_handlers, 'Logging reconfigured unexpectedly'
    logging.getLogger('test').error('Failure happened')
    out = capsys.readouterr().err.strip().splitlines()[-1]
    data = json.loads(out)
    assert data['level'] == 'ERROR' and 'Failure happened' in data['msg']


def test_main_cli_mode(monkeypatch):
    import main as main_mod
    called = {}
    def fake_run_cli():
        called['ran'] = True
        return 0
    monkeypatch.setenv('NEA_MODE','')
    monkeypatch.setenv('SCANNER_REQUEST_TIMEOUT','1')
    monkeypatch.setenv('SCANNER_CRAWL_DELAY','0')
    monkeypatch.setenv('SCANNER_INCLUDE_RE','')
    monkeypatch.setenv('SCANNER_EXCLUDE_RE','')
    monkeypatch.setenv('NEA_LOG_JSON','0')
    monkeypatch.setattr(main_mod, '_run_cli', fake_run_cli)
    monkeypatch.setattr(sys, 'argv', ['prog','--cli'])
    rc = main_mod.main()
    assert rc == 0 and called.get('ran')


def test_cli_list_and_version(monkeypatch, capsys):
    import cli as cli_mod
    # list checks
    rc = cli_mod.run_cli(['--list-checks'])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'xss' in out.lower() and 'sqli' in out.lower()
    # version
    rc = cli_mod.run_cli(['--version'])
    assert rc == 0
    out = capsys.readouterr().out
    assert CONFIG.VERSION in out


def test_cli_missing_url_error(monkeypatch):
    import cli as cli_mod
    with pytest.raises(SystemExit):
        cli_mod.run_cli([])


def test_cli_subset_checks(monkeypatch, capsys):
    import cli as cli_mod
    # Monkeypatch the Crawler used inside cli module (not crawler module)
    class DummyCrawler:
        def __init__(self, *a, **k): pass
        def crawl(self):
            return {'http://t/': PageData(url='http://t/', headers={'content-type':'text/html'}, body='<html></html>')}
    monkeypatch.setattr(cli_mod, 'Crawler', DummyCrawler)
    rc = cli_mod.run_cli(['--url','http://t/','--checks','headers'])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert 'report for http://t/' in out
    # Expect at least one header issue line
    assert 'x-content-type-options' in out or 'security headers' in out
