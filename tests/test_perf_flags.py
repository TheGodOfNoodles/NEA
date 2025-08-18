import os, types
from config import reload_config
from crawler import Crawler, PageData
from http_client import HTTPClient
from scanner.engine import VulnerabilityScanner

class FakeResp:
    def __init__(self, text, url='http://flags.test/'):
        self.text = text
        self.status_code = 200
        self.headers = {'Content-Type':'text/html'}
        self.history = []
        self.raw = types.SimpleNamespace(headers=types.SimpleNamespace(get_all=lambda name: []))
        self.url = url

class FlagHTTP(HTTPClient):
    def __init__(self, pages):
        super().__init__()
        self._pages = pages
    def get(self, url, params=None, allow_redirects=True):  # pragma: no cover - simple mapping
        key = url.split('#')[0]
        return self._pages.get(key), 0.001, None

HTML = """
<html><body>
<script>fetch('/api/data');var x='/api/other';</script>
<img src='/img/a.png'><img src='/img/b.png'>
<link rel='stylesheet' href='/css/app.css'>
<a href='/next'>Next</a>
</body></html>
""".strip()
PAGES = {
    'http://flags.test': FakeResp(HTML, 'http://flags.test'),
    'http://flags.test/next': FakeResp('<html><body>Leaf</body></html>', 'http://flags.test/next')
}

# ---------------- Skip flags -----------------

def test_skip_assets_and_js(monkeypatch):
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    monkeypatch.setenv('SCANNER_SKIP_ASSETS','1')
    monkeypatch.setenv('SCANNER_SKIP_JS_ENDPOINTS','1')
    reload_config()
    http = FlagHTTP(PAGES)
    c = Crawler('http://flags.test', max_depth=1, http_client=http)
    pages = c.crawl()
    root = pages['http://flags.test']
    assert not root.discovered_assets, 'Assets should be skipped'
    assert not root.js_endpoints, 'JS endpoints should be skipped'

# ---------------- Pipeline scan -----------------

class VulnHTTP(HTTPClient):
    def __init__(self, html):
        super().__init__()
        self._html = html
    def get(self, url, params=None, allow_redirects=True):  # pragma: no cover
        return FakeResp(self._html, url), 0.001, None

PIPE_HTML = """
<html><body>
<script>document.write(location.hash)</script>
<!-- AKIA1234567890ABCDEFG -->
<form action='/login' method='post'><input name='u'></form>
</body></html>
""".strip()

def test_pipeline_scan(monkeypatch):
    monkeypatch.setenv('SCANNER_PIPELINE_SCAN','1')
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    reload_config()
    http = VulnHTTP(PIPE_HTML)
    scanner = VulnerabilityScanner(http)
    c = Crawler('http://pipe.test', max_depth=0, http_client=http, scanner=scanner)
    pages = c.crawl()
    # Pipeline should have scanned page already
    initial_count = len(scanner.findings)
    assert initial_count > 0, 'Pipeline scanning produced no findings'
    # Re-running batch scan should not duplicate
    scanner.scan_pages(pages)
    assert len(scanner.findings) == initial_count, 'Duplicate findings added after second scan'

