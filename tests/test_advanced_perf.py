import time, threading, types, os
import pytest
from config import reload_config, CONFIG
from crawler import Crawler, PageData
from http_client import HTTPClient
from scanner.engine import VulnerabilityScanner
from scanner.vulnerability import Finding

# Reuse minimal FakeResp similar to other tests
class FakeResp:
    def __init__(self, text='', headers=None):
        self.text = text
        self.status_code = 200
        self.headers = headers or {'Content-Type':'text/html'}
        self.history = []
        self.raw = types.SimpleNamespace(headers=types.SimpleNamespace(get_all=lambda name: []))
        self.url = 'http://example.test/'

# ---------------- Concurrency Crawl Test -----------------
class ConcurrencyHTTP(HTTPClient):
    def __init__(self, pages):
        super().__init__()
        self._pages = pages
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()
    def get(self, url, params=None, allow_redirects=True):  # pragma: no cover - timing based
        with self._lock:
            self.active += 1
            if self.active > self.max_active:
                self.max_active = self.active
        # Simulate network delay to allow overlap
        time.sleep(0.02)
        key = url.split('#')[0]
        resp = self._pages.get(key) or FakeResp('<html></html>')
        with self._lock:
            self.active -= 1
        return resp, 0.02, None


def build_concurrent_site(n=8):
    # root links to /p1.. /pn
    links = ''.join(f"<a href='/p{i}'>p{i}</a>" for i in range(1, n+1))
    root_html = f"<html><body>{links}</body></html>"
    pages = { 'http://example.test': FakeResp(root_html) }
    for i in range(1, n+1):
        pages[f'http://example.test/p{i}'] = FakeResp(f"<html><body>Page {i}</body></html>")
    return pages


def test_crawler_concurrency(monkeypatch):
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','4')
    reload_config()
    pages = build_concurrent_site(10)
    http = ConcurrencyHTTP(pages)
    c = Crawler('http://example.test', max_depth=1, http_client=http)
    result = c.crawl()
    # Expect root + 10 pages
    assert len(result) == 11
    # Confirm concurrency actually happened
    assert http.max_active > 1, f"Expected concurrent fetches, saw max_active={http.max_active}"

# ---------------- Body Truncation Test -----------------
class BodyHTTP(HTTPClient):
    def __init__(self, body):
        super().__init__()
        self._body = body
    def get(self, url, params=None, allow_redirects=True):
        return FakeResp(self._body), 0.001, None


def test_body_truncation(monkeypatch):
    large_body = '<html><body>' + 'A'*5000 + '</body></html>'
    monkeypatch.setenv('SCANNER_MAX_BODY_SIZE','100')
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    reload_config()
    http = BodyHTTP(large_body)
    c = Crawler('http://trunc.test', max_depth=0, http_client=http)
    pages = c.crawl()
    pd = pages['http://trunc.test']
    assert len(pd.body) <= 100
    # remove limit and ensure bigger body stored
    monkeypatch.setenv('SCANNER_MAX_BODY_SIZE','')
    reload_config()
    http2 = BodyHTTP(large_body)
    c2 = Crawler('http://trunc2.test', max_depth=0, http_client=http2)
    pages2 = c2.crawl()
    assert len(pages2['http://trunc2.test'].body) > 100

# ---------------- Scan Concurrency Equivalence -----------------
class FixedSiteHTTP(HTTPClient):
    def __init__(self, html):
        super().__init__()
        self._html = html
    def get(self, url, params=None, allow_redirects=True):
        return FakeResp(self._html), 0.001, None


def run_scan_with_concurrency(concurrency):
    os.environ['SCANNER_SCAN_CONCURRENCY'] = str(concurrency)
    reload_config()
    html = """
    <html><head><script>document.write(location.hash)</script></head>
    <body>
    <form action='/login' method='post'><input name='user'><input name='pass'></form>
    <a href='/next'>Next</a>
    <!-- AWS key? AKIA1234567890ABCDEZ -->
    </body></html>
    """.strip()
    http = FixedSiteHTTP(html)
    # Build two pages to enlarge work
    c = Crawler('http://scan.example', max_depth=0, http_client=http)
    pages = c.crawl()
    # Duplicate second page entry artificially
    pages['http://scan.example/dup'] = PageData(url='http://scan.example/dup', headers={'content-type':'text/html'}, body=html)
    engine = VulnerabilityScanner(http)
    findings = engine.scan_pages(pages)
    # Return stable tuple set for comparison
    return {(f.issue, f.location, f.evidence) for f in findings}


def test_scan_concurrency_equivalence():
    f1 = run_scan_with_concurrency(1)
    f4 = run_scan_with_concurrency(4)
    assert f1 == f4
    assert len(f1) > 0

# ---------------- Retry jitter basic behavior (smoke) -----------------
class RetryHTTP(HTTPClient):
    def __init__(self, succeed_after=2):
        super().__init__()
        self.count = 0
        self.succeed_after = succeed_after
    def get(self, url, params=None, allow_redirects=True):
        self.count += 1
        if self.count <= self.succeed_after:
            # Simulate transient 500
            r = FakeResp('<html></html>', headers={'Content-Type':'text/html'})
            r.status_code = 500
            return r, 0.001, None
        return FakeResp('<html><body>Ok</body></html>'), 0.001, None


def test_retry_jitter(monkeypatch):
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    reload_config()
    http = RetryHTTP(succeed_after=2)
    c = Crawler('http://retry.test', max_depth=0, http_client=http, retries=3)
    pages = c.crawl()
    assert 'http://retry.test' in pages
    # Ensure multiple attempts occurred
    assert http.count >= 3  # initial + at least 2 retries

# ---------------- Additional Advanced Tests -----------------
import random, threading
from threading import Event

# Extended scan concurrency equivalence with more pages & random order

def run_big_scan(concurrency, n_pages=15):
    os.environ['SCANNER_SCAN_CONCURRENCY'] = str(concurrency)
    reload_config()
    # Build deterministic but shuffled set of PageData with an info disclosure pattern
    base_body = "Potential key AKIA1234567890ABCDZZ"  # pattern length >= required
    items = list(range(n_pages))
    random.Random(1234).shuffle(items)  # stable shuffle
    pages = {}
    for i in items:
        url = f"http://bigscan.example/p{i}"
        # Vary body slightly so evidence location changes a bit
        body = base_body + f"_{i}"
        pages[url] = PageData(url=url, headers={'content-type':'text/html'}, body=body)
    # Add a duplicate page content to test dedup (same evidence string on different location should remain distinct)
    dup_url = "http://bigscan.example/dup"
    pages[dup_url] = PageData(url=dup_url, headers={'content-type':'text/html'}, body=base_body + "_0")
    http = HTTPClient()
    engine = VulnerabilityScanner(http)
    findings = engine.scan_pages(pages)
    # Represent findings as tuple set
    return {(f.issue, f.location, f.evidence) for f in findings}


def test_scan_concurrency_equivalence_large():
    s1 = run_big_scan(1)
    s5 = run_big_scan(5)
    assert s1 == s5
    assert len(s1) >= 1

# Robots + include/exclude regex behavior
class RobotsHTTP(HTTPClient):
    def __init__(self, pages, robots_text):
        super().__init__()
        self._pages = pages
        self._robots = robots_text
    def get(self, url, params=None, allow_redirects=True):
        if url.endswith('/robots.txt'):
            return FakeResp(self._robots, headers={'Content-Type':'text/plain'}), 0.001, None
        key = url.split('#')[0]
        resp = self._pages.get(key)
        if not resp:
            resp = FakeResp('<html><body>NF</body></html>')
        return resp, 0.001, None


def test_robots_and_include_exclude(monkeypatch):
    # Disallow /private but allow /public; exclude pattern removes /public/exclude; include pattern allows public, private, or root
    robots = """User-agent: *\nDisallow: /private\n""".strip()
    root_html = "<a href='/private/area'>Secret</a><a href='/public/page'>Pub</a><a href='/public/exclude'>Excluded</a>"
    pages = {
        'http://robots.test': FakeResp(f"<html><body>{root_html}</body></html>", headers={'Content-Type':'text/html'}),
        'http://robots.test/private/area': FakeResp("<html><body>Should not parse <a href='/private/deeper'>Deep</a></body></html>", headers={'Content-Type':'text/html'}),
        'http://robots.test/public/page': FakeResp("<html><body>Public</body></html>", headers={'Content-Type':'text/html'}),
        'http://robots.test/public/exclude': FakeResp("<html><body>Excluded</body></html>", headers={'Content-Type':'text/html'})
    }
    monkeypatch.setenv('SCANNER_INCLUDE_RE','public|private|robots.test$')
    monkeypatch.setenv('SCANNER_EXCLUDE_RE','exclude')
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','2')
    reload_config()
    http = RobotsHTTP(pages, robots)
    c = Crawler('http://robots.test', max_depth=2, http_client=http, respect_robots=True)
    result = c.crawl()
    # Root, /public/page visited; private present but flagged skipped; exclude path not present
    assert 'http://robots.test' in result
    assert 'http://robots.test/public/page' in result
    assert 'http://robots.test/public/exclude' not in result
    priv = result.get('http://robots.test/private/area')
    assert priv is not None and priv.skipped_by_robots
    assert all('deeper' not in k for k in result.keys())

# Retry/backoff timing ranges
class AlwaysFailHTTP(HTTPClient):
    def __init__(self):
        super().__init__()
        self.count = 0
    def get(self, url, params=None, allow_redirects=True):
        self.count += 1
        r = FakeResp('<html></html>', headers={'Content-Type':'text/html'})
        r.status_code = 500
        return r, 0.0, None


def test_retry_backoff_sleep(monkeypatch):
    sleeps = []
    def fake_sleep(t):
        sleeps.append(t)
    monkeypatch.setattr(time, 'sleep', fake_sleep)
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    reload_config()
    http = AlwaysFailHTTP()
    c = Crawler('http://fail.test', max_depth=0, http_client=http, retries=2)
    c.crawl()  # will still record page but with failures
    # Attempts should be retries+1
    assert http.count == 3
    # Two sleep calls expected (between attempts)
    assert len(sleeps) == 2
    b0 = 0.25
    b1 = 0.5
    assert b0 <= sleeps[0] <= b0 * 1.3 + 1e-6
    assert b1 <= sleeps[1] <= b1 * 1.3 + 1e-6

# Stop event mid-crawl
class MultiPageHTTP(HTTPClient):
    def __init__(self, n):
        super().__init__()
        self._pages = {}
        links = ''.join(f"<a href='/p{i}'>p{i}</a>" for i in range(n))
        self._pages['http://stopcrawl.test'] = FakeResp(f"<html><body>{links}</body></html>", headers={'Content-Type':'text/html'})
        for i in range(n):
            self._pages[f'http://stopcrawl.test/p{i}'] = FakeResp("<html><body>Leaf</body></html>", headers={'Content-Type':'text/html'})
    def get(self, url, params=None, allow_redirects=True):
        return self._pages.get(url) or FakeResp('<html></html>'), 0.001, None


def test_crawl_stop_event(monkeypatch):
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','3')
    reload_config()
    stop_evt = Event()
    fetch_count = {'n':0}
    def pre_hook(url):
        fetch_count['n'] += 1
        if fetch_count['n'] == 3:
            stop_evt.set()
        return True
    http = MultiPageHTTP(20)
    c = Crawler('http://stopcrawl.test', max_depth=1, http_client=http, stop_event=stop_evt, pre_fetch_hook=pre_hook)
    pages = c.crawl()
    # Should not reach all 1 + 20 pages
    assert len(pages) < 21
    # Stop event should be set
    assert stop_evt.is_set()

# Stop event mid-scan

def test_scan_stop_event(monkeypatch):
    from scanner.checks.base_check import BaseCheck
    monkeypatch.setenv('SCANNER_SCAN_CONCURRENCY','1')
    reload_config()
    stop_evt = Event()
    processed = []
    counter = {'n':0}
    class StopCheck(BaseCheck):  # type: ignore
        name = "stopcheck"
        description = "Stop after two pages"
        def scan(self, http, page, **kwargs):
            processed.append(page.url)
            counter['n'] += 1
            time.sleep(0.005)  # slow down to allow stop event evaluation
            if counter['n'] == 2:
                stop_evt.set()
            return []
    # Build pages
    pages = {f"http://scanstop.example/p{i}": PageData(url=f"http://scanstop.example/p{i}", headers={'content-type':'text/html'}, body="Body") for i in range(8)}
    http = HTTPClient()
    engine = VulnerabilityScanner(http, stop_event=stop_evt, enabled_checks=['stopcheck'])
    engine.scan_pages(pages)
    # Should have processed fewer than all pages
    assert len(processed) < len(pages)
    assert stop_evt.is_set()

# Hook behaviors: pre_fetch skip, post_fetch exception isolation, link & form filters
class HookHTTP(HTTPClient):
    def __init__(self):
        super().__init__()
        self._pages = {
            'http://hooks.test': FakeResp("""<html><body>
                <a href='/keep'>Keep</a>
                <a href='/skip'>Skip</a>
                <a href='/pre_skip'>PreSkip</a>
                <form action='/form_skip' method='post'><input name='a'></form>
                <form action='/form_keep' method='post'><input name='b'></form>
            </body></html>""", headers={'Content-Type':'text/html'}),
            'http://hooks.test/keep': FakeResp("<html><body>Keep</body></html>", headers={'Content-Type':'text/html'}),
            'http://hooks.test/skip': FakeResp("<html><body>Skip</html>", headers={'Content-Type':'text/html'}),
            'http://hooks.test/pre_skip': FakeResp("<html><body>PreSkip</html>", headers={'Content-Type':'text/html'}),
            'http://hooks.test/form_keep': FakeResp("<html><body>Form Keep</body></html>", headers={'Content-Type':'text/html'}),
            'http://hooks.test/form_skip': FakeResp("<html><body>Form Skip</body></html>", headers={'Content-Type':'text/html'})
        }
    def get(self, url, params=None, allow_redirects=True):
        return self._pages.get(url) or FakeResp('<html></html>'), 0.001, None


def test_hooks_behavior(monkeypatch):
    monkeypatch.setenv('SCANNER_CRAWL_CONCURRENCY','1')
    reload_config()
    http = HookHTTP()
    skipped_urls = set()
    def pre_hook(url):
        if url.endswith('/pre_skip'):
            skipped_urls.add(url)
            return False
        return True
    post_called = {'count':0}
    def post_hook(page_data):
        post_called['count'] += 1
        if page_data.url.endswith('/keep'):
            raise RuntimeError('Ignore me')  # should be swallowed
    def link_filter(url):
        return not url.endswith('/skip')  # filter out /skip only
    def form_filter(form):
        return not form.action.endswith('/form_skip')
    c = Crawler('http://hooks.test', max_depth=1, http_client=http,
                pre_fetch_hook=pre_hook, post_fetch_hook=post_hook,
                link_filter_hook=link_filter, form_filter_hook=form_filter)
    pages = c.crawl()
    # link filter prevented /skip link
    root = pages['http://hooks.test']
    assert all(not l.endswith('/skip') for l in root.links)
    # pre_fetch skipped page not in pages keys
    assert all(not k.endswith('/pre_skip') for k in pages.keys())
    assert skipped_urls
    # form filter removed one form
    form_actions = {f.action for f in root.forms}
    assert any(a.endswith('/form_keep') for a in form_actions)
    assert all(not a.endswith('/form_skip') for a in form_actions)
    # post hook called for each fetched page
    assert post_called['count'] >= 2
