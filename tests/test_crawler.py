import types
from crawler import Crawler, PageData
from http_client import HTTPClient

class FakeResp:
    def __init__(self, text='', headers=None, cookies=None):
        self.text = text
        self.status_code = 200
        self.headers = headers or {}
        # raw headers with get_all('Set-Cookie') support
        self.raw = types.SimpleNamespace(headers=types.SimpleNamespace(get_all=lambda name: (cookies if name.lower()=='set-cookie' else [])))

class FakeHTTP(HTTPClient):  # reuse metrics logic but override session.request indirectly by get()
    def __init__(self, pages):
        super().__init__()
        self._pages = pages
    def get(self, url, params=None, allow_redirects=True):
        # match without params
        key = url.split('#')[0]
        data = self._pages.get(key)
        if not data:
            return FakeResp('NF', headers={'content-type':'text/html'}), 0.01, None
        return data, 0.01, None


def build_site():
    root_html = """
    <html><body>
      <a href='/page2'>Go2</a>
      <a href='http://external.test/out'>Out</a>
      <form action='/submit' method='post'>
        <input name='user'/><textarea name='comment'></textarea>
      </form>
    </body></html>
    """
    page2_html = "<html><body><p>Page2</p></body></html>"
    pages = {
        'http://example.test': FakeResp(root_html, headers={'Content-Type':'text/html','Set-Cookie':'ID=1; Path=/'}, cookies=['SESS=abc; Path=/','PREF=1; HttpOnly']),
        'http://example.test/page2': FakeResp(page2_html, headers={'Content-Type':'text/html'})
    }
    return pages


def test_crawler_discovers_links_and_forms():
    pages = build_site()
    http = FakeHTTP(pages)
    c = Crawler('http://example.test', max_depth=3, http_client=http)
    result = c.crawl()
    assert 'http://example.test' in result and 'http://example.test/page2' in result
    root = result['http://example.test']
    assert any(f.action.endswith('/submit') for f in root.forms)
    assert any(l.endswith('/page2') for l in root.links)
    # external link not included
    assert all('external.test' not in l for l in root.links)
    # cookies captured
    assert root.raw_set_cookies and len(root.raw_set_cookies) == 2


def test_crawler_scope_and_depth():
    pages = build_site()
    http = FakeHTTP(pages)
    c = Crawler('http://example.test', max_depth=0, http_client=http)
    result = c.crawl()
    # only base page due to depth 0
    assert list(result.keys()) == ['http://example.test']
    assert c.in_scope('http://example.test/anything')
    assert not c.in_scope('http://other.test/')

