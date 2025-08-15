import sys, pathlib
# Ensure project root (parent of tests) is on sys.path
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import urllib.parse as _u
import types
import time
import pytest

class FakeRawHeaders:
    def __init__(self, cookies=None):
        self._cookies = cookies or []
    def get_all(self, name):  # mimic requests internal raw.headers.get_all
        if name.lower() == 'set-cookie':
            return self._cookies
        return []

class FakeResponse:
    def __init__(self, text="", status=200, headers=None, cookies=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}
        self.raw = types.SimpleNamespace(headers=FakeRawHeaders(cookies))

class FakeHTTPClient:
    """Minimal stand‑in for HTTPClient returning crafted responses."""
    def __init__(self):
        self.calls = []
    def get(self, url, params=None, allow_redirects=True):
        full_url = url
        if params:
            qs = _u.urlencode(params)
            sep = '&' if '?' in url else '?'
            full_url = f"{url}{sep}{qs}"
        self.calls.append(full_url)
        parsed = _u.urlparse(full_url)
        q = _u.parse_qs(parsed.query)
        body = ""
        # Simulate SQL error based detection when a quote is present
        if any("'" in v for vs in q.values() for v in vs):
            body = "You have an error in your SQL syntax near '"
        # Directory traversal signature
        for values in q.values():
            for v in values:
                if '<script>alert(' in v or 'svg/onload' in v:
                    body += f" REFLECT:{v}"
                if '../etc/passwd' in v:
                    body = "root:x:0:0"  # traversal signature
                if 'SLEEP(5)' in v or 'pg_sleep' in v or 'WAITFOR DELAY' in v:
                    return FakeResponse("Delayed"), 5.5, None  # time-based sqli
        headers = {}
        if 'example.org' in full_url and 'redirect' in full_url:
            headers['Location'] = 'http://example.org/'
        return FakeResponse(body or "OK", headers=headers), 0.05, None
    def post(self, url, data=None):
        params = data or {}
        qs = _u.urlencode(params)
        return self.get(f"{url}?{qs}")

@pytest.fixture
def fake_http():
    return FakeHTTPClient()
