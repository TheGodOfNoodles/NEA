import types
import pytest
import importlib
from http_client import HTTPClient
from config import CONFIG, reload_config

class DummySession:
    def __init__(self, scenario='ok'):
        self.headers = {}
        self._scenario = scenario
        self.calls = []
    def request(self, method, url, params=None, data=None, timeout=None, allow_redirects=True):  # pragma: no cover - simple harness
        self.calls.append((method, url, params, data, timeout, allow_redirects))
        if self._scenario == 'timeout':
            from requests.exceptions import Timeout
            raise Timeout('timeout')
        if self._scenario == 'conn':
            from requests.exceptions import ConnectionError
            raise ConnectionError('conn')
        if self._scenario == 'error':
            from requests.exceptions import RequestException
            raise RequestException('boom')
        # success scenario
        resp = types.SimpleNamespace()
        resp.status_code = 200
        resp.text = 'OK'
        resp.headers = {'X-Test':'1'}
        resp.raw = types.SimpleNamespace(headers=types.SimpleNamespace(get_all=lambda name: []))
        return resp


def test_http_client_success_metrics():
    s = DummySession()
    client = HTTPClient(session=s)
    r, elapsed, err = client.get('http://example.test/')
    assert err is None and r is not None
    m = client.metrics()
    assert m['requests'] == 1 and m['errors'] == 0 and m['last_error'] is None
    assert 'avg_response_time' in m

@pytest.mark.parametrize('scenario,expected',[('timeout','Timeout'),('conn','ConnectionError'),('error','RequestException: boom')])
def test_http_client_error_paths(scenario, expected):
    client = HTTPClient(session=DummySession(scenario))
    r, elapsed, err = client.get('http://example.test/')
    assert r is None
    assert expected in err
    m = client.metrics()
    assert m['errors'] == 1 and m['last_error']


def test_user_agent_applied_env(monkeypatch):
    # Because http_client imported CONFIG by value at module import time, reload the module after reloading config
    monkeypatch.setenv('SCANNER_UA_SUFFIX','TEST')
    reload_config()
    import http_client as hc
    importlib.reload(hc)
    client = hc.HTTPClient()
    assert 'TEST' in client.session.headers['User-Agent']
