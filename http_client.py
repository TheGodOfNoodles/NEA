import time
import requests
from typing import Optional, Tuple, Dict, Any
from requests import Response
from requests.exceptions import Timeout, ConnectionError, RequestException
from config import CONFIG
from requests.adapters import HTTPAdapter

class HTTPClient:
    def __init__(self, session: Optional[requests.Session] = None, pool_size: int = 20):
        self.session = session or requests.Session()
        # Mount adapters for connection pooling / reuse if session supports it (tests use DummySession without mount())
        if hasattr(self.session, 'mount'):
            adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
            try:
                self.session.mount('http://', adapter)
                self.session.mount('https://', adapter)
            except Exception:
                pass
        if hasattr(self.session, 'headers'):
            self.session.headers.update({"User-Agent": CONFIG.USER_AGENT})
        self.request_count = 0
        self.total_time = 0.0
        self.error_count = 0
        self.last_error: Optional[str] = None

    def _request(self, method: str, url: str, *, params=None, data=None, allow_redirects=True) -> Tuple[Optional[Response], float, Optional[str]]:
        start = time.time()
        try:
            resp = self.session.request(method.upper(), url, params=params, data=data, timeout=CONFIG.REQUEST_TIMEOUT, allow_redirects=allow_redirects)
            elapsed = time.time() - start
            self.request_count += 1
            self.total_time += elapsed
            return resp, elapsed, None
        except Timeout:
            self.error_count += 1
            self.last_error = "Timeout"
            return None, 0.0, "Timeout"
        except ConnectionError:
            self.error_count += 1
            self.last_error = "ConnectionError"
            return None, 0.0, "ConnectionError"
        except RequestException as e:
            self.error_count += 1
            self.last_error = f"RequestException: {e}"
            return None, 0.0, f"RequestException: {e}"

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, allow_redirects: bool = True):
        return self._request('GET', url, params=params, allow_redirects=allow_redirects)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None):
        return self._request('POST', url, data=data)

    def metrics(self) -> Dict[str, Any]:
        avg = self.total_time / self.request_count if self.request_count else 0.0
        return {
            'requests': self.request_count,
            'errors': self.error_count,
            'avg_response_time': round(avg, 3),
            'total_time': round(self.total_time, 3),
            'last_error': self.last_error,
        }
