import time
import requests
from typing import Optional, Tuple, Dict, Any
from requests import Response
from requests.exceptions import Timeout, ConnectionError, RequestException
from config import CONFIG

class HTTPClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": CONFIG.USER_AGENT})

    def _request(self, method: str, url: str, *, params=None, data=None, allow_redirects=True) -> Tuple[Optional[Response], float, Optional[str]]:
        start = time.time()
        try:
            resp = self.session.request(method.upper(), url, params=params, data=data, timeout=CONFIG.REQUEST_TIMEOUT, allow_redirects=allow_redirects)
            return resp, time.time() - start, None
        except Timeout:
            return None, 0.0, "Timeout"
        except ConnectionError:
            return None, 0.0, "ConnectionError"
        except RequestException as e:
            return None, 0.0, f"RequestException: {e}"

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, allow_redirects: bool = True):
        return self._request('GET', url, params=params, allow_redirects=allow_redirects)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None):
        return self._request('POST', url, data=data)

