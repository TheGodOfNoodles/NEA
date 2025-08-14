from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Callable
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from http_client import HTTPClient

@dataclass
class FormField:
    name: str
    field_type: str

@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[FormField] = field(default_factory=list)

@dataclass
class PageData:
    url: str
    links: Set[str] = field(default_factory=set)
    forms: List[FormInfo] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''

class Crawler:
    def __init__(self, base_url: str, max_depth: int, http_client: HTTPClient,
                 status_cb: Optional[Callable[[str], None]] = None,
                 progress_cb: Optional[Callable[[float], None]] = None,
                 stop_event=None):
        self.base_url = self._normalize(base_url)
        self.max_depth = max_depth
        self.parsed_base = urlparse(self.base_url)
        self.visited: Set[str] = set()
        self.pages: Dict[str, PageData] = {}
        self.http = http_client
        self.status_cb = status_cb or (lambda msg: None)
        self.progress_cb = progress_cb or (lambda v: None)
        self.stop_event = stop_event

    def _normalize(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return p.netloc == self.parsed_base.netloc

    def crawl(self):
        self.status_cb("Crawling website...")
        queue_urls: List[Tuple[str, int]] = [(self.base_url, 0)]
        while queue_urls:
            if self.stop_event and self.stop_event.is_set():
                self.status_cb("Crawl stopped by user")
                break
            current, depth = queue_urls.pop(0)
            if current in self.visited or depth > self.max_depth:
                continue
            self.visited.add(current)
            try:
                self.status_cb(f"Fetching {current}")
                resp, _, err = self.http.get(current)
                if err:
                    self.status_cb(f"Error fetching {current}: {err}")
                    continue
                headers = {k.lower(): v for k, v in resp.headers.items()} if resp else {}
                content_type = headers.get('content-type', '')
                page_data = PageData(url=current, headers=headers)
                if resp and 'text/html' in content_type:
                    page_data.body = resp.text
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        href = urljoin(current, a['href'].split('#')[0])
                        if self.in_scope(href):
                            page_data.links.add(href)
                            if href not in self.visited and depth + 1 <= self.max_depth:
                                queue_urls.append((href, depth + 1))
                    for form in soup.find_all('form'):
                        action = form.get('action') or current
                        method = (form.get('method') or 'get').lower()
                        action_full = urljoin(current, action)
                        inputs = []
                        for inp in form.find_all(['input', 'textarea']):
                            name = inp.get('name')
                            if name:
                                inputs.append(FormField(name=name, field_type=(inp.get('type') or 'text')))
                        page_data.forms.append(FormInfo(action=action_full, method=method, inputs=inputs))
                self.pages[current] = page_data
            except Exception as e:
                self.status_cb(f"Error fetching {current}: {e}")
            # progress update
            total_remaining = len(queue_urls) + 1  # approximate
            visited = len(self.visited)
            denom = visited + len(queue_urls)
            progress = visited / denom if denom else 0.0
            self.progress_cb(progress)
        return self.pages

