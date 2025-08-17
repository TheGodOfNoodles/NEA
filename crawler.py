from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Callable, Iterable
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl, urlencode
from bs4 import BeautifulSoup
from http_client import HTTPClient
import re, time, math
from collections import deque
from config import CONFIG

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
    raw_set_cookies: List[str] = field(default_factory=list)
    # enriched metadata
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    content_length: Optional[int] = None
    final_url: Optional[str] = None
    discovered_assets: Set[str] = field(default_factory=set)
    canonical_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    parsed_cookies: List[Dict[str, str]] = field(default_factory=list)
    js_endpoints: Set[str] = field(default_factory=set)
    skipped_by_robots: bool = False

# Hook type aliases
PreFetchHook = Callable[[str], bool]            # return False to skip fetch
PostFetchHook = Callable[[PageData], None]
LinkFilterHook = Callable[[str], bool]          # return True to allow enqueue
FormFilterHook = Callable[[FormInfo], bool]     # return True to keep form

class Crawler:
    def __init__(self, base_url: str, max_depth: int, http_client: HTTPClient,
                 status_cb: Optional[Callable[[str], None]] = None,
                 progress_cb: Optional[Callable[[float], None]] = None,
                 stop_event=None,
                 include_re: Optional[str] = None,
                 exclude_re: Optional[str] = None,
                 max_pages: Optional[int] = None,
                 remove_query_params: Optional[Iterable[str]] = None,
                 respect_robots: bool = False,
                 retries: int = 2,
                 pre_fetch_hook: Optional[PreFetchHook] = None,
                 post_fetch_hook: Optional[PostFetchHook] = None,
                 link_filter_hook: Optional[LinkFilterHook] = None,
                 form_filter_hook: Optional[FormFilterHook] = None):
        self.base_url = self._normalize(base_url)
        self.max_depth = max_depth
        self.parsed_base = urlparse(self.base_url)
        self.visited: Set[str] = set()
        self.seen: Set[str] = set()
        self.pages: Dict[str, PageData] = {}
        self.http = http_client
        self.status_cb = status_cb or (lambda msg: None)
        self.progress_cb = progress_cb or (lambda v: None)
        self.stop_event = stop_event
        self.include_re = re.compile(include_re) if include_re else (re.compile(CONFIG.INCLUDE_RE) if CONFIG.INCLUDE_RE else None)
        self.exclude_re = re.compile(exclude_re) if exclude_re else (re.compile(CONFIG.EXCLUDE_RE) if CONFIG.EXCLUDE_RE else None)
        self.max_pages = max_pages
        self.remove_query_params = set(remove_query_params or {'utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid','ref'})
        self.delay = CONFIG.CRAWL_DELAY
        self.respect_robots = respect_robots
        self.retries = max(0, retries)
        self.pre_fetch_hook = pre_fetch_hook
        self.post_fetch_hook = post_fetch_hook
        self.link_filter_hook = link_filter_hook
        self.form_filter_hook = form_filter_hook
        # robots data
        self._robots_disallow: List[str] = []
        if self.respect_robots:
            self._load_robots()

    # ---------------- Robots handling -----------------
    def _load_robots(self):
        robots_url = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}/robots.txt"
        try:
            resp, _, err = self.http.get(robots_url)
            if err or not resp or resp.status_code >= 400:
                return
            ua_section_relevant = False
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.lower().startswith('user-agent:'):
                    agent = line.split(':',1)[1].strip()
                    ua_section_relevant = (agent == '*' or CONFIG.USER_AGENT.startswith(agent))
                    continue
                if ua_section_relevant and line.lower().startswith('disallow:'):
                    path = line.split(':',1)[1].strip()
                    if path:  # empty means allowed
                        self._robots_disallow.append(path)
        except Exception:
            pass

    def _violates_robots(self, url: str) -> bool:
        if not self._robots_disallow:
            return False
        try:
            parsed = urlparse(url)
            path = parsed.path or '/'
            for rule in self._robots_disallow:
                if rule == '/':
                    return True
                if path.startswith(rule):
                    return True
            return False
        except Exception:
            return False

    # ---------------- Normalization & scope helpers -----------------
    def _normalize(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if netloc.endswith(':80') and scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and scheme == 'https':
            netloc = netloc[:-4]
        path = re.sub(r'/+', '/', parsed.path or '/')
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        is_root = (path == '/')
        if parsed.query:
            q_items = []
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                if k.lower() not in self.remove_query_params:
                    q_items.append((k, v))
            query = urlencode(sorted(q_items)) if q_items else ''
        else:
            query = ''
        if is_root and not query:
            return f"{scheme}://{netloc}"
        new_url = urlunparse((scheme, netloc, path, '', query, ''))
        return new_url

    def in_scope(self, url: str) -> bool:
        try:
            p = urlparse(url)
        except Exception:
            return False
        return p.netloc.lower() == self.parsed_base.netloc.lower()

    def _allow(self, url: str) -> bool:
        if self.include_re and not self.include_re.search(url):
            return False
        if self.exclude_re and self.exclude_re.search(url):
            return False
        return True

    # ---------------- Cookie parsing -----------------
    def _parse_cookie(self, raw: str) -> Dict[str, str]:
        parts = [p.strip() for p in raw.split(';') if p.strip()]
        if not parts:
            return {}
        name, value = (parts[0].split('=',1)+[''])[:2]
        attrs = {'name': name, 'value': value}
        for attr in parts[1:]:
            if '=' in attr:
                k,v = attr.split('=',1)
                attrs[k.lower()] = v
            else:
                attrs[attr.lower()] = 'true'
        return attrs

    # ---------------- Fetch with retries -----------------
    def _fetch_with_retries(self, url: str):
        attempt = 0
        while True:
            resp, elapsed, err = self.http.get(url)
            status = getattr(resp, 'status_code', None) if resp else None
            transient = err is not None or (status is not None and (status >= 500 or status == 429))
            if not transient or attempt >= self.retries:
                return resp, elapsed, err
            backoff = min(2 ** attempt * 0.25, 5.0)
            time.sleep(backoff)
            attempt += 1

    # ---------------- JS endpoint extraction -----------------
    _endpoint_re = re.compile(r"(?:(?:fetch|ajax|open)\(['\"]([^'\"#?]+)['\"]|['\"](/[^'\"\s<>{}]+)['\"])", re.IGNORECASE)

    def _extract_js_endpoints(self, soup: BeautifulSoup, base_for_page: str) -> Set[str]:
        found: Set[str] = set()
        for script in soup.find_all('script'):
            if script.get('src'):
                continue
            text = script.string or ''
            for match in self._endpoint_re.findall(text):
                # match can be tuple due to alternation; pick first non-empty
                if isinstance(match, tuple):
                    for part in match:
                        if part:
                            candidate = part
                            break
                else:
                    candidate = match
                if not candidate:
                    continue
                candidate_url = self._normalize(urljoin(base_for_page, candidate))
                if self.in_scope(candidate_url):
                    found.add(candidate_url)
        return found

    # ---------------- Crawl core -----------------
    def crawl(self):
        self.status_cb("Crawling website...")
        queue: deque[Tuple[str, int]] = deque()
        norm_base = self._normalize(self.base_url)
        queue.append((norm_base, 0))
        self.seen.add(norm_base)
        last_progress_emit = time.time()

        while queue:
            if self.stop_event and self.stop_event.is_set():
                self.status_cb("Crawl stopped by user")
                break
            if self.max_pages and len(self.visited) >= self.max_pages:
                self.status_cb("Reached max page limit")
                break

            current, depth = queue.popleft()
            if current in self.visited or depth > self.max_depth:
                continue
            if self.delay:
                time.sleep(self.delay)
            if self.pre_fetch_hook and not self.pre_fetch_hook(current):
                continue
            if self.respect_robots and self._violates_robots(current):
                pd = PageData(url=current, skipped_by_robots=True)
                self.pages[current] = pd
                self.visited.add(current)
                continue
            self.visited.add(current)
            try:
                self.status_cb(f"Fetching {current}")
                resp, elapsed, err = self._fetch_with_retries(current)
                if err:
                    self.status_cb(f"Error fetching {current}: {err}")
                    continue
                headers = {k.lower(): v for k, v in resp.headers.items()} if resp else {}
                content_type = headers.get('content-type', '')
                page_data = PageData(url=current, headers=headers)
                page_data.response_time = elapsed
                if resp:
                    page_data.status_code = getattr(resp, 'status_code', None)
                    page_data.content_length = int(headers.get('content-length') or len(getattr(resp, 'text', '') or 0) or 0)
                    page_data.final_url = self._normalize(getattr(resp, 'url', current) or current)
                    # redirect chain
                    history = getattr(resp, 'history', []) or []
                    for h in history:
                        try:
                            page_data.redirect_chain.append(self._normalize(getattr(h, 'url', '')))
                        except Exception:
                            continue
                    try:
                        raw = resp.raw.headers.get_all('Set-Cookie') or []  # type: ignore[attr-defined]
                    except Exception:
                        raw = []
                    if 'set-cookie' in headers and not raw:
                        raw = [headers['set-cookie']]
                    page_data.raw_set_cookies = raw
                    page_data.parsed_cookies = [self._parse_cookie(c) for c in raw if c]
                if resp and 'text/html' in content_type:
                    page_data.body = resp.text
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    base_tag = soup.find('base', href=True)
                    base_for_page = urljoin(current, base_tag['href']) if base_tag else current
                    canon_tag = soup.find('link', rel=lambda v: v and 'canonical' in v.lower(), href=True)
                    if canon_tag:
                        canon_url = self._normalize(urljoin(base_for_page, canon_tag['href']))
                        page_data.canonical_url = canon_url
                    for a in soup.find_all('a', href=True):
                        href_raw = a['href'].split('#')[0]
                        if not href_raw:
                            continue
                        href = self._normalize(urljoin(base_for_page, href_raw))
                        if not self.in_scope(href) or not self._allow(href):
                            continue
                        if self.link_filter_hook and not self.link_filter_hook(href):
                            continue
                        page_data.links.add(href)
                        if href not in self.seen and depth + 1 <= self.max_depth:
                            queue.append((href, depth + 1))
                            self.seen.add(href)
                    for form in soup.find_all('form'):
                        action = form.get('action') or current
                        method = (form.get('method') or 'get').lower()
                        action_full = self._normalize(urljoin(base_for_page, action))
                        inputs = []
                        for inp in form.find_all(['input', 'textarea']):
                            name = inp.get('name')
                            if name:
                                inputs.append(FormField(name=name, field_type=(inp.get('type') or 'text')))
                        fi = FormInfo(action=action_full, method=method, inputs=inputs)
                        if self.form_filter_hook and not self.form_filter_hook(fi):
                            continue
                        page_data.forms.append(fi)
                    for tag, attr in (('script','src'),('img','src'),('link','href')):
                        for node in soup.find_all(tag):
                            ref = node.get(attr)
                            if not ref:
                                continue
                            if tag == 'link' and node.get('rel') and 'stylesheet' not in [r.lower() for r in node.get('rel')]:
                                continue
                            asset_url = self._normalize(urljoin(base_for_page, ref))
                            if self.in_scope(asset_url) and self._allow(asset_url):
                                page_data.discovered_assets.add(asset_url)
                    # JS endpoints
                    page_data.js_endpoints = self._extract_js_endpoints(soup, base_for_page)
                self.pages[current] = page_data
                if self.post_fetch_hook:
                    try:
                        self.post_fetch_hook(page_data)
                    except Exception:
                        pass
            except Exception as e:
                self.status_cb(f"Error fetching {current}: {e}")
            now = time.time()
            if now - last_progress_emit > 0.25:
                denom = len(self.visited) + len(queue)
                progress = (len(self.visited) / denom) if denom else 0.0
                self.progress_cb(progress)
                last_progress_emit = now
        self.progress_cb(1.0)
        return self.pages
