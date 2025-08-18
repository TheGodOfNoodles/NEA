import pkgutil
import importlib
from typing import List, Dict, Callable, Optional, Type, Iterable, Set, Tuple
from threading import Event, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from .vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient
from config import CONFIG
try:
    from .checks.base_check import BaseCheck
except Exception:  # fallback for some analyzers
    from scanner.checks.base_check import BaseCheck  # type: ignore

class VulnerabilityScanner:
    def __init__(self, http_client: HTTPClient, status_cb: Optional[Callable[[str], None]] = None, progress_cb: Optional[Callable[[float], None]] = None, stop_event: Optional[Event] = None, enabled_checks: Optional[Iterable[str]] = None):
        self.http = http_client
        self.status_cb = status_cb or (lambda m: None)
        self.progress_cb = progress_cb or (lambda v: None)
        self.stop_event = stop_event
        self.findings: List[Finding] = []
        self.check_classes: List[Type[BaseCheck]] = []
        self.check_instances: List[BaseCheck] = []  # cached instances for stateless reuse
        self.enabled_checks = {c.lower() for c in enabled_checks} if enabled_checks else None
        self.dedup_keys: Set[Tuple[str, str, str]] = set()
        self._scan_concurrency = max(1, CONFIG.SCAN_CONCURRENCY)
        self._lock = Lock()
        self.scanned_urls: Set[str] = set()  # track pages already scanned (pipeline support)
        self._discover_checks()
        self._instantiate_checks()

    def _discover_checks(self):
        pkg_name = 'scanner.checks'
        package = importlib.import_module(pkg_name)
        for _, mod_name, ispkg in pkgutil.iter_modules(package.__path__, package.__name__ + '.'):  # type: ignore[attr-defined]
            if ispkg or mod_name.endswith('base_check'):
                continue
            try:
                importlib.import_module(mod_name)
            except Exception as e:
                self.status_cb(f"Failed loading check module {mod_name}: {e}")
        # Collect subclasses
        for cls in BaseCheck.__subclasses__():
            if cls not in self.check_classes:
                if self.enabled_checks and cls.name.lower() not in self.enabled_checks:
                    continue
                self.check_classes.append(cls)

    def _instantiate_checks(self):
        self.check_instances = []
        for cls in self.check_classes:
            try:
                inst = cls()
                self.check_instances.append(inst)
            except Exception as e:
                self.status_cb(f"Failed instantiating check {cls.__name__}: {e}")

    def _run_checks_on_page(self, url: str, page: PageData, check_classes: List[Type[BaseCheck]]):
        local_findings: List[Finding] = []
        for cls in check_classes:
            if self.stop_event and self.stop_event.is_set():
                break
            check = cls()
            try:
                new_findings = check.scan(self.http, page, status_cb=self.status_cb, config=CONFIG) or []
            except Exception as e:
                self.status_cb(f"Check {check.name} failed on {url}: {e}")
                continue
            for f in new_findings:
                key = (f.issue, f.location, f.evidence)
                f._dedup_key = key  # type: ignore[attr-defined]
                local_findings.append(f)
        return local_findings

    def _run_checks_on_page_cached(self, url: str, page: PageData):
        # Uses pre-instantiated check objects (assumed stateless per scan call)
        local_findings: List[Finding] = []
        for check in self.check_instances:
            if self.stop_event and self.stop_event.is_set():
                break
            try:
                new_findings = check.scan(self.http, page, status_cb=self.status_cb, config=CONFIG) or []
            except Exception as e:
                self.status_cb(f"Check {check.name} failed on {url}: {e}")
                continue
            for f in new_findings:
                key = (f.issue, f.location, f.evidence)
                f._dedup_key = key  # type: ignore[attr-defined]
                local_findings.append(f)
        return local_findings

    def scan_page(self, page: PageData):
        """Scan a single PageData object (used for pipeline mode)."""
        url = page.url
        if url in self.scanned_urls:
            return
        local_findings = self._run_checks_on_page_cached(url, page)
        with self._lock:
            self.scanned_urls.add(url)
            for f in local_findings:
                if f._dedup_key in self.dedup_keys:  # type: ignore[attr-defined]
                    continue
                self.dedup_keys.add(f._dedup_key)  # type: ignore[attr-defined]
                self.findings.append(f)

    def scan_pages(self, pages: Dict[str, PageData]) -> List[Finding]:
        total_pages = len(pages) or 1
        # Filter out already scanned pages if pipeline mode in effect
        remaining_items = {u: p for u, p in pages.items() if u not in self.scanned_urls}
        if not remaining_items:
            return self.findings
        check_classes = list(self.check_classes)
        self.status_cb(f"Running {len(check_classes)} checks over {len(remaining_items)} pages")
        processed = 0
        if self._scan_concurrency <= 1 or len(remaining_items) <= 1:
            for url, page in remaining_items.items():
                if self.stop_event and self.stop_event.is_set():
                    self.status_cb("Scan stopped by user")
                    break
                local_findings = self._run_checks_on_page_cached(url, page)
                with self._lock:
                    self.scanned_urls.add(url)
                    for f in local_findings:
                        if f._dedup_key in self.dedup_keys:  # type: ignore[attr-defined]
                            continue
                        self.dedup_keys.add(f._dedup_key)  # type: ignore[attr-defined]
                        self.findings.append(f)
                processed += 1
                self.progress_cb(processed / total_pages)
            return self.findings
        # Concurrent path
        with ThreadPoolExecutor(max_workers=self._scan_concurrency) as executor:
            future_map = {executor.submit(self._run_checks_on_page, url, page, check_classes): url for url, page in remaining_items.items()}
            for fut in as_completed(future_map):
                if self.stop_event and self.stop_event.is_set():
                    self.status_cb("Scan stopped by user")
                    break
                url = future_map[fut]
                try:
                    local_findings = fut.result()
                except Exception as e:
                    self.status_cb(f"Scan worker failed: {e}")
                    local_findings = []
                with self._lock:
                    self.scanned_urls.add(url)
                    for f in local_findings:
                        if f._dedup_key in self.dedup_keys:  # type: ignore[attr-defined]
                            continue
                        self.dedup_keys.add(f._dedup_key)  # type: ignore[attr-defined]
                        self.findings.append(f)
                processed += 1
                self.progress_cb(processed / total_pages)
        return self.findings
