import pkgutil
import importlib
from typing import List, Dict, Callable, Optional, Type, Iterable, Set, Tuple
from threading import Event
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
        self.enabled_checks = {c.lower() for c in enabled_checks} if enabled_checks else None
        self.dedup_keys: Set[Tuple[str, str, str]] = set()
        self._discover_checks()

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

    def scan_pages(self, pages: Dict[str, PageData]) -> List[Finding]:
        total_pages = len(pages) or 1
        checks = [cls() for cls in self.check_classes]
        self.status_cb(f"Running {len(checks)} checks over {total_pages} pages")
        processed = 0
        for url, page in pages.items():
            if self.stop_event and self.stop_event.is_set():
                self.status_cb("Scan stopped by user")
                break
            for check in checks:
                if self.stop_event and self.stop_event.is_set():
                    break
                try:
                    new_findings = check.scan(self.http, page, status_cb=self.status_cb, config=CONFIG)
                    if new_findings:
                        for f in new_findings:
                            key = (f.issue, f.location, f.evidence)
                            if key in self.dedup_keys:
                                continue
                            self.dedup_keys.add(key)
                            self.findings.append(f)
                except Exception as e:
                    self.status_cb(f"Check {check.name} failed on {url}: {e}")
            processed += 1
            self.progress_cb(processed / total_pages)
        return self.findings

