from typing import List, Optional, Callable
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

class HeaderCheck(BaseCheck):
    name = "headers"
    description = "Security header presence and configuration"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not config:
            return findings
        status = status_cb or (lambda m: None)
        headers = page.headers
        if not headers:
            return findings
        xcto = headers.get('x-content-type-options')
        if xcto is None or xcto.lower() != 'nosniff':
            findings.append(Finding(
                issue="Missing or Misconfigured X-Content-Type-Options",
                severity="Low",
                location=page.url,
                evidence=str(xcto),
                risk="Browsers may perform MIME sniffing leading to unexpected content execution.",
                category="Security Headers"
            ))
        xfo = headers.get('x-frame-options')
        if xfo is None or xfo.lower() not in ('deny', 'sameorigin'):
            findings.append(Finding(
                issue="Missing or Weak X-Frame-Options",
                severity="Medium",
                location=page.url,
                evidence=str(xfo),
                risk="Could allow clickjacking attacks.",
                category="Security Headers"
            ))
        csp = headers.get('content-security-policy')
        if csp is None:
            findings.append(Finding(
                issue="Missing Content-Security-Policy",
                severity="Low",
                location=page.url,
                evidence=str(csp),
                risk="Lack of CSP increases risk of XSS and data injection.",
                category="Security Headers"
            ))
        return findings

