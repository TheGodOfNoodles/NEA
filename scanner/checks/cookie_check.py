from typing import List, Optional, Callable
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

class CookieSecurityCheck(BaseCheck):
    name = "cookies"
    description = "Detect insecure cookie attributes (HttpOnly, Secure, SameSite)"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not page.raw_set_cookies:
            return findings
        for raw in page.raw_set_cookies:
            lowered = raw.lower()
            cookie_name = raw.split('=',1)[0].strip()
            missing = []
            severity = 'Low'
            if 'httponly' not in lowered:
                missing.append('HttpOnly')
            if page.url.startswith('https://') and 'secure' not in lowered:
                missing.append('Secure')
            if 'samesite' not in lowered:
                missing.append('SameSite')
            if missing:
                findings.append(Finding(
                    issue=f"Cookie missing attributes: {', '.join(missing)}",
                    severity=severity,
                    location=page.url,
                    evidence=cookie_name,
                    risk="Missing cookie protections may allow theft or CSRF.",
                    category="Cookies"
                ))
        return findings

