import re
from typing import List, Optional, Callable
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

PATTERNS = [
    (re.compile(r"-----BEGIN PRIVATE KEY-----"), "Private Key Material"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "Possible AWS Access Key"),
    (re.compile(r"SECRET[_-]?KEY\s*[:=]\s*['\"]?[A-Za-z0-9/_\-]{8,}"), "Potential Secret Key"),
    (re.compile(r"API[_-]?KEY\s*[:=]\s*['\"]?[A-Za-z0-9/_\-]{8,}"), "Potential API Key"),
    (re.compile(r"(?i)todo[:]?|fixme[:]?"), "Developer Comment"),
]

MAX_BODY_LENGTH = 500_000

class InfoDisclosureCheck(BaseCheck):
    name = "info_disclosure"
    description = "Search for disclosed secrets or sensitive info in page body"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not page.body:
            return findings
        body = page.body
        if len(body) > MAX_BODY_LENGTH:
            body = body[:MAX_BODY_LENGTH]
        for pattern, label in PATTERNS:
            for m in pattern.finditer(body):
                snippet = body[max(0, m.start()-20): m.end()+20]
                findings.append(Finding(
                    issue=f"Potential {label}",
                    severity="Medium" if 'KEY' in label else "Low",
                    location=page.url,
                    evidence=snippet.replace('\n', ' ')[:120],
                    risk="Could expose sensitive data aiding attackers.",
                    category="Information Disclosure"
                ))
        return findings

