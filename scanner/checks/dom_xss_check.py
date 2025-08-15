import re
from typing import List, Optional, Callable
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

# Simple heuristic patterns for potential DOM XSS sinks using location / hash / search
DOM_SINK_PATTERNS = [
    r"document\.write\(.*location[\.\[]",
    r"innerHTML\s*=\s*location[\.\[]",
    r"innerHTML\s*=\s*.*hash",
    r"eval\(.*location",
    r"setTimeout\(.*location",
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in DOM_SINK_PATTERNS]

class DOMXSSCheck(BaseCheck):
    name = "dom_xss"
    description = "Heuristic detection of potential DOM-based XSS sinks"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not page.body:
            return findings
        lowered = page.body
        for rx in COMPILED:
            for m in rx.finditer(lowered):
                snippet = lowered[max(0, m.start()-25): m.end()+25]
                findings.append(Finding(
                    issue="Potential DOM XSS Sink",
                    severity="Low",
                    location=page.url,
                    evidence=snippet.replace('\n',' ')[:160],
                    risk="Client-side script uses location data in sink (manual review needed)",
                    category="Cross-Site Scripting",
                    description="JavaScript code appears to write data derived from location/hash/search directly into DOM sinks, which can enable DOM-based XSS if the location components are attacker-controlled.",
                    recommendation="Avoid using document.write / innerHTML with untrusted data; use textContent or safe DOM APIs and apply strict Content Security Policy.",
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                ))
        return findings
