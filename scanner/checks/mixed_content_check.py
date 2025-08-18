from typing import List, Optional, Callable
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient
import re

class MixedContentCheck(BaseCheck):
    name = "mixed_content"
    description = "Detect insecure HTTP sub-resources on HTTPS pages"

    _res_re = re.compile(r'''(?:src|href)=["'](http://[^"'#?\s>]+)''', re.IGNORECASE)

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not page.url.startswith('https://'):
            return findings
        if not page.body:
            return findings
        insecure: set[str] = set()
        for m in self._res_re.finditer(page.body):
            insecure.add(m.group(1))
            if len(insecure) > 50:
                break  # cap to avoid noise
        for res in sorted(insecure):
            findings.append(Finding(
                issue="Mixed Content Reference",
                severity="Medium",
                location=page.url,
                evidence=res,
                risk="Loading HTTP resources within an HTTPS page allows man-in-the-middle tampering.",
                category="Mixed Content",
                description="The page served over HTTPS references one or more sub-resources over insecure HTTP, undermining transport security.",
                recommendation="Serve all sub-resources (scripts, images, styles) over HTTPS or use protocol-relative/relative URLs. Enforce upgrade-insecure-requests via CSP where possible.",
                references=[
                    "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
                    "https://owasp.org/www-project-top-ten/"
                ],
                parameter="resource",
                payload=res
            ))
        return findings

