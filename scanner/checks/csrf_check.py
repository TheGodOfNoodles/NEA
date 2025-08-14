from typing import List, Optional, Callable
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

TOKEN_FIELD_MARKERS = {"csrf", "token", "authenticity", "xsrf"}

class CSRFCheck(BaseCheck):
    name = "csrf"
    description = "Detect forms lacking anti-CSRF tokens"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        for form in page.forms:
            if form.method != 'post':
                continue
            field_names = {inp.name.lower() for inp in form.inputs if inp.name}
            if not any(any(marker in n for marker in TOKEN_FIELD_MARKERS) for n in field_names):
                findings.append(Finding(
                    issue="Form without apparent CSRF token",
                    severity="Medium",
                    location=form.action,
                    evidence=", ".join(sorted(field_names)) or "(no fields)",
                    risk="May allow Cross-Site Request Forgery attacks.",
                    category="CSRF"
                ))
        return findings

