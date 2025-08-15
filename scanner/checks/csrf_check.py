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
                    category="CSRF",
                    description="A POST form lacks an identifiable anti-CSRF token parameter, making forged state-changing requests possible.",
                    recommendation="Include a cryptographically strong, per-session or per-request CSRF token in each state-changing form and validate it server-side.",
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                    ]
                ))
        return findings
