from typing import List, Optional, Callable
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

class InsecureFormCheck(BaseCheck):
    name = "insecure_form"
    description = "Detect potentially insecure form configurations"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not page.forms:
            return findings
        for form in page.forms:
            field_types = {i.field_type.lower() for i in form.inputs if i.field_type}
            has_password = 'password' in field_types
            # 1. Password field sent with GET
            if has_password and form.method.lower() == 'get':
                findings.append(Finding(
                    issue="Password Field Sent via GET",
                    severity="Medium",
                    location=form.action,
                    evidence="method=GET",
                    risk="Credentials may be logged in server logs, browser history, or intermediary proxies.",
                    category="Insecure Form",
                    description="A form containing a password input submits via GET, exposing credentials in URL query strings.",
                    recommendation="Use POST for credential submission and ensure transport over HTTPS.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Information_exposure",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    parameter="method",
                    payload="GET"
                ))
            # 2. HTTPS page posting to HTTP action (downgrade)
            if page.url.startswith('https://') and form.action.startswith('http://'):
                findings.append(Finding(
                    issue="HTTPS Page Form Posts to HTTP",
                    severity="High" if has_password else "Medium",
                    location=form.action,
                    evidence=f"page={page.url} -> action={form.action}",
                    risk="Sensitive data can be intercepted due to downgrade from HTTPS page to HTTP form action.",
                    category="Insecure Form",
                    description="A form on a secure page submits to an insecure HTTP endpoint, enabling man-in-the-middle interception.",
                    recommendation="Ensure form actions on HTTPS pages also use HTTPS endpoints.",
                    references=[
                        "https://owasp.org/www-project-top-ten/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ],
                    parameter="action",
                    payload=form.action
                ))
        return findings

