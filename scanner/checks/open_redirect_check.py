from typing import List, Optional, Callable
from urllib.parse import urlparse, parse_qs, urlencode
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

REDIRECT_PARAM_CANDIDATES = {"url", "next", "redirect", "redirect_uri", "return", "return_url", "goto"}
TEST_EXTERNAL = "http://example.org/"

class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"
    description = "Detect possible open redirect parameters"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        status = status_cb or (lambda m: None)
        parsed = urlparse(page.url)
        if not parsed.query:
            return findings
        qs = parse_qs(parsed.query)
        for param in list(qs.keys()):
            if param.lower() in REDIRECT_PARAM_CANDIDATES:
                original_value = qs[param][0] if qs[param] else ''
                test_qs = {k: v[:] for k, v in qs.items()}
                test_qs[param] = [TEST_EXTERNAL]
                new_query = urlencode({k: v[0] if v else '' for k, v in test_qs.items()}, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                status(f"Open redirect test {param} on {parsed.path}")
                resp, _, err = http.get(test_url, allow_redirects=False)
                if resp is None:
                    continue
                loc = resp.headers.get('Location') if hasattr(resp, 'headers') else None
                if loc and loc.startswith(TEST_EXTERNAL):
                    findings.append(Finding(
                        issue="Potential Open Redirect",
                        severity="Medium",
                        location=f"{page.url} (param: {param})",
                        evidence=f"Redirects to external {TEST_EXTERNAL}",
                        risk="Can be abused for phishing and chaining attacks.",
                        category="Open Redirect",
                        description="Application allows unvalidated redirection to an arbitrary external domain via a user-controlled parameter.",
                        recommendation="Validate redirect targets against an allow-list or use internal identifiers; avoid directly using user input in Location headers.",
                        references=[
                            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                        ],
                        parameter=param,
                        payload=TEST_EXTERNAL
                    ))
        return findings
