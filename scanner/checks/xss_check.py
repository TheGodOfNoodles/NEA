from typing import List, Callable, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

class XSSCheck(BaseCheck):
    name = "xss"
    description = "Reflected XSS via parameters and forms"

    def _test_reflection(self, body: str, payload: str) -> bool:
        return payload in body and payload.replace('<', '&lt;') not in body

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not config:
            return findings
        status = status_cb or (lambda m: None)
        # URL param tests
        parsed = urlparse(page.url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                original_value = values[0] if values else ''
                for payload in config.XSS_PAYLOADS:
                    test_qs = {k: v[:] for k, v in qs.items()}
                    test_qs[param] = [original_value + payload]
                    new_query = urlencode({k: v[0] if v else '' for k, v in test_qs.items()}, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    status(f"XSS test param {param} on {parsed.path}")
                    resp, _, err = http.get(test_url)
                    if err or not resp:
                        continue
                    if self._test_reflection(resp.text, payload):
                        findings.append(Finding(
                            issue="Potential Reflected XSS",
                            severity="Medium",
                            location=f"{page.url} (param: {param})",
                            evidence=payload,
                            risk="Attackers could run malicious scripts in users' browsers.",
                            category="Cross-Site Scripting"
                        ))
                        break
        # Form tests
        for form in page.forms:
            params = {inp.name: 'test' for inp in form.inputs}
            for field in form.inputs:
                for payload in config.XSS_PAYLOADS:
                    test_params = params.copy()
                    test_params[field.name] = payload
                    status(f"XSS test form field {field.name} on {form.action}")
                    if form.method == 'post':
                        resp, _, err = http.post(form.action, data=test_params)
                    else:
                        resp, _, err = http.get(form.action, params=test_params)
                    if err or not resp:
                        continue
                    if self._test_reflection(resp.text, payload):
                        findings.append(Finding(
                            issue="Potential Reflected XSS",
                            severity="Medium",
                            location=f"Form {form.action} field {field.name}",
                            evidence=payload,
                            risk="Attackers could run malicious scripts in users' browsers.",
                            category="Cross-Site Scripting"
                        ))
                        break
        return findings

