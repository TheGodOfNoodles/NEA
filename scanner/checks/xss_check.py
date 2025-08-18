from typing import List, Callable, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Removed global cross-run cache to keep scans deterministic

class XSSCheck(BaseCheck):
    name = "xss"
    description = "Reflected XSS via parameters and forms"

    def _test_reflection(self, body: str, payload: str) -> bool:
        return payload in body and payload.replace('<', '&lt;') not in body

    def _limited_payloads(self, payloads, config):
        if not config or not getattr(config, 'FAST_XSS', False):
            return payloads
        # Keep first 2 + any payload containing onerror (heuristic) for coverage
        core = payloads[:2]
        extra = [p for p in payloads if 'onerror' in p][:1]
        # maintain original order without duplicates
        seen = set(); limited = []
        for p in core + extra:
            if p not in seen:
                limited.append(p); seen.add(p)
        return limited

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not config:
            return findings
        status = status_cb or (lambda m: None)
        payloads = self._limited_payloads(config.XSS_PAYLOADS, config)
        max_parallel = max(1, getattr(config, 'XSS_MAX_PARALLEL', 1))
        tested_lock = threading.Lock()
        tested = set()  # (identifier)
        allow_multi = not getattr(config, 'FAST_XSS', False)  # in fast mode keep prior behavior (first only)
        # URL param tests
        parsed = urlparse(page.url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                original_value = values[0] if values else ''
                def gen_tasks():
                    for payload in payloads:
                        test_qs = {k: v[:] for k, v in qs.items()}
                        test_qs[param] = [original_value + payload]
                        new_query = urlencode({k: v[0] if v else '' for k, v in test_qs.items()}, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        sig = (test_url, param, payload, 0)
                        with tested_lock:
                            if sig in tested:
                                continue
                            tested.add(sig)
                        yield test_url, payload
                tasks = list(gen_tasks())
                if not tasks:
                    continue
                if max_parallel == 1 or len(tasks) == 1:
                    for test_url, payload in tasks:
                        if not allow_multi and any(f.parameter == param for f in findings):
                            break
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
                                category="Cross-Site Scripting",
                                description="The application reflects user-supplied input into the response without proper output encoding, enabling script injection.",
                                recommendation="Implement context-aware output encoding (e.g., HTML entity encoding), validate/clean input, and set a restrictive Content-Security-Policy.",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                ],
                                parameter=param,
                                payload=payload
                            ))
                else:
                    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
                        fut_map = {ex.submit(http.get, test_url): (payload, test_url) for test_url, payload in tasks}
                        for fut in as_completed(fut_map):
                            payload, test_url = fut_map[fut]
                            if not allow_multi and any(f.parameter == param for f in findings):
                                break
                            try:
                                resp, _, err = fut.result()
                            except Exception:
                                continue
                            if err or not resp:
                                continue
                            if self._test_reflection(resp.text, payload):
                                findings.append(Finding(
                                    issue="Potential Reflected XSS",
                                    severity="Medium",
                                    location=f"{page.url} (param: {param})",
                                    evidence=payload,
                                    risk="Attackers could run malicious scripts in users' browsers.",
                                    category="Cross-Site Scripting",
                                    description="The application reflects user-supplied input into the response without proper output encoding, enabling script injection.",
                                    recommendation="Implement context-aware output encoding (e.g., HTML entity encoding), validate/clean input, and set a restrictive Content-Security-Policy.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                    ],
                                    parameter=param,
                                    payload=payload
                                ))
        # Form tests
        for form in page.forms:
            params = {inp.name: 'test' for inp in form.inputs}
            for field in form.inputs:
                def gen_form_tasks():
                    for payload in payloads:
                        sig = (form.action, field.name, payload, 1)
                        with tested_lock:
                            if sig in tested:
                                continue
                            tested.add(sig)
                        test_params = params.copy(); test_params[field.name] = payload
                        yield payload, test_params
                tasks = list(gen_form_tasks())
                if not tasks:
                    continue
                if max_parallel == 1 or len(tasks) == 1:
                    for payload, test_params in tasks:
                        if not allow_multi and any(f.parameter == field.name and f.location.startswith("Form ") for f in findings):
                            break
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
                                category="Cross-Site Scripting",
                                description="A form field's value is reflected unsafely in the server response, indicating insufficient output encoding.",
                                recommendation="Apply server-side output encoding, prefer framework templating auto-escaping, and sanitize untrusted HTML/JS.",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://owasp.org/Top10/A03_2021-Injection/"
                                ],
                                parameter=field.name,
                                payload=payload
                            ))
                else:
                    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
                        if form.method == 'post':
                            fut_map = {ex.submit(http.post, form.action, data=test_params): (payload, test_params) for payload, test_params in tasks}
                        else:
                            fut_map = {ex.submit(http.get, form.action, params=test_params): (payload, test_params) for payload, test_params in tasks}
                        for fut in as_completed(fut_map):
                            payload, _tp = fut_map[fut]
                            if not allow_multi and any(f.parameter == field.name and f.location.startswith("Form ") for f in findings):
                                break
                            try:
                                resp, _, err = fut.result()
                            except Exception:
                                continue
                            if err or not resp:
                                continue
                            if self._test_reflection(resp.text, payload):
                                findings.append(Finding(
                                    issue="Potential Reflected XSS",
                                    severity="Medium",
                                    location=f"Form {form.action} field {field.name}",
                                    evidence=payload,
                                    risk="Attackers could run malicious scripts in users' browsers.",
                                    category="Cross-Site Scripting",
                                    description="A form field's value is reflected unsafely in the server response, indicating insufficient output encoding.",
                                    recommendation="Apply server-side output encoding, prefer framework templating auto-escaping, and sanitize untrusted HTML/JS.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://owasp.org/Top10/A03_2021-Injection/"
                                    ],
                                    parameter=field.name,
                                    payload=payload
                                ))
        return findings
