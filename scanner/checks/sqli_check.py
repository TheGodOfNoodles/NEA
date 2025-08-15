from typing import List, Optional, Callable
from urllib.parse import urlparse, parse_qs, urlencode
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

BOOLEAN_DIFF_THRESHOLD = 50
TIME_DELAY_SECONDS = 5

SQLI_REFERENCES = [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://owasp.org/Top10/A03_2021-Injection/"
]

class SQLiCheck(BaseCheck):
    name = "sqli"
    description = "Basic SQL Injection heuristics (error, boolean, time-based)"

    def _error_based(self, body: str, sql_errors: List[str]) -> bool:
        low = body.lower()
        return any(err in low for err in sql_errors)

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not config:
            return findings
        status = status_cb or (lambda m: None)
        parsed = urlparse(page.url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                original_value = values[0] if values else ''
                # Error-based
                inj_value = original_value + "'"
                test_qs = {k: v[:] for k, v in qs.items()}; test_qs[param] = [inj_value]
                new_query = urlencode({k: v[0] if v else '' for k, v in test_qs.items()}, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                status(f"SQLi error-based test {param}")
                resp, _, err = http.get(test_url)
                if resp and self._error_based(resp.text, config.SQL_ERRORS):
                    findings.append(Finding(
                        issue="Potential SQL Injection (Error-Based)",
                        severity="High",
                        location=f"{page.url} (param: {param})",
                        evidence="SQL error message detected",
                        risk="Could allow database access or data theft.",
                        category="SQL Injection",
                        description="Database error messages indicate that user-supplied input is concatenated into SQL without proper parameterization.",
                        recommendation="Use parameterized queries / prepared statements and enforce server-side input validation. Suppress verbose SQL errors in production.",
                        references=SQLI_REFERENCES,
                        parameter=param,
                        payload=inj_value
                    ))
                    continue
                # Boolean-based
                true_payload = original_value + " AND 1=1"
                false_payload = original_value + " AND 1=2"
                qs_true = {k: v[:] for k, v in qs.items()}; qs_true[param] = [true_payload]
                qs_false = {k: v[:] for k, v in qs.items()}; qs_false[param] = [false_payload]
                url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_true.items()}, doseq=True)
                url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_false.items()}, doseq=True)
                status(f"SQLi boolean-based test {param}")
                r_true, _, _ = http.get(url_true)
                r_false, _, _ = http.get(url_false)
                if r_true and r_false and r_true.status_code == 200 and r_false.status_code == 200:
                    if abs(len(r_true.text) - len(r_false.text)) > BOOLEAN_DIFF_THRESHOLD:
                        findings.append(Finding(
                            issue="Potential SQL Injection (Boolean-Based)",
                            severity="High",
                            location=f"{page.url} (param: {param})",
                            evidence="Response length differs for boolean conditions",
                            risk="Could allow database access or data theft.",
                            category="SQL Injection",
                            description="Application behavior differs based on injected boolean condition, suggesting dynamic SQL evaluation.",
                            recommendation="Adopt parameterized queries and avoid constructing SQL strings with unsanitized input.",
                            references=SQLI_REFERENCES,
                            parameter=param,
                            payload=true_payload + " | " + false_payload
                        ))
                        continue
                # Time-based (MySQL, PostgreSQL, MSSQL variants)
                time_payloads = [
                    original_value + " AND SLEEP(5)",
                    original_value + " AND pg_sleep(5)",
                    original_value + ";WAITFOR DELAY '0:0:5'--",
                ]
                did_time = False
                for time_payload in time_payloads:
                    qs_time = {k: v[:] for k, v in qs.items()}; qs_time[param] = [time_payload]
                    url_time = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_time.items()}, doseq=True)
                    status(f"SQLi time-based test {param}")
                    r_time, elapsed, _ = http.get(url_time)
                    if elapsed > TIME_DELAY_SECONDS:
                        findings.append(Finding(
                            issue="Potential SQL Injection (Time-Based)",
                            severity="High",
                            location=f"{page.url} (param: {param})",
                            evidence=f"Delayed response ({elapsed:.2f}s)",
                            risk="Could allow database access or data theft.",
                            category="SQL Injection",
                            description="Injected time-delay function caused measurable response delay, indicating execution within SQL context.",
                            recommendation="Use parameterized queries and limit database permissions. Implement query timeouts and monitoring.",
                            references=SQLI_REFERENCES,
                            parameter=param,
                            payload=time_payload
                        ))
                        did_time = True
                        break
                if did_time:
                    continue
        # Forms
        for form in page.forms:
            base_params = {i.name: 'test' for i in form.inputs}
            for field in form.inputs:
                # Error-based
                params_err = base_params.copy(); params_err[field.name] = "test'"
                status(f"SQLi error-based form {field.name}")
                if form.method == 'post':
                    resp, _, _ = http.post(form.action, data=params_err)
                else:
                    resp, _, _ = http.get(form.action, params=params_err)
                if resp and self._error_based(resp.text, config.SQL_ERRORS):
                    findings.append(Finding(
                        issue="Potential SQL Injection (Error-Based)",
                        severity="High",
                        location=f"Form {form.action} field {field.name}",
                        evidence="SQL error message detected",
                        risk="Could allow database access or data theft.",
                        category="SQL Injection",
                        description="Database error indicates form field input is injected into SQL without parameterization.",
                        recommendation="Refactor data access layer to use prepared statements for all queries.",
                        references=SQLI_REFERENCES,
                        parameter=field.name,
                        payload="test'"
                    ))
                    continue
                # Boolean-based
                params_true = base_params.copy(); params_true[field.name] = "test AND 1=1"
                params_false = base_params.copy(); params_false[field.name] = "test AND 1=2"
                status(f"SQLi boolean-based form {field.name}")
                if form.method == 'post':
                    r_true, _, _ = http.post(form.action, data=params_true)
                    r_false, _, _ = http.post(form.action, data=params_false)
                else:
                    r_true, _, _ = http.get(form.action, params=params_true)
                    r_false, _, _ = http.get(form.action, params=params_false)
                if r_true and r_false and r_true.status_code == 200 and r_false.status_code == 200:
                    if abs(len(r_true.text) - len(r_false.text)) > BOOLEAN_DIFF_THRESHOLD:
                        findings.append(Finding(
                            issue="Potential SQL Injection (Boolean-Based)",
                            severity="High",
                            location=f"Form {form.action} field {field.name}",
                            evidence="Response length differs for boolean conditions",
                            risk="Could allow database access or data theft.",
                            category="SQL Injection",
                            description="Form field influences SQL logic flow based on injected boolean expression.",
                            recommendation="Use parameter binding and ORM features to abstract query construction.",
                            references=SQLI_REFERENCES,
                            parameter=field.name,
                            payload="test AND 1=1 | test AND 1=2"
                        ))
                        continue
                # Time-based
                time_payloads_f = [
                    "test AND SLEEP(5)",
                    "test AND pg_sleep(5)",
                    "test;WAITFOR DELAY '0:0:5'--",
                ]
                time_hit = False
                for tp in time_payloads_f:
                    params_time = base_params.copy(); params_time[field.name] = tp
                    status(f"SQLi time-based form {field.name}")
                    if form.method == 'post':
                        r_time, elapsed, _ = http.post(form.action, data=params_time)
                    else:
                        r_time, elapsed, _ = http.get(form.action, params=params_time)
                    if elapsed > TIME_DELAY_SECONDS:
                        findings.append(Finding(
                            issue="Potential SQL Injection (Time-Based)",
                            severity="High",
                            location=f"Form {form.action} field {field.name}",
                            evidence=f"Delayed response ({elapsed:.2f}s)",
                            risk="Could allow database access or data theft.",
                            category="SQL Injection",
                            description="Injected time-based function executed by the database engine, causing delay.",
                            recommendation="Apply least privilege to DB accounts, parameterize, and monitor for anomalous slow queries.",
                            references=SQLI_REFERENCES,
                            parameter=field.name,
                            payload=tp
                        ))
                        time_hit = True
                        break
                if time_hit:
                    continue
        return findings

