from typing import List, Optional, Callable
from scanner.vulnerability import Finding
from .base_check import BaseCheck
from crawler import PageData
from http_client import HTTPClient

class HeaderCheck(BaseCheck):
    name = "headers"
    description = "Security header presence and configuration"

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        if not config:
            return findings
        status = status_cb or (lambda m: None)
        headers = page.headers
        if not headers:
            return findings
        xcto = headers.get('x-content-type-options')
        if xcto is None or xcto.lower() != 'nosniff':
            findings.append(Finding(
                issue="Missing or Misconfigured X-Content-Type-Options",
                severity="Low",
                location=page.url,
                evidence=str(xcto),
                risk="Browsers may perform MIME sniffing leading to unexpected content execution.",
                category="Security Headers",
                description="Response lacks a proper X-Content-Type-Options: nosniff header, allowing browsers to guess MIME types.",
                recommendation="Add 'X-Content-Type-Options: nosniff' for all responses serving user-supplied or script/style content.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"]
            ))
        xfo = headers.get('x-frame-options')
        if xfo is None or xfo.lower() not in ('deny', 'sameorigin'):
            findings.append(Finding(
                issue="Missing or Weak X-Frame-Options",
                severity="Medium",
                location=page.url,
                evidence=str(xfo),
                risk="Could allow clickjacking attacks.",
                category="Security Headers",
                description="Response does not set X-Frame-Options or uses an unsafe value, enabling framing by attacker sites.",
                recommendation="Set 'X-Frame-Options: DENY' or at least 'SAMEORIGIN' (or use CSP frame-ancestors).",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"]
            ))
        csp = headers.get('content-security-policy')
        if csp is None:
            findings.append(Finding(
                issue="Missing Content-Security-Policy",
                severity="Low",
                location=page.url,
                evidence=str(csp),
                risk="Lack of CSP increases risk of XSS and data injection.",
                category="Security Headers",
                description="No Content-Security-Policy header present to restrict script, style, or resource sources.",
                recommendation="Define a restrictive CSP (e.g., default-src 'self'; object-src 'none'; base-uri 'self').",
                references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"]
            ))
        hsts = headers.get('strict-transport-security')
        if page.url.startswith('https://') and not hsts:
            findings.append(Finding(
                issue="Missing Strict-Transport-Security",
                severity="Medium",
                location=page.url,
                evidence=str(hsts),
                risk="Without HSTS users could be downgraded to HTTP (MITM risk).",
                category="Security Headers",
                description="HTTPS site does not enforce HSTS, allowing protocol downgrade or cookie stripping.",
                recommendation="Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' after confirming readiness for preload.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]
            ))
        refpol = headers.get('referrer-policy')
        if not refpol:
            findings.append(Finding(
                issue="Missing Referrer-Policy",
                severity="Low",
                location=page.url,
                evidence=str(refpol),
                risk="Referrers may leak sensitive path/query data to third-party sites.",
                category="Security Headers",
                description="No Referrer-Policy set; full URLs may be leaked in Referer headers to external origins.",
                recommendation="Set 'Referrer-Policy: no-referrer-when-downgrade' or stricter (e.g., 'strict-origin-when-cross-origin').",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"]
            ))
        perm_pol = headers.get('permissions-policy') or headers.get('feature-policy')
        if not perm_pol:
            findings.append(Finding(
                issue="Missing Permissions-Policy",
                severity="Low",
                location=page.url,
                evidence=str(perm_pol),
                risk="Browser features not restricted (e.g., camera, geolocation).",
                category="Security Headers",
                description="No Permissions-Policy header to limit powerful browser features to trusted origins.",
                recommendation="Add a tailored Permissions-Policy limiting features to origins that require them.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"]
            ))
        return findings
