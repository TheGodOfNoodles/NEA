from typing import List, Optional, Callable
from urllib.parse import urlparse, parse_qs, urlencode
from .base_check import BaseCheck
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

PAYLOADS = ['../etc/passwd', '..\\..\\windows\\win.ini', '../../../../../etc/passwd']
SIGNATURES = ['root:x:0:0', '[extensions]', '[fonts]']

class DirectoryTraversalCheck(BaseCheck):
    name = 'dir_traversal'
    description = 'Detect simple directory traversal via parameters'

    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(page.url)
        if not parsed.query:
            return findings
        qs = parse_qs(parsed.query)
        status = status_cb or (lambda m: None)
        for param, values in qs.items():
            original_value = values[0] if values else ''
            for payload in PAYLOADS:
                test_qs = {k: v[:] for k, v in qs.items()}
                test_qs[param] = [payload]
                new_query = urlencode({k: v[0] if v else '' for k, v in test_qs.items()}, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                status(f"Dir traversal test {param}")
                resp, _, err = http.get(test_url)
                if not resp or err:
                    continue
                low = resp.text.lower()
                if any(sig.lower() in low for sig in SIGNATURES):
                    findings.append(Finding(
                        issue='Potential Directory Traversal',
                        severity='High',
                        location=f"{page.url} (param: {param})",
                        evidence=payload,
                        risk='May allow reading arbitrary server files.',
                        category='Directory Traversal',
                        description='Application appears to concatenate user-controlled input into file system paths without proper sanitisation.',
                        recommendation='Normalise and validate path input, restrict to whitelisted directories, and avoid directly using user input in file operations.',
                        references=[
                            'https://owasp.org/www-community/attacks/Path_Traversal',
                            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
                        ],
                        parameter=param,
                        payload=payload
                    ))
                    break
        return findings
