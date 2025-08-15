# Simple Web Security Scanner

Educational lightweight web application scanner for basic security hygiene checks. Intended for learning and controlled assessment on targets you own or have explicit written permission to test.

## Disclaimer
**Use only on systems you own or have *explicit* authorization to test. Unauthorized scanning may be illegal.** The tool is intentionally limited and NOT a substitute for a professional security assessment.

## Features
- Crawling (configurable depth, in‑scope link discovery, form enumeration)
- Vulnerability checks:
  - Reflected XSS (query + form inputs)
  - DOM XSS heuristic sinks
  - SQL Injection heuristics (error, boolean, time‑based)
  - Directory Traversal (basic payload / signature match)
  - Open Redirect parameters
  - CSRF (missing apparent token in POST forms)
  - Cookie security attributes (HttpOnly, Secure, SameSite)
  - Security Headers (X-Frame-Options, CSP, HSTS, etc.)
  - Information Disclosure (simple secret/credential regexes, dev comments)
- Rich Finding metadata (description, recommendation, references, parameter, payload)
- Multiple report formats: Text, HTML, JSON, CSV, Markdown, SARIF
- GUI (Tk / CustomTkinter) + CLI modes
- Basic request metrics (count, errors, average, total time)
- Deduplication of repeated findings
- Pytest test suite (unit tests for checks + reporting)

## Finding Data Model
Each Finding includes:
| Field | Purpose |
|-------|---------|
| issue | Human readable title |
| severity | High / Medium / Low |
| location | URL / form action context |
| evidence | Minimal proof (payload snippet, header value, etc.) |
| risk | Short impact statement |
| category | Logical grouping (e.g. "Cross-Site Scripting") |
| description | Expanded explanation (optional) |
| recommendation | Remediation guidance (optional) |
| references | List of reference URLs (optional) |
| parameter | Affected parameter / field / cookie (when applicable) |
| payload | Injected payload (where relevant) |

Empty optional fields are omitted or left blank in outputs.

## Installation
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## GUI Usage
```bash
python main.py
```
1. Enter target URL (must start with http:// or https://).
2. Set crawl depth (default 2).
3. Start Scan. Double‑click a finding or use right‑click -> Details for full metadata.
4. Save report (choose format) after completion.

## CLI Usage
```bash
python cli.py --url https://target.example --depth 2 --format text
python cli.py --url https://target.example --format json -o report.json
python cli.py --list-checks
```
Optional env overrides:
- `SCANNER_REQUEST_TIMEOUT` (seconds)
- `SCANNER_UA_SUFFIX` (appends to User-Agent)
- `SCANNER_EXTRA_XSS` (append extra XSS payloads separated by `||`)

## Report Formats
| Format | Notes |
|--------|-------|
| text | Plain text with sections and separators |
| html | Styled blocks, clickable references |
| json | Machine consumable, full Finding fields |
| csv | Tabular, references pipe‑separated |
| markdown | Table + detailed sections |
| sarif | Minimal SARIF 2.1.0 (rules + results) |

## Running Tests
```bash
pytest -q
```
All current tests (checks + reporting) should pass (see tests/). Add new tests when creating additional checks or output formats.

## Extending: Adding a New Check
1. Create `scanner/checks/new_check_name.py` implementing `BaseCheck.scan` returning `List[Finding]`.
2. Populate enriched fields (`description`, `recommendation`, `references`).
3. Add a focused test in `tests/test_checks.py` (or a new module under `tests/`).
4. Run `pytest -q`.
5. (Optional) Add any payload lists / signatures to `config.py`.

## Design Overview
- `crawler.py`: Collects in-scope pages, forms, headers, cookies.
- `scanner/engine.py`: Dynamically discovers check subclasses, orchestrates scans, handles dedup.
- `scanner/checks/*`: Individual, focused vulnerability heuristics.
- `scanner/vulnerability.py`: `Finding` dataclass with enriched metadata.
- `reporting.py`: Multi-format report serialization.
- `app_ui.py`: Tk/CustomTkinter desktop interface.
- `cli.py`: Command line wrapper.
- `tests/`: Pytest suite (fake HTTP client for deterministic checks).

## Metrics
`HTTPClient.metrics()` returns request count, errors, average response time, total time, last error. Displayed in GUI summary.

## Limitations / Future Ideas
- No authentication workflows or session state modeling.
- Limited DOM / JavaScript parsing (regex heuristics only).
- No passive/active separation or rate limiting.
- Add: SSRF, XXE, Path Normalization bypasses, JSON output schema versioning, plugin enable/disable UI.

## Ethics & Responsible Use
Always obtain explicit written permission. Respect robots.txt and rate-limit in real environments. Do not attempt exploitation beyond proof-of-concept payload reflection or header inspection.


## Quick Troubleshooting
| Issue | Cause | Fix |
|-------|-------|-----|
| Empty findings | Target static / no testable parameters | Increase depth, verify dynamic endpoints |
| Slow scan | Time-based SQLi delays | Reduce payloads / depth |
| GUI freeze | Long blocking network | Ensure non-blocking thread (already used), verify connectivity |

---
For educational & improvement feedback, extend tests and contribute new safe heuristics.

