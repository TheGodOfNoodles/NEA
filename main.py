import threading
import requests
import time
import queue
import traceback
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

try:
    import customtkinter as ctk
    USING_CUSTOM = True
except ImportError:
    import tkinter as ctk
    from tkinter import ttk, messagebox, filedialog
    USING_CUSTOM = False
else:
    from tkinter import messagebox, filedialog

from bs4 import BeautifulSoup

APP_NAME = "Simple Web Security Scanner"
VERSION = "0.1.0"
ETHICAL_WARNING = "Use only on sites you own or have explicit written permission to test. Unauthorized testing may be illegal."
USER_AGENT = f"{APP_NAME}/{VERSION} (Educational Scanner)"
REQUEST_TIMEOUT = 10

# ---------------- Data Structures -----------------
@dataclass
class FormField:
    name: str
    field_type: str

@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[FormField] = field(default_factory=list)

@dataclass
class PageData:
    url: str
    links: Set[str] = field(default_factory=set)
    forms: List[FormInfo] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class Finding:
    issue: str
    severity: str
    location: str
    evidence: str
    risk: str
    category: str

# ---------------- Crawler -----------------
class Crawler:
    def __init__(self, base_url: str, max_depth: int, status_cb=None, session: Optional[requests.Session] = None):
        self.base_url = self._normalize(base_url)
        self.max_depth = max_depth
        self.parsed_base = urlparse(self.base_url)
        self.visited: Set[str] = set()
        self.pages: Dict[str, PageData] = {}
        self.status_cb = status_cb or (lambda msg: None)
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def _normalize(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return p.netloc == self.parsed_base.netloc

    def crawl(self):
        self.status_cb("Crawling website...")
        queue_urls: List[Tuple[str, int]] = [(self.base_url, 0)]
        while queue_urls:
            current, depth = queue_urls.pop(0)
            if current in self.visited or depth > self.max_depth:
                continue
            self.visited.add(current)
            try:
                self.status_cb(f"Fetching {current}")
                resp = self.session.get(current, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                content_type = headers.get('content-type', '')
                page_data = PageData(url=current, headers=headers)
                if 'text/html' in content_type:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    # Links
                    for a in soup.find_all('a', href=True):
                        href = urljoin(current, a['href'].split('#')[0])
                        if self.in_scope(href):
                            page_data.links.add(href)
                            if href not in self.visited and depth + 1 <= self.max_depth:
                                queue_urls.append((href, depth + 1))
                    # Forms
                    for form in soup.find_all('form'):
                        action = form.get('action') or current
                        method = (form.get('method') or 'get').lower()
                        action_full = urljoin(current, action)
                        inputs = []
                        for inp in form.find_all(['input', 'textarea']):
                            name = inp.get('name')
                            if name:
                                inputs.append(FormField(name=name, field_type=(inp.get('type') or 'text')))
                        page_data.forms.append(FormInfo(action=action_full, method=method, inputs=inputs))
                self.pages[current] = page_data
            except Exception as e:
                self.status_cb(f"Error fetching {current}: {e}")
        return self.pages

# ---------------- Vulnerability Scanner -----------------
class VulnerabilityScanner:
    XSS_PAYLOADS = [
        "<script>alert('XSS_TEST')</script>",
        "\"'><img src=x onerror=alert(1)>",
    ]
    SQL_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql server",
        "sqlite error",
        "psql:",
    ]

    def __init__(self, session: Optional[requests.Session] = None, status_cb=None):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.status_cb = status_cb or (lambda msg: None)
        self.findings: List[Finding] = []

    # Utility
    def _test_reflection(self, response_text: str, payload: str) -> bool:
        return payload in response_text and payload.replace('<', '&lt;') not in response_text

    def _safe_request(self, method: str, url: str, params=None, data=None):
        try:
            start = time.time()
            if method.lower() == 'post':
                r = self.session.post(url, data=data, params=None, timeout=REQUEST_TIMEOUT)
            else:
                r = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            elapsed = time.time() - start
            return r, elapsed
        except Exception as e:
            self.status_cb(f"Request error {url}: {e}")
            return None, 0

    def scan_pages(self, pages: Dict[str, PageData]):
        self.status_cb("Testing security headers...")
        self._check_headers(pages)
        for page in pages.values():
            self._scan_url_params(page.url)
            for form in page.forms:
                self._scan_form(form, page.url)
        return self.findings

    def _scan_url_params(self, url: str):
        parsed = urlparse(url)
        if not parsed.query:
            return
        qs = parse_qs(parsed.query)
        for param, values in qs.items():
            original_value = values[0] if values else ''
            # XSS tests
            for payload in self.XSS_PAYLOADS:
                test_qs = {k: v[:] for k, v in qs.items()}  # deep copy lists
                test_qs[param] = [original_value + payload]
                new_query = urlencode({k: v[0] if isinstance(v, list) and v else '' for k, v in test_qs.items()}, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                self.status_cb(f"XSS test param {param} on {parsed.path}")
                r, _ = self._safe_request('get', test_url)
                if r and self._test_reflection(r.text, payload):
                    self.findings.append(Finding(
                        issue="Potential Reflected XSS",
                        severity="Medium",
                        location=f"{url} (param: {param})",
                        evidence=payload,
                        risk="Attackers could run malicious scripts in users' browsers.",
                        category="Cross-Site Scripting"
                    ))
                    break  # avoid multiple payload reports for same param
            # SQLi tests
            self._test_sqli_param(url, param, original_value, qs)

    def _scan_form(self, form: FormInfo, page_url: str):
        target = form.action
        params = {}
        for f in form.inputs:
            params[f.name] = "test"
        for f in form.inputs:
            # XSS
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[f.name] = payload
                self.status_cb(f"XSS test form field {f.name} on {target}")
                r, _ = self._safe_request(form.method, target, params=test_params if form.method=='get' else None, data=test_params if form.method=='post' else None)
                if r and self._test_reflection(r.text, payload):
                    self.findings.append(Finding(
                        issue="Potential Reflected XSS",
                        severity="Medium",
                        location=f"Form {target} field {f.name}",
                        evidence=payload,
                        risk="Attackers could run malicious scripts in users' browsers.",
                        category="Cross-Site Scripting"
                    ))
                    break
            # SQLi
            self._test_sqli_form_field(form, target, f, params)

    def _test_sqli_param(self, base_url: str, param: str, original_value: str, qs: Dict[str, List[str]]):
        # Error-based
        inj_value = original_value + "'"
        test_qs = {k: v[:] for k, v in qs.items()}
        test_qs[param] = [inj_value]
        parsed = urlparse(base_url)
        new_query = urlencode({k: v[0] if isinstance(v, list) and v else '' for k, v in test_qs.items()}, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        self.status_cb(f"SQLi error-based test {param}")
        r, _ = self._safe_request('get', test_url)
        if r and any(err in r.text.lower() for err in self.SQL_ERRORS):
            self.findings.append(Finding(
                issue="Potential SQL Injection (Error-Based)",
                severity="High",
                location=f"{base_url} (param: {param})",
                evidence="SQL error message detected",
                risk="Could allow database access or data theft.",
                category="SQL Injection"
            ))
            return
        # Boolean-based
        true_payload = original_value + " AND 1=1"
        false_payload = original_value + " AND 1=2"
        qs_true = {k: v[:] for k, v in qs.items()}; qs_true[param] = [true_payload]
        qs_false = {k: v[:] for k, v in qs.items()}; qs_false[param] = [false_payload]
        url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_true.items()}, doseq=True)
        url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_false.items()}, doseq=True)
        self.status_cb(f"SQLi boolean-based test {param}")
        r_true, _ = self._safe_request('get', url_true)
        r_false, _ = self._safe_request('get', url_false)
        if r_true and r_false and r_true.status_code == 200 and r_false.status_code == 200:
            if abs(len(r_true.text) - len(r_false.text)) > 50:  # heuristic
                self.findings.append(Finding(
                    issue="Potential SQL Injection (Boolean-Based)",
                    severity="High",
                    location=f"{base_url} (param: {param})",
                    evidence="Response length differs for boolean conditions",
                    risk="Could allow database access or data theft.",
                    category="SQL Injection"
                ))
                return
        # Time-based
        time_payload = original_value + " AND SLEEP(5)"
        qs_time = {k: v[:] for k, v in qs.items()}; qs_time[param] = [time_payload]
        url_time = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] if v else '' for k, v in qs_time.items()}, doseq=True)
        self.status_cb(f"SQLi time-based test {param}")
        r_time, elapsed = self._safe_request('get', url_time)
        if elapsed > 5:
            self.findings.append(Finding(
                issue="Potential SQL Injection (Time-Based)",
                severity="High",
                location=f"{base_url} (param: {param})",
                evidence=f"Delayed response ({elapsed:.2f}s)",
                risk="Could allow database access or data theft.",
                category="SQL Injection"
            ))

    def _test_sqli_form_field(self, form: FormInfo, target: str, field: FormField, base_params: Dict[str, str]):
        # Error-based
        params_err = base_params.copy(); params_err[field.name] = "test'"
        self.status_cb(f"SQLi error-based form {field.name}")
        r, _ = self._safe_request(form.method, target, params=params_err if form.method=='get' else None, data=params_err if form.method=='post' else None)
        if r and any(err in r.text.lower() for err in self.SQL_ERRORS):
            self.findings.append(Finding(
                issue="Potential SQL Injection (Error-Based)",
                severity="High",
                location=f"Form {target} field {field.name}",
                evidence="SQL error message detected",
                risk="Could allow database access or data theft.",
                category="SQL Injection"
            ))
            return
        # Boolean-based
        params_true = base_params.copy(); params_true[field.name] = "test AND 1=1"
        params_false = base_params.copy(); params_false[field.name] = "test AND 1=2"
        self.status_cb(f"SQLi boolean-based form {field.name}")
        r_true, _ = self._safe_request(form.method, target, params=params_true if form.method=='get' else None, data=params_true if form.method=='post' else None)
        r_false, _ = self._safe_request(form.method, target, params=params_false if form.method=='get' else None, data=params_false if form.method=='post' else None)
        if r_true and r_false and r_true.status_code == 200 and r_false.status_code == 200:
            if abs(len(r_true.text) - len(r_false.text)) > 50:
                self.findings.append(Finding(
                    issue="Potential SQL Injection (Boolean-Based)",
                    severity="High",
                    location=f"Form {target} field {field.name}",
                    evidence="Response length differs for boolean conditions",
                    risk="Could allow database access or data theft.",
                    category="SQL Injection"
                ))
                return
        # Time-based
        params_time = base_params.copy(); params_time[field.name] = "test AND SLEEP(5)"
        self.status_cb(f"SQLi time-based form {field.name}")
        r_time, elapsed = self._safe_request(form.method, target, params=params_time if form.method=='get' else None, data=params_time if form.method=='post' else None)
        if elapsed > 5:
            self.findings.append(Finding(
                issue="Potential SQL Injection (Time-Based)",
                severity="High",
                location=f"Form {target} field {field.name}",
                evidence=f"Delayed response ({elapsed:.2f}s)",
                risk="Could allow database access or data theft.",
                category="SQL Injection"
            ))

    def _check_headers(self, pages: Dict[str, PageData]):
        checked = set()
        for url, page in pages.items():
            if page.url in checked:
                continue
            checked.add(page.url)
            headers = page.headers
            missing = []
            # X-Content-Type-Options
            xcto = headers.get('x-content-type-options')
            if xcto is None or xcto.lower() != 'nosniff':
                self.findings.append(Finding(
                    issue="Missing or Misconfigured X-Content-Type-Options",
                    severity="Low",
                    location=url,
                    evidence=str(xcto),
                    risk="Browsers may perform MIME sniffing leading to unexpected content execution.",
                    category="Security Headers"
                ))
            # X-Frame-Options
            xfo = headers.get('x-frame-options')
            if xfo is None or xfo.lower() not in ('deny', 'sameorigin'):
                self.findings.append(Finding(
                    issue="Missing or Weak X-Frame-Options",
                    severity="Medium",
                    location=url,
                    evidence=str(xfo),
                    risk="Could allow clickjacking attacks.",
                    category="Security Headers"
                ))
            # Content-Security-Policy
            csp = headers.get('content-security-policy')
            if csp is None:
                self.findings.append(Finding(
                    issue="Missing Content-Security-Policy",
                    severity="Low",
                    location=url,
                    evidence=str(csp),
                    risk="Lack of CSP increases risk of XSS and data injection.",
                    category="Security Headers"
                ))

# ---------------- Report Builder -----------------
class ReportBuilder:
    def __init__(self, target: str, findings: List[Finding]):
        self.target = target
        self.findings = findings

    def group_by_category(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.category, []).append(f)
        return groups

    def to_text(self) -> str:
        lines = [f"Report for {self.target}", f"Generated: {time.ctime()}", "Disclaimer: " + ETHICAL_WARNING, ""]
        for f in self.findings:
            lines.extend([
                f"[{f.severity}] {f.issue}",
                f"Location: {f.location}",
                f"Evidence: {f.evidence}",
                f"Risk: {f.risk}",
                "---"
            ])
        if not self.findings:
            lines.append("No issues detected by basic tests.")
        return "\n".join(lines)

    def to_html(self) -> str:
        style = """
        <style>
        body { font-family: Arial, sans-serif; margin:20px; }
        .sev-High { color:#b30000; }
        .sev-Medium { color:#d97706; }
        .sev-Low { color:#2563eb; }
        .finding { border:1px solid #ddd; padding:10px; margin-bottom:10px; border-left:6px solid #999; }
        .sev-High.finding { border-left-color:#b30000; }
        .sev-Medium.finding { border-left-color:#d97706; }
        .sev-Low.finding { border-left-color:#2563eb; }
        h1 { font-size:24px; }
        .meta { font-size:12px; color:#555; }
        </style>
        """
        parts = ["<html><head><meta charset='utf-8'><title>Scan Report</title>", style, "</head><body>"]
        parts.append(f"<h1>Report for {self.target}</h1>")
        parts.append(f"<div class='meta'>Generated: {time.ctime()}<br>Disclaimer: {ETHICAL_WARNING}</div><hr>")
        if not self.findings:
            parts.append("<p>No issues detected by basic tests.</p>")
        for f in self.findings:
            parts.append(f"<div class='finding sev-{f.severity}'><h3>[{f.severity}] {f.issue}</h3><p><b>Location:</b> {f.location}<br><b>Evidence:</b> {f.evidence}<br><b>Risk:</b> {f.risk}</p></div>")
        parts.append("</body></html>")
        return "".join(parts)

# ---------------- GUI Application -----------------
class SecurityScanApp:
    def __init__(self):
        if USING_CUSTOM:
            ctk.set_appearance_mode("System")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = ctk.Tk()
        self.root.title(APP_NAME)
        self.status_queue = queue.Queue()
        self._build_ui()
        self.scanner_thread = None
        self.findings: List[Finding] = []
        self.pages: Dict[str, PageData] = {}
        self.root.after(200, self._poll_status)

    def _build_ui(self):
        pad = 8
        frm = ctk.CTkFrame(self.root) if USING_CUSTOM else ctk.Frame(self.root)
        frm.pack(fill='both', expand=True, padx=pad, pady=pad)

        # URL
        lbl_url = ctk.CTkLabel(frm, text="Target URL:") if USING_CUSTOM else ctk.Label(frm, text="Target URL:")
        lbl_url.grid(row=0, column=0, sticky='w')
        self.entry_url = ctk.CTkEntry(frm, width=400) if USING_CUSTOM else ctk.Entry(frm, width=60)
        self.entry_url.grid(row=0, column=1, sticky='we', columnspan=2, pady=2)

        # Depth
        lbl_depth = ctk.CTkLabel(frm, text="Crawl Depth:") if USING_CUSTOM else ctk.Label(frm, text="Crawl Depth:")
        lbl_depth.grid(row=1, column=0, sticky='w')
        self.depth_var = ctk.StringVar(value='2') if not USING_CUSTOM else ctk.StringVar(value='2')
        self.entry_depth = ctk.CTkEntry(frm, width=60, textvariable=self.depth_var) if USING_CUSTOM else ctk.Entry(frm, width=6, textvariable=self.depth_var)
        self.entry_depth.grid(row=1, column=1, sticky='w', pady=2)

        # Buttons
        self.btn_scan = ctk.CTkButton(frm, text="Start Scan", command=self.start_scan) if USING_CUSTOM else ctk.Button(frm, text="Start Scan", command=self.start_scan)
        self.btn_scan.grid(row=2, column=0, pady=4, sticky='we')
        self.btn_report = ctk.CTkButton(frm, text="Save Report", state='disabled', command=self.save_report) if USING_CUSTOM else ctk.Button(frm, text="Save Report", state='disabled', command=self.save_report)
        self.btn_report.grid(row=2, column=1, pady=4, sticky='we')
        self.btn_about = ctk.CTkButton(frm, text="Help / About", command=self.show_about) if USING_CUSTOM else ctk.Button(frm, text="Help / About", command=self.show_about)
        self.btn_about.grid(row=2, column=2, pady=4, sticky='we')

        # Progress
        if USING_CUSTOM:
            self.progress = ctk.CTkProgressBar(frm)
            self.progress.set(0)
        else:
            self.progress = ttk.Progressbar(frm, maximum=100)
            self.progress['value'] = 0
        self.progress.grid(row=3, column=0, columnspan=3, sticky='we', pady=6)

        # Status
        self.status_var = ctk.StringVar(value='Idle') if not USING_CUSTOM else ctk.StringVar(value='Idle')
        self.lbl_status = ctk.CTkLabel(frm, textvariable=self.status_var, anchor='w') if USING_CUSTOM else ctk.Label(frm, textvariable=self.status_var, anchor='w')
        self.lbl_status.grid(row=4, column=0, columnspan=3, sticky='we')

        # Results list
        self.results_box = ctk.CTkTextbox(frm, height=260) if USING_CUSTOM else ctk.Text(frm, height=16, width=80)
        self.results_box.grid(row=5, column=0, columnspan=3, sticky='nsew', pady=6)
        frm.rowconfigure(5, weight=1)
        frm.columnconfigure(1, weight=1)

    def show_about(self):
        about_text = (f"{APP_NAME} v{VERSION}\n\n" +
                      "Basic educational scanner for:\n" +
                      " - Cross-Site Scripting (Reflected)\n" +
                      " - SQL Injection (basic heuristics)\n" +
                      " - Missing Security Headers\n\n" +
                      ETHICAL_WARNING)
        if USING_CUSTOM:
            top = ctk.CTkToplevel(self.root)
            top.title("About")
            lbl = ctk.CTkLabel(top, text=about_text, justify='left')
            lbl.pack(padx=12, pady=12)
        else:
            messagebox.showinfo("About", about_text)

    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            return
        url = self.entry_url.get().strip()
        if not self._valid_url(url):
            messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http:// or https://")
            return
        try:
            depth = int(self.depth_var.get())
        except ValueError:
            messagebox.showerror("Invalid Depth", "Depth must be a number")
            return
        self.btn_scan.configure(state='disabled')
        self.btn_report.configure(state='disabled')
        self.results_box.delete('1.0', 'end')
        self.status_var.set('Starting scan...')
        self.progress_set(0)
        self.findings.clear()
        self.pages.clear()
        self.scanner_thread = threading.Thread(target=self._run_scan, args=(url, depth), daemon=True)
        self.scanner_thread.start()

    def _run_scan(self, url: str, depth: int):
        try:
            self._push_status("Crawling phase started")
            crawler = Crawler(url, depth, status_cb=self._push_status)
            pages = crawler.crawl()
            self.pages = pages
            self._push_status("Vulnerability testing phase started")
            scanner = VulnerabilityScanner(status_cb=self._push_status)
            findings = scanner.scan_pages(pages)
            self.findings = findings
            self._push_status("Scan complete")
            self._render_results()
            self._push_status("Ready to save report")
            self.status_queue.put(("enable_report", None))
        except Exception:
            self._push_status("Scan failed: " + traceback.format_exc(limit=1))
        finally:
            self.status_queue.put(("scan_done", None))

    def _render_results(self):
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.category, []).append(f)
        lines = []
        if not self.findings:
            lines.append("No issues detected by basic tests.")
        for cat, items in groups.items():
            lines.append(f"=== {cat} ===")
            for f in items:
                lines.append(f"[{f.severity}] {f.issue}\nLocation: {f.location}\nRisk: {f.risk}\n")
        self.results_box.insert('end', "\n".join(lines))
        self.results_box.see('end')

    def save_report(self):
        if not self.findings and not self.pages:
            messagebox.showinfo("No Data", "Run a scan first")
            return
        filetypes = [("Text File", "*.txt"), ("HTML File", "*.html")]
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)
        if not path:
            return
        rb = ReportBuilder(self.entry_url.get().strip(), self.findings)
        try:
            if path.lower().endswith('.html'):
                content = rb.to_html()
            else:
                content = rb.to_text()
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Report saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    def _valid_url(self, url: str) -> bool:
        return url.startswith('http://') or url.startswith('https://')

    def _push_status(self, msg: str):
        self.status_queue.put(("status", msg))

    def _poll_status(self):
        try:
            while True:
                item = self.status_queue.get_nowait()
                kind, payload = item
                if kind == 'status':
                    self.status_var.set(payload)
                    # naive progress increment
                    self._increment_progress()
                elif kind == 'scan_done':
                    self.btn_scan.configure(state='normal')
                elif kind == 'enable_report':
                    self.btn_report.configure(state='normal')
        except queue.Empty:
            pass
        self.root.after(300, self._poll_status)

    def _increment_progress(self):
        if USING_CUSTOM:
            val = self.progress._current_value if hasattr(self.progress, '_current_value') else 0
            val = min(1.0, val + 0.03)
            self.progress.set(val)
        else:
            val = self.progress['value'] / 100
            val = min(1.0, val + 0.03)
            self.progress['value'] = val * 100

    def progress_set(self, value: float):
        if USING_CUSTOM:
            self.progress.set(value)
        else:
            self.progress['value'] = value * 100

    def run(self):
        self.root.mainloop()

# ---------------- Entry Point -----------------

def main():
    app = SecurityScanApp()
    app.run()

if __name__ == '__main__':
    main()

