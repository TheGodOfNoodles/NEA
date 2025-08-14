import threading
import queue
import traceback
import webbrowser
from typing import List, Dict

try:
    import customtkinter as ctk
    USING_CUSTOM = True
except ImportError:
    import tkinter as ctk
    from tkinter import ttk, messagebox, filedialog
    USING_CUSTOM = False
else:
    from tkinter import ttk, messagebox, filedialog

from config import CONFIG
from http_client import HTTPClient
from crawler import Crawler, PageData
from scanner.vulnerability import Finding
from scanner.engine import VulnerabilityScanner
from reporting import ReportBuilder

class SecurityScanApp:
    def __init__(self):
        if USING_CUSTOM:
            ctk.set_appearance_mode("System")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = ctk.Tk()
        self.root.title(CONFIG.APP_NAME)
        self.status_queue = queue.Queue()
        self._build_ui()
        self.scanner_thread = None
        self.findings: List[Finding] = []
        self.pages: Dict[str, PageData] = {}
        self.stop_event = threading.Event()
        self.http_client = None
        self.root.after(200, self._poll_status)

    # ---------------- UI Construction ----------------
    def _build_ui(self):
        pad = 8
        frm = ctk.CTkFrame(self.root) if USING_CUSTOM else ctk.Frame(self.root)
        frm.pack(fill='both', expand=True, padx=pad, pady=pad)

        lbl_url = ctk.CTkLabel(frm, text="Target URL:") if USING_CUSTOM else ctk.Label(frm, text="Target URL:")
        lbl_url.grid(row=0, column=0, sticky='w')
        self.entry_url = ctk.CTkEntry(frm, width=420) if USING_CUSTOM else ctk.Entry(frm, width=65)
        self.entry_url.grid(row=0, column=1, sticky='we', columnspan=3, pady=2)

        lbl_depth = ctk.CTkLabel(frm, text="Crawl Depth:") if USING_CUSTOM else ctk.Label(frm, text="Crawl Depth:")
        lbl_depth.grid(row=1, column=0, sticky='w')
        self.depth_var = ctk.StringVar(value='2')
        self.entry_depth = ctk.CTkEntry(frm, width=60, textvariable=self.depth_var) if USING_CUSTOM else ctk.Entry(frm, width=6, textvariable=self.depth_var)
        self.entry_depth.grid(row=1, column=1, sticky='w', pady=2)

        self.btn_scan = ctk.CTkButton(frm, text="Start Scan", command=self.start_scan) if USING_CUSTOM else ctk.Button(frm, text="Start Scan", command=self.start_scan)
        self.btn_scan.grid(row=2, column=0, pady=4, sticky='we')
        self.btn_stop = ctk.CTkButton(frm, text="Stop Scan", state='disabled', command=self.stop_scan) if USING_CUSTOM else ctk.Button(frm, text="Stop Scan", state='disabled', command=self.stop_scan)
        self.btn_stop.grid(row=2, column=1, pady=4, sticky='we')
        self.btn_report = ctk.CTkButton(frm, text="Save Report", state='disabled', command=self.save_report) if USING_CUSTOM else ctk.Button(frm, text="Save Report", state='disabled', command=self.save_report)
        self.btn_report.grid(row=2, column=2, pady=4, sticky='we')
        self.btn_about = ctk.CTkButton(frm, text="Help / About", command=self.show_about) if USING_CUSTOM else ctk.Button(frm, text="Help / About", command=self.show_about)
        self.btn_about.grid(row=2, column=3, pady=4, sticky='we')

        if USING_CUSTOM:
            self.progress = ctk.CTkProgressBar(frm)
            self.progress.set(0)
        else:
            self.progress = ttk.Progressbar(frm, maximum=100)
            self.progress['value'] = 0
        self.progress.grid(row=3, column=0, columnspan=4, sticky='we', pady=6)

        self.status_var = ctk.StringVar(value='Idle')
        self.lbl_status = ctk.CTkLabel(frm, textvariable=self.status_var, anchor='w') if USING_CUSTOM else ctk.Label(frm, textvariable=self.status_var, anchor='w')
        self.lbl_status.grid(row=4, column=0, columnspan=4, sticky='we')

        # Insert filter row (row 5)
        self.search_var = ctk.StringVar(value='')
        self.sev_filter_var = ctk.StringVar(value='All')
        self.export_format_var = ctk.StringVar(value='text')
        lbl_search = ctk.Label(frm, text='Search:') if not USING_CUSTOM else ctk.CTkLabel(frm, text='Search:')
        lbl_search.grid(row=5, column=0, sticky='w')
        self.entry_search = ctk.Entry(frm, textvariable=self.search_var, width=20) if not USING_CUSTOM else ctk.CTkEntry(frm, width=160, textvariable=self.search_var)
        self.entry_search.grid(row=5, column=1, sticky='we')
        # severity filter simple option menu
        sev_opts = ['All', 'High', 'Medium', 'Low']
        if USING_CUSTOM:
            self.sev_menu = ctk.CTkOptionMenu(frm, values=sev_opts, variable=self.sev_filter_var, command=lambda _: self._apply_filters())
        else:
            import tkinter as tk
            self.sev_menu = ctk.OptionMenu(frm, self.sev_filter_var, *sev_opts, command=lambda _: self._apply_filters())
        self.sev_menu.grid(row=5, column=2, sticky='we')
        # export format selector
        fmt_opts = ['text', 'html', 'json', 'csv', 'markdown', 'sarif']
        if USING_CUSTOM:
            self.fmt_menu = ctk.CTkOptionMenu(frm, values=fmt_opts, variable=self.export_format_var)
        else:
            self.fmt_menu = ctk.OptionMenu(frm, self.export_format_var, *fmt_opts)
        self.fmt_menu.grid(row=5, column=3, sticky='we')

        # Results Treeview (moved to row 6 to free row 5 for filters)
        columns = ('severity', 'category', 'location', 'issue')
        self.tree = ttk.Treeview(frm, columns=columns, show='headings', height=14)
        self.tree.heading('severity', text='Severity', command=lambda: self._sort_tree('severity'))
        self.tree.heading('category', text='Category', command=lambda: self._sort_tree('category'))
        self.tree.heading('location', text='Location', command=lambda: self._sort_tree('location'))
        self.tree.heading('issue', text='Issue', command=lambda: self._sort_tree('issue'))
        for col in columns:
            self.tree.column(col, width=120 if col != 'location' else 280, anchor='w')
        vsb = ttk.Scrollbar(frm, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=6, column=0, columnspan=3, sticky='nsew', pady=6)
        vsb.grid(row=6, column=3, sticky='ns')
        frm.rowconfigure(6, weight=1)
        frm.columnconfigure(2, weight=1)

        # Summary & metrics (row 7)
        self.summary_var = ctk.StringVar(value='Summary: -')
        self.metrics_var = ctk.StringVar(value='Metrics: -')
        lbl_summary = ctk.Label(frm, textvariable=self.summary_var, anchor='w') if not USING_CUSTOM else ctk.CTkLabel(frm, textvariable=self.summary_var, anchor='w')
        lbl_summary.grid(row=7, column=0, columnspan=4, sticky='we', pady=(4,0))
        lbl_metrics = ctk.Label(frm, textvariable=self.metrics_var, anchor='w') if not USING_CUSTOM else ctk.CTkLabel(frm, textvariable=self.metrics_var, anchor='w')
        lbl_metrics.grid(row=8, column=0, columnspan=4, sticky='we')

        # Severity tags (colors)
        style = ttk.Style(self.root)
        # Use tag bindings for colors (ttk doesn't directly style rows; use tag_configure via Treeview tag)
        self.tree.tag_configure('sev-High', foreground='#b30000')
        self.tree.tag_configure('sev-Medium', foreground='#d97706')
        self.tree.tag_configure('sev-Low', foreground='#2563eb')

        # Context menu
        self._init_context_menu()
        self.tree.bind('<Button-3>', self._on_right_click)
        # Search bindings
        self.entry_search.bind('<Return>', lambda e: self._apply_filters())

    def _init_context_menu(self):
        import tkinter as tk
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label='Open URL', command=self._ctx_open_url)
        self.ctx_menu.add_command(label='Copy Issue', command=lambda: self._ctx_copy_col('issue'))
        self.ctx_menu.add_command(label='Copy Location', command=lambda: self._ctx_copy_col('location'))
        self.ctx_menu.add_command(label='Copy Row', command=self._ctx_copy_row)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_open_url(self):
        sel = self.tree.selection()
        if not sel:
            return
        loc = self.tree.set(sel[0], 'location')
        webbrowser.open(loc)

    def _ctx_copy_col(self, col):
        sel = self.tree.selection()
        if not sel:
            return
        val = self.tree.set(sel[0], col)
        self.root.clipboard_clear(); self.root.clipboard_append(val)

    def _ctx_copy_row(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], 'values')
        self.root.clipboard_clear(); self.root.clipboard_append('\t'.join(vals))

    # ---------------- Sorting ----------------
    def _sort_tree(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            items.sort()
        except Exception:
            pass
        # toggle
        if getattr(self, '_last_sort', None) == (col, 'asc'):
            items.reverse()
            self._last_sort = (col, 'desc')
        else:
            self._last_sort = (col, 'asc')
        for index, (_, k) in enumerate(items):
            self.tree.move(k, '', index)

    # ---------------- Actions ----------------
    def show_about(self):
        about_text = (f"{CONFIG.APP_NAME} v{CONFIG.VERSION}\n\n" +
                      "Educational scanner for: XSS, SQLi, Headers, Open Redirect, Info Disclosure\n\n" +
                      CONFIG.ETHICAL_WARNING)
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
        self.btn_stop.configure(state='normal')
        self.btn_report.configure(state='disabled')
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.status_var.set('Starting scan...')
        self.progress_set(0)
        self.findings.clear()
        self.pages.clear()
        self.stop_event.clear()
        self.summary_var.set('Summary: -')
        self.metrics_var.set('Metrics: -')
        self.scanner_thread = threading.Thread(target=self._run_scan, args=(url, depth), daemon=True)
        self.scanner_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set('Stopping scan...')
        self.btn_stop.configure(state='disabled')

    def _run_scan(self, url: str, depth: int):
        try:
            self._push_status("Crawling phase started")
            self.http_client = HTTPClient()
            crawler = Crawler(url, depth, self.http_client, status_cb=self._push_status, progress_cb=lambda v: self._push_progress(v * 0.5), stop_event=self.stop_event)
            pages = crawler.crawl()
            self.pages = pages
            if self.stop_event.is_set():
                self._push_status("Scan cancelled after crawling")
                return
            self._push_status("Vulnerability testing phase started")
            scanner = VulnerabilityScanner(self.http_client, status_cb=self._push_status, progress_cb=lambda v: self._push_progress(0.5 + v * 0.5), stop_event=self.stop_event)
            findings = scanner.scan_pages(pages)
            self.findings = findings
            if self.stop_event.is_set():
                self._push_status("Scan stopped")
            else:
                self._push_status("Scan complete")
            self._render_results()
            self._update_summary_and_metrics()
            self._push_status("Ready to save report")
            self.status_queue.put(("enable_report", None))
        except Exception:
            self._push_status("Scan failed: " + traceback.format_exc(limit=1))
        finally:
            self.status_queue.put(("scan_done", None))

    def _render_results(self):
        for f in self.findings:
            self.tree.insert('', 'end', values=(f.severity, f.category, f.location, f.issue), tags=(f'sev-{f.severity}',))

    def _update_summary_and_metrics(self):
        from reporting import ReportBuilder
        rb = ReportBuilder(self.entry_url.get().strip(), self.findings)
        summ = rb.summary()
        self.summary_var.set(f"Summary: High={summ.get('High',0)} Medium={summ.get('Medium',0)} Low={summ.get('Low',0)} RiskScore={summ.get('risk_score',0)} Findings={len(self.findings)}")
        if self.http_client:
            m = self.http_client.metrics()
            self.metrics_var.set(f"Metrics: requests={m['requests']} errors={m['errors']} avg={m['avg_response_time']}s total={m['total_time']}s")

    def save_report(self):
        if not self.findings and not self.pages:
            messagebox.showinfo("No Data", "Run a scan first")
            return
        fmt = self.export_format_var.get()
        ext_map = {
            'text': '.txt', 'html': '.html', 'json': '.json', 'csv': '.csv', 'markdown': '.md', 'sarif': '.sarif'
        }
        default_ext = ext_map.get(fmt, '.txt')
        filetypes = [(fmt.upper(), f"*{default_ext}")]
        from reporting import ReportBuilder
        path = filedialog.asksaveasfilename(defaultextension=default_ext, filetypes=filetypes)
        if not path:
            return
        rb = ReportBuilder(self.entry_url.get().strip(), self.findings)
        try:
            if fmt == 'html':
                content = rb.to_html()
            elif fmt == 'json':
                content = rb.to_json()
            elif fmt == 'csv':
                content = rb.to_csv()
            elif fmt == 'markdown':
                content = rb.to_markdown()
            elif fmt == 'sarif':
                content = rb.to_sarif()
            else:
                content = rb.to_text()
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Report saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    # ---------------- Helpers ----------------
    def _valid_url(self, url: str) -> bool:
        return url.startswith('http://') or url.startswith('https://')

    def _push_status(self, msg: str):
        self.status_queue.put(("status", msg))

    def _push_progress(self, value: float):
        self.status_queue.put(("progress", value))

    def _poll_status(self):
        try:
            while True:
                kind, payload = self.status_queue.get_nowait()
                if kind == 'status':
                    self.status_var.set(payload)
                elif kind == 'progress':
                    self.progress_set(payload)
                elif kind == 'scan_done':
                    self.btn_scan.configure(state='normal')
                    self.btn_stop.configure(state='disabled')
                elif kind == 'enable_report':
                    self.btn_report.configure(state='normal')
        except queue.Empty:
            pass
        self.root.after(300, self._poll_status)

    def progress_set(self, value: float):
        value = max(0.0, min(1.0, value))
        if USING_CUSTOM:
            self.progress.set(value)
        else:
            self.progress['value'] = value * 100

    def _apply_filters(self):
        query = self.search_var.get().lower().strip()
        sev = self.sev_filter_var.get()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for f in self.findings:
            if sev != 'All' and f.severity != sev:
                continue
            blob = f"{f.issue} {f.location} {f.category} {f.evidence}".lower()
            if query and query not in blob:
                continue
            self.tree.insert('', 'end', values=(f.severity, f.category, f.location, f.issue), tags=(f'sev-{f.severity}',))

    def run(self):
        self.root.mainloop()

# Entry helper
def main():
    app = SecurityScanApp()
    app.run()

