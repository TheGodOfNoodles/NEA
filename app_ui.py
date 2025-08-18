import threading
import queue
import traceback
import webbrowser
import json
import os
import re
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

from config import CONFIG, reload_config
from http_client import HTTPClient
from crawler import Crawler, PageData
from scanner.vulnerability import Finding
from scanner.engine import VulnerabilityScanner
from reporting import ReportBuilder

class SecurityScanApp:
    def __init__(self):
        # Attempt to use customtkinter, but gracefully fallback if underlying Tcl/Tk not available
        global USING_CUSTOM, ctk
        if USING_CUSTOM:
            try:
                ctk.set_appearance_mode("System")
                ctk.set_default_color_theme("blue")
                self.root = ctk.CTk()
            except Exception:
                # Fallback to standard tkinter to avoid hard failure in headless / limited envs
                try:
                    import tkinter as tk_fallback
                    from tkinter import ttk, messagebox, filedialog  # ensure symbols loaded
                    USING_CUSTOM = False
                    ctk = tk_fallback  # rebind alias so rest of code uses standard widgets
                    self.root = tk_fallback.Tk()
                except Exception as e:
                    raise RuntimeError(f"Failed to initialize any Tk root: {e}")
        else:
            self.root = ctk.Tk()
        self.root.title(CONFIG.APP_NAME)
        self.status_queue = queue.Queue()
        self._prefs_path = os.path.join(os.getcwd(), 'user_settings.json')
        self.group_mode_var = None
        self._risk_canvas = None
        self._status_log = None
        self._load_prefs_cache = {}
        self.selected_checks: List[str] = []
        self.include_var = None
        self.exclude_var = None
        self.case_sensitive_var = None
        self._build_ui()
        self.scanner_thread = None
        self.findings: List[Finding] = []
        self.pages: Dict[str, PageData] = {}
        self.stop_event = threading.Event()
        self.http_client = None
        self._item_finding_map: Dict[str, Finding] = {}
        self.root.after(200, self._poll_status)
        self._scan_running = False
        # legacy button placeholders
        self.btn_scan = None
        self.btn_stop = None
        self.btn_report = None
        self._settings_cache = {}
        self._fast_mode = False

    # ---------------- UI Construction ----------------
    def _build_ui(self):
        # Rebuild simplified layout
        # Clear existing root children if re-run (defensive)
        for child in self.root.winfo_children():
            try: child.destroy()
            except Exception: pass
        pad = 6
        outer = ctk.CTkFrame(self.root) if USING_CUSTOM else ctk.Frame(self.root)
        outer.pack(fill='both', expand=True)
        # Configure grid responsiveness
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)
        # Menu bar (always at top)
        try:
            menubar = ctk.CTkFrame(self.root) if USING_CUSTOM else None  # customtkinter lacks native menu; fallback to tk menu when not using custom
            if not USING_CUSTOM:
                import tkinter as tk
                m = tk.Menu(self.root)
                app_menu = tk.Menu(m, tearoff=0)
                app_menu.add_command(label='Settings (Ctrl+,)', command=self._open_settings)
                app_menu.add_command(label='Toggle Fast Mode (F9)', command=self._toggle_fast_mode)
                app_menu.add_command(label='Toggle Pipeline (F10)', command=self._toggle_pipeline)
                app_menu.add_separator()
                app_menu.add_command(label='Quit', command=self.root.destroy)
                m.add_cascade(label='App', menu=app_menu)
                self.root.config(menu=m)
        except Exception:
            pass
        # Top controls frame
        top = ctk.CTkFrame(outer) if USING_CUSTOM else ctk.Frame(outer)
        top.grid(row=0, column=0, sticky='we', padx=pad, pady=(pad,4))
        top.columnconfigure(1, weight=1)
        import tkinter as tk
        # URL + Depth + Scan button row
        lbl_url = ctk.CTkLabel(top, text='Target URL:') if USING_CUSTOM else tk.Label(top, text='Target URL:')
        lbl_url.grid(row=0, column=0, sticky='w')
        self.entry_url = ctk.CTkEntry(top) if USING_CUSTOM else tk.Entry(top, width=65)
        self.entry_url.grid(row=0, column=1, sticky='we', padx=(4,6))
        lbl_depth = ctk.CTkLabel(top, text='Depth:') if USING_CUSTOM else tk.Label(top, text='Depth:')
        lbl_depth.grid(row=0, column=2, sticky='e')
        self.depth_var = ctk.StringVar(value='2')
        self.entry_depth = ctk.CTkEntry(top, width=60, textvariable=self.depth_var) if USING_CUSTOM else tk.Entry(top, width=5, textvariable=self.depth_var)
        self.entry_depth.grid(row=0, column=3, sticky='w', padx=(4,8))
        # Stateful scan button
        self.btn_scan_toggle = ctk.CTkButton(top, text='Start Scan', command=self._toggle_scan) if USING_CUSTOM else tk.Button(top, text='Start Scan', command=self._toggle_scan)
        self.btn_scan_toggle.grid(row=0, column=4, padx=(0,6))
        # Export button (single consolidated dialog)
        self.btn_export_dialog = ctk.CTkButton(top, text='Export...', command=self._open_export_dialog) if USING_CUSTOM else tk.Button(top, text='Export...', command=self._open_export_dialog)
        self.btn_export_dialog.grid(row=0, column=5, padx=(0,6))
        self.btn_settings = ctk.CTkButton(top, text='Settings', command=self._open_settings) if USING_CUSTOM else tk.Button(top, text='Settings', command=self._open_settings)
        self.btn_settings.grid(row=0, column=6, padx=(0,6))
        # Shift Help/About to next column
        self.btn_about = ctk.CTkButton(top, text='Help / About', command=self.show_about) if USING_CUSTOM else tk.Button(top, text='Help / About', command=self.show_about)
        self.btn_about.grid(row=0, column=7, padx=(0,0))
        # Progress bar below controls
        if USING_CUSTOM:
            self.progress = ctk.CTkProgressBar(top)
            self.progress.set(0)
        else:
            from tkinter import ttk as _ttk
            self.progress = _ttk.Progressbar(top, maximum=100)
            self.progress['value'] = 0
        # Adjust progress bar span
        self.progress.grid(row=1, column=0, columnspan=8, sticky='we', pady=(6,4))
        # Filter row (condensed)
        filter_frame = ctk.CTkFrame(outer) if USING_CUSTOM else tk.Frame(outer)
        filter_frame.grid(row=1, column=0, sticky='nwe', padx=pad)
        filter_frame.columnconfigure(1, weight=1)
        self.search_var = ctk.StringVar(value='')
        self.sev_filter_var = ctk.StringVar(value='All')
        self.case_sensitive_var = tk.BooleanVar(value=False)
        self.group_mode_var = tk.StringVar(value='None')
        self.include_var = tk.StringVar(value='')
        self.exclude_var = tk.StringVar(value='')
        self.export_format_var = ctk.StringVar(value='text') if USING_CUSTOM else tk.StringVar(value='text')  # kept for backward compat
        lbl_search = ctk.CTkLabel(filter_frame, text='Search:') if USING_CUSTOM else tk.Label(filter_frame, text='Search:')
        lbl_search.grid(row=0, column=0, sticky='w')
        self.entry_search = ctk.CTkEntry(filter_frame, placeholder_text='Search issue, location, parameter...') if USING_CUSTOM else tk.Entry(filter_frame, width=40, textvariable=self.search_var)
        if not USING_CUSTOM:
            self.entry_search.configure(textvariable=self.search_var)
        self.entry_search.grid(row=0, column=1, sticky='we', padx=(4,8))
        lbl_sev = ctk.CTkLabel(filter_frame, text='Severity:') if USING_CUSTOM else tk.Label(filter_frame, text='Severity:')
        lbl_sev.grid(row=0, column=2, sticky='e')
        sev_opts = ['All','High','Medium','Low']
        if USING_CUSTOM:
            self.sev_menu = ctk.CTkOptionMenu(filter_frame, values=sev_opts, variable=self.sev_filter_var, command=lambda _: self._apply_filters())
        else:
            self.sev_menu = tk.OptionMenu(filter_frame, self.sev_filter_var, *sev_opts, command=lambda *_: self._apply_filters())
        self.sev_menu.grid(row=0, column=3, sticky='w', padx=(4,8))
        # create case sensitive checkbox with proper variable binding
        if USING_CUSTOM:
            chk_cs = ctk.CTkCheckBox(filter_frame, text='Case Sensitive', command=self._apply_filters, variable=self.case_sensitive_var)
        else:
            chk_cs = tk.Checkbutton(filter_frame, text='Case Sensitive', variable=self.case_sensitive_var, command=self._apply_filters)
        chk_cs.grid(row=0, column=4, sticky='w', padx=(0,8))
        lbl_group = ctk.CTkLabel(filter_frame, text='Group By:') if USING_CUSTOM else tk.Label(filter_frame, text='Group By:')
        lbl_group.grid(row=0, column=5, sticky='e')
        if USING_CUSTOM:
            self.grp_menu = ctk.CTkOptionMenu(filter_frame, values=['None','Severity','Category'], variable=self.group_mode_var, command=lambda _: self._apply_filters())
        else:
            self.grp_menu = tk.OptionMenu(filter_frame, self.group_mode_var, 'None','Severity','Category', command=lambda *_: self._apply_filters())
        self.grp_menu.grid(row=0, column=6, sticky='w', padx=(4,8))
        # Advanced include/exclude (secondary row)
        lbl_inc = ctk.CTkLabel(filter_frame, text='Include Re:') if USING_CUSTOM else tk.Label(filter_frame, text='Include Re:')
        lbl_inc.grid(row=1, column=0, sticky='w', pady=(4,0))
        ent_inc = ctk.CTkEntry(filter_frame, textvariable=self.include_var, placeholder_text='(Optional) pattern') if USING_CUSTOM else tk.Entry(filter_frame, width=25, textvariable=self.include_var)
        ent_inc.grid(row=1, column=1, sticky='we', padx=(4,8), pady=(4,0))
        lbl_exc = ctk.CTkLabel(filter_frame, text='Exclude Re:') if USING_CUSTOM else tk.Label(filter_frame, text='Exclude Re:')
        lbl_exc.grid(row=1, column=2, sticky='e', pady=(4,0))
        ent_exc = ctk.CTkEntry(filter_frame, textvariable=self.exclude_var, placeholder_text='(Optional) pattern') if USING_CUSTOM else tk.Entry(filter_frame, width=25, textvariable=self.exclude_var)
        ent_exc.grid(row=1, column=3, sticky='we', padx=(4,8), pady=(4,0))
        # Results + details frame
        center = ctk.CTkFrame(outer) if USING_CUSTOM else tk.Frame(outer)
        center.grid(row=2, column=0, sticky='nsew', padx=pad, pady=(4,4))
        center.rowconfigure(1, weight=1)
        center.columnconfigure(0, weight=1)
        # Tree styling
        columns = ('severity','issue','location','category')
        self.tree = ttk.Treeview(center, columns=columns, show='headings', selectmode='extended')
        self.tree.heading('severity', text='Severity', command=lambda: self._sort_tree('severity'))
        self.tree.heading('issue', text='Issue', command=lambda: self._sort_tree('issue'))
        self.tree.heading('location', text='Location', command=lambda: self._sort_tree('location'))
        self.tree.heading('category', text='Category', command=lambda: self._sort_tree('category'))
        self.tree.column('severity', width=90, anchor='w')
        self.tree.column('issue', width=240, anchor='w')
        self.tree.column('location', width=320, anchor='w')
        self.tree.column('category', width=160, anchor='w')
        style = ttk.Style(self.root)
        try:
            style.configure('Treeview', background='#1e1e1e', fieldbackground='#1e1e1e', foreground='#f0f0f0')
            style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        except Exception:
            pass
        vsb = ttk.Scrollbar(center, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        # Finding Details separator
        sep1 = ttk.Separator(center, orient='horizontal') if not USING_CUSTOM else ctk.CTkFrame(center, height=2)
        sep1.grid(row=1, column=0, columnspan=2, sticky='we', pady=(6,4))
        lbl_details = ctk.CTkLabel(center, text='Finding Details:') if USING_CUSTOM else tk.Label(center, text='Finding Details:')
        lbl_details.grid(row=2, column=0, columnspan=2, sticky='w')
        self.detail_text = ctk.CTkTextbox(center, height=120) if USING_CUSTOM else tk.Text(center, height=8, wrap='word')
        self.detail_text.grid(row=3, column=0, columnspan=2, sticky='nsew', pady=(2,2))
        if not USING_CUSTOM:
            self.detail_text.configure(state='disabled')
        center.rowconfigure(3, weight=1)
        # Summary / Metrics separators
        sep2 = ttk.Separator(center, orient='horizontal') if not USING_CUSTOM else ctk.CTkFrame(center, height=2)
        sep2.grid(row=4, column=0, columnspan=2, sticky='we', pady=(6,4))
        self.summary_var = ctk.StringVar(value='Summary: -')
        self.metrics_var = ctk.StringVar(value='Metrics: -')
        lbl_summary = ctk.CTkLabel(center, textvariable=self.summary_var, anchor='w') if USING_CUSTOM else tk.Label(center, textvariable=self.summary_var, anchor='w')
        lbl_summary.grid(row=5, column=0, columnspan=2, sticky='we')
        lbl_metrics = ctk.CTkLabel(center, textvariable=self.metrics_var, anchor='w') if USING_CUSTOM else tk.Label(center, textvariable=self.metrics_var, anchor='w')
        lbl_metrics.grid(row=6, column=0, columnspan=2, sticky='we')
        # Log separator
        sep3 = ttk.Separator(center, orient='horizontal') if not USING_CUSTOM else ctk.CTkFrame(center, height=2)
        sep3.grid(row=7, column=0, columnspan=2, sticky='we', pady=(6,4))
        self._status_log = ctk.CTkTextbox(center, height=110) if USING_CUSTOM else tk.Text(center, height=6, wrap='word')
        self._status_log.grid(row=8, column=0, columnspan=2, sticky='nsew')
        if not USING_CUSTOM:
            self._status_log.configure(state='disabled')
        center.rowconfigure(8, weight=1)
        # Bottom status bar
        status_bar = ctk.CTkFrame(outer) if USING_CUSTOM else tk.Frame(outer, relief='sunken', bd=1)
        status_bar.grid(row=3, column=0, sticky='we')
        self.status_var = ctk.StringVar(value='Ready')
        self.status_label = ctk.CTkLabel(status_bar, textvariable=self.status_var, anchor='w') if USING_CUSTOM else tk.Label(status_bar, textvariable=self.status_var, anchor='w')
        self.status_label.pack(fill='x', padx=4, pady=2)

        # Event bindings & shortcuts
        self.tree.bind('<<TreeviewSelect>>', lambda e: self._update_detail_pane())
        self.entry_search.bind('<KeyRelease>', lambda e: self._apply_filters())
        for w in (ent_inc, ent_exc):
            w.bind('<KeyRelease>', lambda e: self._apply_filters())
        self.root.bind('<Control-s>', lambda e: self._open_export_dialog())
        self.root.bind('<Control-r>', lambda e: self._toggle_scan())
        self.root.bind('<Control-f>', lambda e: self.entry_search.focus_set())
        self.root.bind('<Control-g>', lambda e: self._cycle_group_mode())
        self.root.bind('<Escape>', lambda e: self.stop_scan())
        # Bind hotkeys for settings / fast mode / pipeline
        self.root.bind('<Control-comma>', lambda e: self._open_settings())
        self.root.bind('<F9>', lambda e: self._toggle_fast_mode())
        self.root.bind('<F10>', lambda e: self._toggle_pipeline())
        # Context menu
        self._init_context_menu()
        self.tree.bind('<Button-3>', self._on_right_click)
        # Load prefs
        self._load_prefs()

    # ---------------- Settings Dialog ----------------
    def _open_settings(self):
        import tkinter as tk
        if getattr(self, '_settings_open', False):
            return
        self._settings_open = True
        win = tk.Toplevel(self.root)
        win.title('Settings')
        win.geometry('620x720')
        win.protocol('WM_DELETE_WINDOW', lambda: (setattr(self, '_settings_open', False), win.destroy()))
        frm = tk.Frame(win)
        frm.pack(fill='both', expand=True, padx=10, pady=8)
        entries = {}
        def add_row(r, label, default, width=18):
            tk.Label(frm, text=label).grid(row=r, column=0, sticky='w', pady=2)
            var = tk.StringVar(value=str(default) if default is not None else '')
            ent = tk.Entry(frm, textvariable=var, width=width)
            ent.grid(row=r, column=1, sticky='w', padx=(4,12))
            entries[label] = var
        r = 0
        add_row(r, 'Request Timeout (s)', CONFIG.REQUEST_TIMEOUT); r+=1
        add_row(r, 'Crawl Delay (s)', CONFIG.CRAWL_DELAY); r+=1
        add_row(r, 'Crawl Concurrency', CONFIG.CRAWL_CONCURRENCY); r+=1
        add_row(r, 'Scan Concurrency', CONFIG.SCAN_CONCURRENCY); r+=1
        add_row(r, 'Max Body Size (bytes)', CONFIG.MAX_BODY_SIZE if CONFIG.MAX_BODY_SIZE is not None else ''); r+=1
        add_row(r, 'Progress Interval (s)', CONFIG.PROGRESS_INTERVAL); r+=1
        add_row(r, 'Retries', self._settings_cache.get('retries',2)); r+=1
        add_row(r, 'Max Pages', self._settings_cache.get('max_pages') or ''); r+=1
        add_row(r, 'Include Regex', self.include_var.get() if self.include_var else ''); r+=1
        add_row(r, 'Exclude Regex', self.exclude_var.get() if self.exclude_var else ''); r+=1
        add_row(r, 'User-Agent', CONFIG.USER_AGENT or ''); r+=1
        add_row(r, 'Remove Query Params (comma)', ','.join(sorted(getattr(self, '_remove_params', []))) if hasattr(self,'_remove_params') else 'utm_source,utm_medium,utm_campaign,utm_term,utm_content,gclid,fbclid,ref'); r+=1
        # Multi-line extra XSS payloads
        tk.Label(frm, text='Extra XSS Payloads (newline separated):').grid(row=r, column=0, columnspan=2, sticky='w', pady=(8,2)); r+=1
        xss_txt = tk.Text(frm, height=4, width=48, wrap='word')
        existing_extra = ''
        # compute extras beyond default list
        try:
            default_set = set(["<script>alert('XSS_TEST')</script>","\"'><img src=x onerror=alert(1)>","'><svg/onload=alert(1)>",'" onmouseover=alert(1) x="',"'></textarea><script>alert(1)</script>"])
            extra_list = [p for p in CONFIG.XSS_PAYLOADS if p not in default_set]
            existing_extra = '\n'.join(extra_list)
        except Exception:
            pass
        if existing_extra:
            xss_txt.insert('1.0', existing_extra)
        xss_txt.grid(row=r, column=0, columnspan=2, sticky='we'); r+=1
        # Checkboxes
        bools = {}
        def add_chk(label, value):
            nonlocal r
            var = tk.BooleanVar(value=value)
            tk.Checkbutton(frm, text=label, variable=var).grid(row=r, column=0, columnspan=2, sticky='w', pady=2)
            bools[label] = var
            r += 1
        add_chk('Skip Assets', CONFIG.SKIP_ASSETS)
        add_chk('Skip JS Endpoints', CONFIG.SKIP_JS_ENDPOINTS)
        add_chk('Pipeline Scan', CONFIG.PIPELINE_SCAN)
        add_chk('Respect robots.txt', getattr(self, '_respect_robots', False))
        # Selected checks management
        tk.Label(frm, text='Enabled Checks (comma or * for all):').grid(row=r, column=0, columnspan=2, sticky='w', pady=(8,2)); r+=1
        checks_var = tk.StringVar(value=','.join(self.selected_checks) if self.selected_checks else '*')
        tk.Entry(frm, textvariable=checks_var, width=58).grid(row=r, column=0, columnspan=2, sticky='we'); r+=1
        # Buttons
        btn_frame = tk.Frame(frm); btn_frame.grid(row=r, column=0, columnspan=2, pady=12, sticky='e')
        status_lbl = tk.Label(frm, text='', fg='green'); status_lbl.grid(row=r+1, column=0, columnspan=2, sticky='w')
        def apply_settings():
            try:
                CONFIG.REQUEST_TIMEOUT = int(entries['Request Timeout (s)'].get() or CONFIG.REQUEST_TIMEOUT)
                CONFIG.CRAWL_DELAY = float(entries['Crawl Delay (s)'].get() or 0.0)
                CONFIG.CRAWL_CONCURRENCY = max(1, int(entries['Crawl Concurrency'].get() or CONFIG.CRAWL_CONCURRENCY))
                CONFIG.SCAN_CONCURRENCY = max(1, int(entries['Scan Concurrency'].get() or CONFIG.SCAN_CONCURRENCY))
                mbs_raw = entries['Max Body Size (bytes)'].get().strip(); CONFIG.MAX_BODY_SIZE = int(mbs_raw) if mbs_raw else None
                CONFIG.PROGRESS_INTERVAL = max(0.05, float(entries['Progress Interval (s)'].get() or CONFIG.PROGRESS_INTERVAL))
                retries_raw = entries['Retries'].get().strip(); self._settings_cache['retries'] = int(retries_raw) if retries_raw else 2
                max_pages_raw = entries['Max Pages'].get().strip(); self._settings_cache['max_pages'] = int(max_pages_raw) if max_pages_raw else None
                inc_pat = entries['Include Regex'].get().strip(); exc_pat = entries['Exclude Regex'].get().strip(); self.include_var.set(inc_pat); self.exclude_var.set(exc_pat)
                ua_val = entries['User-Agent'].get().strip();
                if ua_val:
                    CONFIG.USER_AGENT = ua_val
                remove_raw = entries['Remove Query Params (comma)'].get().strip()
                self._remove_params = [p.strip() for p in remove_raw.split(',') if p.strip()] if remove_raw else []
                CONFIG.SKIP_ASSETS = bools['Skip Assets'].get()
                CONFIG.SKIP_JS_ENDPOINTS = bools['Skip JS Endpoints'].get()
                CONFIG.PIPELINE_SCAN = bools['Pipeline Scan'].get()
                self._respect_robots = bools['Respect robots.txt'].get()
                raw_checks = checks_var.get().strip()
                if raw_checks == '*' or not raw_checks:
                    self.selected_checks = []
                else:
                    self.selected_checks = [c.strip() for c in raw_checks.split(',') if c.strip()]
                # Extra XSS payloads merge
                extra_payloads = [ln.strip() for ln in xss_txt.get('1.0','end').splitlines() if ln.strip()]
                if extra_payloads:
                    base_defaults = set(CONFIG.XSS_PAYLOADS)
                    for p in extra_payloads:
                        if p not in base_defaults:
                            CONFIG.XSS_PAYLOADS.append(p)
                status_lbl.configure(text='Saved (applies next scan)', fg='green')
                self._save_prefs()
            except Exception as e:
                status_lbl.configure(text=f'Error: {e}', fg='red')
        def close():
            setattr(self, '_settings_open', False)
            win.destroy()
        tk.Button(btn_frame, text='Apply', command=apply_settings).pack(side='right', padx=4)
        tk.Button(btn_frame, text='Close', command=close).pack(side='right')

    # ------------- Fast / Pipeline toggles -------------
    def _toggle_fast_mode(self):
        if self._scan_running:
            self._ephemeral_status('Cannot toggle Fast Mode during active scan')
            return
        self._fast_mode = not self._fast_mode
        enabled = self._fast_mode
        # Apply fast mode flags
        CONFIG.SKIP_ASSETS = enabled
        CONFIG.SKIP_JS_ENDPOINTS = enabled
        CONFIG.FAST_XSS = enabled
        CONFIG.XSS_MAX_PARALLEL = 4 if enabled else 1
        # Persist
        self._save_prefs()
        self._ephemeral_status(f"Fast Mode {'ON' if enabled else 'OFF'}")

    def _toggle_pipeline(self):
        if self._scan_running:
            self._ephemeral_status('Cannot toggle Pipeline during active scan')
            return
        CONFIG.PIPELINE_SCAN = not CONFIG.PIPELINE_SCAN
        self._save_prefs()
        self._ephemeral_status(f"Pipeline {'ON' if CONFIG.PIPELINE_SCAN else 'OFF'}")

    # ---------------- Actions ----------------
    def show_about(self):
        about_text = (f"{CONFIG.APP_NAME} v{CONFIG.VERSION}\n\n" +
                      "Educational scanner for: XSS, SQLi, Headers, Open Redirect, Info Disclosure\n\n" +
                      CONFIG.ETHICAL_WARNING)
        messagebox.showinfo("About", about_text)

    def stop_scan(self):
        if not self._scan_running:
            return
        self.stop_event.set()
        self.status_var.set('Stopping scan...')

    def _toggle_scan(self):
        if not self._scan_running:
            # start scan
            if self.scanner_thread and self.scanner_thread.is_alive():
                return
            url = self.entry_url.get().strip()
            if not self._valid_url(url):
                from tkinter import messagebox
                messagebox.showerror('Invalid URL', 'Enter a valid http(s) URL')
                return
            try:
                depth = int(self.depth_var.get())
            except ValueError:
                from tkinter import messagebox
                messagebox.showerror('Invalid Depth', 'Depth must be a number')
                return
            self._scan_running = True
            self.btn_scan_toggle.configure(text='Stop Scan')
            self.status_var.set('Starting scan...')
            self.progress_set(0)
            self.findings.clear(); self.pages.clear(); self.summary_var.set('Summary: -'); self.metrics_var.set('Metrics: -')
            self.stop_event.clear()
            self.scanner_thread = threading.Thread(target=self._run_scan, args=(url, depth), daemon=True)
            self.scanner_thread.start()
        else:
            self.stop_scan()

    # ---------------- Actions ----------------
    def _run_scan(self, url: str, depth: int):
        try:
            self._push_status('Crawling phase started')
            self.http_client = HTTPClient()
            retries = self._settings_cache.get('retries', 2)
            max_pages = self._settings_cache.get('max_pages')
            include_re = self.include_var.get().strip() or None
            exclude_re = self.exclude_var.get().strip() or None
            remove_params = getattr(self, '_remove_params', None)
            pipeline = CONFIG.PIPELINE_SCAN
            scanner = None
            if pipeline:
                scanner = VulnerabilityScanner(self.http_client, status_cb=self._push_status, progress_cb=lambda v: self._push_progress(0.5 * v), stop_event=self.stop_event, enabled_checks=(self.selected_checks if self.selected_checks else None))
            crawler = Crawler(url, depth, self.http_client, status_cb=self._push_status, progress_cb=(lambda v: self._push_progress(0.5 * v if pipeline else v * 0.5)), stop_event=self.stop_event,
                              include_re=include_re, exclude_re=exclude_re, retries=retries, max_pages=max_pages,
                              remove_query_params=remove_params, respect_robots=getattr(self,'_respect_robots', False), scanner=scanner)
            pages = crawler.crawl()
            self.pages = pages
            if self.stop_event.is_set():
                self._push_status('Scan cancelled after crawling')
                return
            if pipeline and scanner:
                self._push_status('Finalizing pipeline scan')
                scanner.scan_pages(pages)
                findings = scanner.findings
                self._push_progress(1.0)
            else:
                self._push_status('Vulnerability testing phase started')
                scanner2 = VulnerabilityScanner(self.http_client, status_cb=self._push_status, progress_cb=lambda v: self._push_progress(0.5 + v * 0.5), stop_event=self.stop_event, enabled_checks=(self.selected_checks if self.selected_checks else None))
                findings = scanner2.scan_pages(pages)
            self.findings = findings
            if self.stop_event.is_set():
                self._push_status('Scan stopped')
            else:
                self._push_status('Scan complete')
            self._render_results(); self._update_summary_and_metrics(); self._push_status('Ready to export'); self.status_queue.put(('enable_report', None))
        except Exception:
            self._push_status('Scan failed: ' + traceback.format_exc(limit=1))
        finally:
            self.status_queue.put(('scan_done', None)); self._scan_running = False
            try: self.btn_scan_toggle.configure(text='Start Scan')
            except Exception: pass

    def _render_results(self):
        self._apply_filters()
        if not hasattr(self, '_dbl_bind'):
            self.tree.bind('<Double-1>', self._on_double_click)
            self._dbl_bind = True

    def _update_summary_and_metrics(self):
        from reporting import ReportBuilder
        rb = ReportBuilder(self.entry_url.get().strip(), self.findings)
        summ = rb.summary()
        self.summary_var.set(f"Summary: High: {summ.get('High',0)} | Medium: {summ.get('Medium',0)} | Low: {summ.get('Low',0)} | Total Findings: {len(self.findings)} | RiskScore: {summ.get('risk_score',0)}")
        if self.http_client:
            m = self.http_client.metrics()
            self.metrics_var.set(f"Metrics: Requests: {m['requests']} | Errors: {m['errors']} | Avg: {m['avg_response_time']}s | Total: {m['total_time']}s")
        self._save_prefs()

    def save_report(self):
        if not self.findings and not self.pages:
            messagebox.showinfo("No Data", "Run a scan first")
            return
        fmt = self.export_format_var.get()
        ext_map = {'text':'.txt','html':'.html','json':'.json','csv':'.csv','markdown':'.md','sarif':'.sarif'}
        default_ext = ext_map.get(fmt,'.txt')
        filetypes=[(fmt.upper(), f"*{default_ext}")]
        from reporting import ReportBuilder
        path = filedialog.asksaveasfilename(defaultextension=default_ext, filetypes=filetypes)
        if not path: return
        rb = ReportBuilder(self.entry_url.get().strip(), self.findings)
        try:
            if fmt=='html': content=rb.to_html()
            elif fmt=='json': content=rb.to_json()
            elif fmt=='csv': content=rb.to_csv()
            elif fmt=='markdown': content=rb.to_markdown()
            elif fmt=='sarif': content=rb.to_sarif()
            else: content=rb.to_text()
            with open(path,'w',encoding='utf-8') as f: f.write(content)
            self._ephemeral_status(f"Report saved: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    def quick_export(self):
        from reporting import ReportBuilder
        fmt = self.export_format_var.get()
        mode = self.group_mode_var.get() if self.group_mode_var else 'None'
        findings = []
        for iid in self.tree.get_children(''):
            if mode in ('Severity','Category') and iid not in self._item_finding_map:
                for c in self.tree.get_children(iid):
                    f = self._item_finding_map.get(c)
                    if f: findings.append(f)
            else:
                f = self._item_finding_map.get(iid)
                if f: findings.append(f)
        rb = ReportBuilder(self.entry_url.get().strip() or 'N/A', findings)
        if fmt=='html': content=rb.to_html()
        elif fmt=='json': content=rb.to_json()
        elif fmt=='csv': content=rb.to_csv()
        elif fmt=='markdown': content=rb.to_markdown()
        elif fmt=='sarif': content=rb.to_sarif()
        else: content=rb.to_text()
        fname = f"quick_report.{fmt if fmt!='text' else 'txt'}"
        try:
            with open(fname,'w',encoding='utf-8') as f: f.write(content)
            self._ephemeral_status(f"Quick export: {fname}")
        except Exception as e:
            self._ephemeral_status(f"Export failed: {e}")

    # ---------------- Helpers ----------------
    def _valid_url(self, url: str) -> bool:
        return url.startswith('http://') or url.startswith('https://')

    def _push_status(self, msg: str):
        self.status_queue.put(("status", msg))
        self._append_status_log(msg)

    def _append_status_log(self, line: str):
        if not self._status_log:
            return
        if USING_CUSTOM:
            self._status_log.configure(state='normal')
            self._status_log.insert('end', line + "\n")
            self._status_log.see('end')
            self._status_log.configure(state='disabled')
        else:
            self._status_log.configure(state='normal')
            self._status_log.insert('end', line + "\n")
            self._status_log.see('end')
            self._status_log.configure(state='disabled')

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
                    # re-enable toggle button
                    try:
                        self.btn_scan_toggle.configure(state='normal')
                    except Exception: pass
                elif kind == 'enable_report':
                    try:
                        self.btn_export_dialog.configure(state='normal')
                    except Exception: pass
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
        query = self.search_var.get().strip()
        tokens, free = self._parse_advanced_query(query)
        sev_filter = self.sev_filter_var.get()
        inc_pat = self.include_var.get().strip() if self.include_var else ''
        exc_pat = self.exclude_var.get().strip() if self.exclude_var else ''
        inc_re = None; exc_re = None
        try:
            if inc_pat: inc_re = re.compile(inc_pat, re.IGNORECASE)
        except Exception: inc_re = None
        try:
            if exc_pat: exc_re = re.compile(exc_pat, re.IGNORECASE)
        except Exception: exc_re = None
        self._clear_tree()
        mode = self.group_mode_var.get() if self.group_mode_var else 'None'
        parents = {}
        sev_icons = {'High':'🔥 High','Medium':'⚠️ Medium','Low':'ℹ️ Low'}
        for f in self.findings:
            if sev_filter != 'All' and f.severity != sev_filter:
                continue
            if not self._matches_filter(f, tokens, free):
                continue
            blob = f"{f.issue} {f.location} {f.category} {f.evidence} {f.description} {f.recommendation} {f.parameter} {f.payload}" if self.case_sensitive_var.get() else f"{f.issue} {f.location} {f.category} {f.evidence} {f.description} {f.recommendation} {f.parameter} {f.payload}".lower()
            if inc_re and not inc_re.search(blob):
                continue
            if exc_re and exc_re.search(blob):
                continue
            parent_iid = ''
            if mode in ('Severity','Category'):
                key = f.severity if mode=='Severity' else f.category
                if key not in parents:
                    parents[key] = self.tree.insert('', 'end', values=(key,'','',''), text=key, open=True)
                parent_iid = parents[key]
            sev_val = sev_icons.get(f.severity, f.severity)
            iid = self.tree.insert(parent_iid, 'end', values=(sev_val, f.issue, f.location, f.category), tags=(f'sev-'+f.severity,))
            self._item_finding_map[iid] = f
        self._update_detail_pane()
        # risk chart removed

    def _clear_tree(self):
        if not hasattr(self, 'tree'):
            return
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._item_finding_map.clear()

    # Backward compatibility public wrappers (legacy callbacks may reference these)
    def clear_tree(self):  # legacy name
        self._clear_tree()

    def apply_filters(self):  # legacy name
        self._apply_filters()

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

    def _open_export_dialog(self):
        import tkinter as tk
        from tkinter import filedialog, messagebox
        if not self.findings:
            messagebox.showinfo('No Findings', 'Nothing to export yet.')
            return
        win = tk.Toplevel(self.root)
        win.title('Export Findings')
        win.geometry('360x260')
        scope_var = tk.StringVar(value='all')
        fmt_var = tk.StringVar(value=self.export_format_var.get())
        tk.Label(win, text='Scope:').pack(anchor='w', padx=8, pady=(8,2))
        for val, label in [('all','All Findings'),('filtered','Filtered View'),('selection','Current Selection')]:
            tk.Radiobutton(win, text=label, variable=scope_var, value=val).pack(anchor='w', padx=16)
        tk.Label(win, text='Format:').pack(anchor='w', padx=8, pady=(8,2))
        fmt_box = tk.OptionMenu(win, fmt_var, 'text','html','json','csv','markdown','sarif')
        fmt_box.pack(anchor='w', padx=16)
        path_var = tk.StringVar(value='')
        def choose_path():
            ext_map = {'text':'.txt','html':'.html','json':'.json','csv':'.csv','markdown':'.md','sarif':'.sarif'}
            default_ext = ext_map.get(fmt_var.get(), '.txt')
            p = filedialog.asksaveasfilename(defaultextension=default_ext, filetypes=[(fmt_var.get().upper(), f"*{default_ext}")])
            if p:
                path_var.set(p)
        tk.Button(win, text='Browse...', command=choose_path).pack(anchor='w', padx=16, pady=(8,2))
        tk.Label(win, textvariable=path_var, wraplength=320, fg='gray').pack(anchor='w', padx=16)
        def do_export():
            path = path_var.get().strip()
            if not path:
                messagebox.showerror('Path Required', 'Choose export destination.')
                return
            self.export_format_var.set(fmt_var.get())  # sync for legacy methods
            from reporting import ReportBuilder
            # Determine findings list
            if scope_var.get() == 'all':
                data = self.findings
            elif scope_var.get() == 'selection':
                sels = self.tree.selection()
                data = [self._item_finding_map[i] for i in sels if i in self._item_finding_map]
                if not data:
                    messagebox.showinfo('Empty Selection', 'No selected findings to export.')
                    return
            else:  # filtered
                # Reconstruct filtered list from current tree view leaves
                data = []
                for iid in self.tree.get_children(''):
                    if iid in self._item_finding_map:
                        data.append(self._item_finding_map[iid])
                    else:
                        for c in self.tree.get_children(iid):
                            if c in self._item_finding_map:
                                data.append(self._item_finding_map[c])
            rb = ReportBuilder(self.entry_url.get().strip() or 'N/A', data)
            fmt = fmt_var.get()
            if fmt=='html': content=rb.to_html()
            elif fmt=='json': content=rb.to_json()
            elif fmt=='csv': content=rb.to_csv()
            elif fmt=='markdown': content=rb.to_markdown()
            elif fmt=='sarif': content=rb.to_sarif()
            else: content=rb.to_text()
            try:
                with open(path,'w',encoding='utf-8') as f: f.write(content)
                self._ephemeral_status(f'Exported {len(data)} findings to {path}')
                win.destroy()
            except Exception as e:
                messagebox.showerror('Export Failed', str(e))
        tk.Button(win, text='Export', command=do_export).pack(anchor='e', padx=16, pady=8)

    # ---------------- Context Menu ----------------
    def _init_context_menu(self):
        import tkinter as tk
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label='Open URL', command=self._ctx_open_url)
        self.ctx_menu.add_command(label='Copy Issue', command=lambda: self._ctx_copy_col('issue'))
        self.ctx_menu.add_command(label='Copy Location', command=lambda: self._ctx_copy_col('location'))
        self.ctx_menu.add_command(label='Copy Row', command=self._ctx_copy_row)
        self.ctx_menu.add_command(label='Copy Selection', command=self._ctx_copy_selection)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label='Details', command=self._ctx_show_details)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_open_url(self):
        sel = self.tree.selection()
        if not sel: return
        loc = self.tree.set(sel[0], 'location')
        webbrowser.open(loc)

    def _ctx_copy_col(self, col):
        sel = self.tree.selection();
        if not sel: return
        val = self.tree.set(sel[0], col)
        self.root.clipboard_clear(); self.root.clipboard_append(val)

    def _ctx_copy_row(self):
        sel = self.tree.selection();
        if not sel: return
        vals = self.tree.item(sel[0], 'values'); self.root.clipboard_clear(); self.root.clipboard_append('\t'.join(vals))

    def _ctx_copy_selection(self):
        sels = self.tree.selection(); rows=[]
        for iid in sels:
            vals = self.tree.item(iid,'values')
            if vals: rows.append('\t'.join(vals))
        if rows:
            self.root.clipboard_clear(); self.root.clipboard_append('\n'.join(rows))

    def _ctx_show_details(self):
        sel = self.tree.selection();
        if not sel: return
        f = self._item_finding_map.get(sel[0])
        if f: self._show_finding_details(f)

    def _on_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid: return
        f = self._item_finding_map.get(iid)
        if f: self._show_finding_details(f)

    def _show_finding_details(self, f: Finding):
        import tkinter as tk
        try:
            from tkinter import scrolledtext
            use = True
        except Exception:
            use = False
        win = tk.Toplevel(self.root)
        win.title(f"Details: {f.issue}")
        win.geometry('620x500')
        tk.Label(win, text=f"[{f.severity}] {f.issue}", font=('Arial',12,'bold')).pack(anchor='w', padx=8, pady=(8,4))
        parts = [
            f"Category: {f.category}",
            f"Location: {f.location}",
            f"Parameter: {f.parameter or '-'}",
            f"Payload: {f.payload or '-'}",
            f"Evidence: {f.evidence}",
            f"Risk: {f.risk}",
            f"Description: {f.description}",
            f"Recommendation: {f.recommendation}",
            "References:" if f.references else "References: -"
        ] + (["  - "+r for r in f.references] if f.references else [])
        blob = '\n'.join(parts)
        if use:
            txt = scrolledtext.ScrolledText(win, wrap='word')
        else:
            txt = tk.Text(win, wrap='word')
        txt.pack(fill='both', expand=True, padx=8, pady=4)
        txt.insert('1.0', blob)
        txt.configure(state='disabled')
        tk.Button(win, text='Close', command=win.destroy).pack(pady=6)

    def _set_sev_filter(self, sev):
        self.sev_filter_var.set(sev)
        self._apply_filters()

    def _choose_checks(self):
        import tkinter as tk
        win = tk.Toplevel(self.root)
        win.title('Select Checks')
        win.geometry('260x360')
        from scanner.engine import VulnerabilityScanner
        temp_engine = VulnerabilityScanner(HTTPClient())
        all_checks = sorted([c.name for c in temp_engine.check_classes])
        vars_map = {}
        frame = tk.Frame(win); frame.pack(fill='both', expand=True)
        for name in all_checks:
            var = tk.BooleanVar(value=(not self.selected_checks) or (name in self.selected_checks))
            cb = tk.Checkbutton(frame, text=name, variable=var)
            cb.pack(anchor='w')
            vars_map[name] = var
        def apply_close():
            self.selected_checks = [n for n,v in vars_map.items() if v.get()]
            win.destroy()
        tk.Button(win, text='Apply', command=apply_close).pack(pady=4)

    def _retest_selected(self):
        if not self.http_client or not self.pages:
            return
        sels = self.tree.selection()
        targets = set()
        for iid in sels:
            f = self._item_finding_map.get(iid)
            if f:
                for url in self.pages.keys():
                    if f.location.startswith(url):
                        targets.add(url); break
        if not targets:
            return
        subset = {u:self.pages[u] for u in targets if u in self.pages}
        scanner = VulnerabilityScanner(self.http_client, status_cb=self._push_status, enabled_checks=(self.selected_checks if self.selected_checks else None))
        new_findings = scanner.scan_pages(subset)
        existing_keys = {(f.issue, f.location, f.evidence) for f in self.findings}
        added = 0
        for f in new_findings:
            k = (f.issue, f.location, f.evidence)
            if k not in existing_keys:
                self.findings.append(f); existing_keys.add(k); added += 1
        self._render_results()
        self._update_summary_and_metrics()
        self._push_status(f"Re-test added {added} findings")

    def _export_selection(self):
        sels = self.tree.selection()
        if not sels:
            self._ephemeral_status('No selection to export')
            return
        selected = [self._item_finding_map[iid] for iid in sels if iid in self._item_finding_map]
        # Fallback: if selection corresponds to group parent(s), collect their leaf children
        if not selected:
            leaf_candidates = []
            for parent in sels:
                for child in self.tree.get_children(parent):
                    f = self._item_finding_map.get(child)
                    if f:
                        leaf_candidates.append(f)
            selected = leaf_candidates
        if not selected:
            self._ephemeral_status('No leaf findings selected')
            return
        from reporting import ReportBuilder
        rb = ReportBuilder(self.entry_url.get().strip(), selected)
        fmt = self.export_format_var.get()
        if fmt == 'html': content = rb.to_html()
        elif fmt == 'json': content = rb.to_json()
        elif fmt == 'csv': content = rb.to_csv()
        elif fmt == 'markdown': content = rb.to_markdown()
        elif fmt == 'sarif': content = rb.to_sarif()
        else: content = rb.to_text()
        fname = f"selection_report.{fmt if fmt!='text' else 'txt'}"
        with open(fname,'w',encoding='utf-8') as fh: fh.write(content)
        self._ephemeral_status(f"Selection exported: {fname}")

    def _save_prefs(self):
        try:
            data = {
                'last_url': self.entry_url.get().strip(),
                'depth': self.depth_var.get(),
                'format': self.export_format_var.get(),
                'group_mode': self.group_mode_var.get() if self.group_mode_var else 'None',
                'geometry': self.root.geometry(),
                'selected_checks': self.selected_checks,
                'include_re': self.include_var.get() if self.include_var else '',
                'exclude_re': self.exclude_var.get() if self.exclude_var else '',
                'request_timeout': CONFIG.REQUEST_TIMEOUT,
                'crawl_delay': CONFIG.CRAWL_DELAY,
                'crawl_concurrency': CONFIG.CRAWL_CONCURRENCY,
                'scan_concurrency': CONFIG.SCAN_CONCURRENCY,
                'max_body_size': CONFIG.MAX_BODY_SIZE,
                'progress_interval': CONFIG.PROGRESS_INTERVAL,
                'skip_assets': CONFIG.SKIP_ASSETS,
                'skip_js': CONFIG.SKIP_JS_ENDPOINTS,
                'pipeline_scan': CONFIG.PIPELINE_SCAN,
                'retries': self._settings_cache.get('retries',2),
                'max_pages': self._settings_cache.get('max_pages'),
                'user_agent': CONFIG.USER_AGENT,
                'respect_robots': getattr(self,'_respect_robots', False),
                'remove_query_params': getattr(self,'_remove_params', []),
            }
            with open(self._prefs_path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            pass

    def _load_prefs(self):
        try:
            if os.path.exists(self._prefs_path):
                with open(self._prefs_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if data.get('last_url'):
                    self.entry_url.delete(0, 'end'); self.entry_url.insert(0, data['last_url'])
                if data.get('depth'): self.depth_var.set(data['depth'])
                if data.get('format'): self.export_format_var.set(data['format'])
                if self.group_mode_var and 'group_mode' in data: self.group_mode_var.set(data['group_mode'])
                if 'selected_checks' in data: self.selected_checks = data['selected_checks']
                if self.include_var and data.get('include_re') is not None: self.include_var.set(data.get('include_re',''))
                if self.exclude_var and data.get('exclude_re') is not None: self.exclude_var.set(data.get('exclude_re',''))
                if data.get('geometry'): self.root.geometry(data['geometry'])
                # Restore runtime config fields
                if 'request_timeout' in data: CONFIG.REQUEST_TIMEOUT = data['request_timeout']
                if 'crawl_delay' in data: CONFIG.CRAWL_DELAY = data['crawl_delay']
                if 'crawl_concurrency' in data: CONFIG.CRAWL_CONCURRENCY = data['crawl_concurrency']
                if 'scan_concurrency' in data: CONFIG.SCAN_CONCURRENCY = data['scan_concurrency']
                if 'max_body_size' in data: CONFIG.MAX_BODY_SIZE = data['max_body_size']
                if 'progress_interval' in data: CONFIG.PROGRESS_INTERVAL = data['progress_interval']
                if 'skip_assets' in data: CONFIG.SKIP_ASSETS = data['skip_assets']
                if 'skip_js' in data: CONFIG.SKIP_JS_ENDPOINTS = data['skip_js']
                if 'pipeline_scan' in data: CONFIG.PIPELINE_SCAN = data['pipeline_scan']
                if 'retries' in data: self._settings_cache['retries'] = data['retries']
                if 'max_pages' in data: self._settings_cache['max_pages'] = data['max_pages']
                if 'user_agent' in data and data['user_agent']:
                    CONFIG.USER_AGENT = data['user_agent']
                if 'respect_robots' in data:
                    self._respect_robots = data['respect_robots']
                if 'remove_query_params' in data:
                    self._remove_params = data['remove_query_params']
                if 'fast_mode' in data:
                    self._fast_mode = data['fast_mode']
                    if self._fast_mode:
                        # reapply fast flags on load
                        CONFIG.SKIP_ASSETS = True
                        CONFIG.SKIP_JS_ENDPOINTS = True
                        CONFIG.FAST_XSS = True
                        CONFIG.XSS_MAX_PARALLEL = max(CONFIG.XSS_MAX_PARALLEL, 4)
        except Exception:
            pass

    def _cycle_group_mode(self):
        order = ['None','Severity','Category']
        cur = self.group_mode_var.get() if self.group_mode_var else 'None'
        try:
            idx = order.index(cur)
        except ValueError:
            idx = 0
        nxt = order[(idx+1)%len(order)]
        if self.group_mode_var:
            self.group_mode_var.set(nxt)
            self._apply_filters()

    def _update_detail_pane(self):
        if not hasattr(self, 'detail_text'):
            return
        sels = self.tree.selection()
        lines = []
        for iid in sels:
            f = self._item_finding_map.get(iid)
            if not f:
                continue
            lines.append(f"[{f.severity}] {f.issue}\nLocation: {f.location}\nCategory: {f.category}\nParameter: {f.parameter or '-'}\nPayload: {f.payload or '-'}\nEvidence: {f.evidence}\nRisk: {f.risk}\nDescription: {f.description}\nRecommendation: {f.recommendation}\nReferences: {'; '.join(f.references) if f.references else '-'}\n---")
        text_blob = "\n".join(lines) if lines else "(No selection)"
        if USING_CUSTOM:
            self.detail_text.configure(state='normal')
            self.detail_text.delete('1.0', 'end')
            self.detail_text.insert('1.0', text_blob)
            self.detail_text.configure(state='disabled')
        else:
            self.detail_text.configure(state='normal')
            self.detail_text.delete('1.0', 'end')
            self.detail_text.insert('1.0', text_blob)
            self.detail_text.configure(state='disabled')

    def _ephemeral_status(self, msg: str):
        self.status_var.set(msg)
        # auto-reset after delay
        try:
            self.root.after(4000, lambda: self.status_var.set('Ready'))
        except Exception:
            pass

    def run(self):
        """Start the Tk main event loop."""
        try:
            self.root.mainloop()
        finally:
            pass


    def _parse_advanced_query(self, query: str):
        """Parse simple key:value tokens out of the search box.
        Returns (tokens_dict, free_text_lowercase)
        Supported keys map directly to Finding attributes: sev,severity,issue,loc,location,cat,category,param,parameter,payload,risk,evidence.
        Anything without a colon is treated as free text (space joined)."""
        tokens = {}
        free_parts = []
        for part in query.split():
            if ':' in part:
                k, v = part.split(':', 1)
                k = k.strip().lower(); v = v.strip()
                if k and v:
                    tokens[k] = v
            else:
                free_parts.append(part)
        free_text = ' '.join(free_parts)
        return tokens, free_text

    def _matches_filter(self, finding: Finding, tokens: dict, free_text: str) -> bool:
        if not tokens and not free_text:
            return True
        # attribute map
        attr_map = {
            'severity': finding.severity,
            'sev': finding.severity,
            'issue': finding.issue,
            'location': finding.location,
            'loc': finding.location,
            'category': finding.category,
            'cat': finding.category,
            'parameter': finding.parameter,
            'param': finding.parameter,
            'payload': finding.payload,
            'risk': finding.risk,
            'evidence': finding.evidence,
        }
        cs = self.case_sensitive_var.get() if self.case_sensitive_var else False
        for k, needle in tokens.items():
            hay = attr_map.get(k)
            if hay is None:
                return False
            if not cs:
                hay = hay.lower(); needle_cmp = needle.lower()
            else:
                needle_cmp = needle
            if needle_cmp not in hay:
                return False
        if free_text:
            blob = f"{finding.issue} {finding.location} {finding.category} {finding.parameter} {finding.payload} {finding.evidence} {finding.risk}"
            if not cs:
                blob = blob.lower(); search = free_text.lower()
            else:
                search = free_text
            for term in search.split():
                if term not in blob:
                    return False
        return True

def main():  # convenience for console_scripts / main entry
    app = SecurityScanApp()
    app.run()

if __name__ == '__main__':
    main()
