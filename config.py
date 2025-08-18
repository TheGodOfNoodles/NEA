from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import os, json

CONFIG_PATH = os.getenv('NEA_USER_SETTINGS', 'user_settings.json')

@dataclass
class Config:
    APP_NAME: str = "Simple Web Security Scanner"
    VERSION: str = "0.2.0"
    ETHICAL_WARNING: str = (
        "Use only on sites you own or have explicit written permission to test. Unauthorized testing may be illegal."
    )
    REQUEST_TIMEOUT: int = 10
    USER_AGENT: str = ""
    XSS_PAYLOADS: List[str] = field(default_factory=list)
    SQL_ERRORS: List[str] = field(default_factory=list)
    CRAWL_DELAY: float = 0.0  # politeness delay seconds between requests
    INCLUDE_RE: str = ""
    EXCLUDE_RE: str = ""
    CRAWL_CONCURRENCY: int = 1
    SCAN_CONCURRENCY: int = 1
    MAX_BODY_SIZE: Optional[int] = None  # if set, truncate stored body to this many bytes
    PROGRESS_INTERVAL: float = 0.5  # minimum seconds between progress callback emissions
    SKIP_ASSETS: bool = False       # skip collecting img/script/link assets
    SKIP_JS_ENDPOINTS: bool = False # skip inline JS endpoint extraction
    PIPELINE_SCAN: bool = False     # enable crawl+scan pipelining when scanner provided
    FAST_XSS: bool = False          # limit XSS payloads for speed if enabled
    XSS_MAX_PARALLEL: int = 1       # per-page parallel XSS payload attempts

    def apply_overrides(self):
        # Environment variable overrides
        self.REQUEST_TIMEOUT = int(os.getenv("SCANNER_REQUEST_TIMEOUT", self.REQUEST_TIMEOUT))
        self.CRAWL_DELAY = float(os.getenv("SCANNER_CRAWL_DELAY", self.CRAWL_DELAY))
        self.INCLUDE_RE = os.getenv('SCANNER_INCLUDE_RE', self.INCLUDE_RE)
        self.EXCLUDE_RE = os.getenv('SCANNER_EXCLUDE_RE', self.EXCLUDE_RE)
        self.CRAWL_CONCURRENCY = int(os.getenv('SCANNER_CRAWL_CONCURRENCY', self.CRAWL_CONCURRENCY))
        self.SCAN_CONCURRENCY = int(os.getenv('SCANNER_SCAN_CONCURRENCY', self.SCAN_CONCURRENCY))
        max_body_env = os.getenv('SCANNER_MAX_BODY_SIZE')
        if max_body_env is not None:
            try:
                self.MAX_BODY_SIZE = int(max_body_env) if max_body_env.strip() else None
            except ValueError:
                pass
        # progress interval override
        prog_env = os.getenv('SCANNER_PROGRESS_INTERVAL')
        if prog_env:
            try:
                self.PROGRESS_INTERVAL = max(0.05, float(prog_env))
            except ValueError:
                pass
        # performance feature toggles
        self.SKIP_ASSETS = os.getenv('SCANNER_SKIP_ASSETS','0') in ('1','true','True')
        self.SKIP_JS_ENDPOINTS = os.getenv('SCANNER_SKIP_JS_ENDPOINTS','0') in ('1','true','True')
        self.PIPELINE_SCAN = os.getenv('SCANNER_PIPELINE_SCAN','0') in ('1','true','True')
        self.FAST_XSS = os.getenv('SCANNER_FAST_XSS','0') in ('1','true','True')
        ua_suffix = os.getenv("SCANNER_UA_SUFFIX", "")
        if not self.USER_AGENT:
            self.USER_AGENT = f"{self.APP_NAME}/{self.VERSION} (Educational Scanner){' '+ua_suffix if ua_suffix else ''}".strip()
        extra_xss = os.getenv("SCANNER_EXTRA_XSS", "")
        if extra_xss:
            for p in extra_xss.split("||"):
                p = p.strip()
                if p and p not in self.XSS_PAYLOADS:
                    self.XSS_PAYLOADS.append(p)
        self.XSS_MAX_PARALLEL = int(os.getenv('SCANNER_XSS_MAX_PARALLEL', self.XSS_MAX_PARALLEL))

    def apply_user_settings(self, data: Dict[str, Any]):
        # only apply recognized keys to avoid accidental override of complex structures
        for k in ('REQUEST_TIMEOUT','INCLUDE_RE','EXCLUDE_RE'):
            if k.lower() in data:
                setattr(self, k, data[k.lower()])


def _default_config() -> Config:
    cfg = Config(
        XSS_PAYLOADS=[
            "<script>alert('XSS_TEST')</script>",
            "\"'><img src=x onerror=alert(1)>",
            "'><svg/onload=alert(1)>",
            '" onmouseover=alert(1) x="',
            "'></textarea><script>alert(1)</script>",
        ],
        SQL_ERRORS=[
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sql server",
            "sqlite error",
            "psql:",
        ],
    )
    # Attempt to load user settings for regex include/exclude defaults
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH,'r',encoding='utf-8') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                # Legacy keys in user settings may use include_re / exclude_re
                if 'include_re' in data:
                    cfg.INCLUDE_RE = data['include_re']
                if 'exclude_re' in data:
                    cfg.EXCLUDE_RE = data['exclude_re']
    except Exception:
        pass
    cfg.apply_overrides()
    return cfg

CONFIG = _default_config()


def reload_config():
    global CONFIG
    new_cfg = _default_config()
    # Mutate existing object so imported references remain valid
    if CONFIG is not None:
        CONFIG.__dict__.update(new_cfg.__dict__)
        return CONFIG
    CONFIG = new_cfg
    return CONFIG
