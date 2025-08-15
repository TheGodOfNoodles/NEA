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

    def apply_overrides(self):
        # Environment variable overrides
        self.REQUEST_TIMEOUT = int(os.getenv("SCANNER_REQUEST_TIMEOUT", self.REQUEST_TIMEOUT))
        self.CRAWL_DELAY = float(os.getenv("SCANNER_CRAWL_DELAY", self.CRAWL_DELAY))
        self.INCLUDE_RE = os.getenv('SCANNER_INCLUDE_RE', self.INCLUDE_RE)
        self.EXCLUDE_RE = os.getenv('SCANNER_EXCLUDE_RE', self.EXCLUDE_RE)
        ua_suffix = os.getenv("SCANNER_UA_SUFFIX", "")
        if not self.USER_AGENT:
            self.USER_AGENT = f"{self.APP_NAME}/{self.VERSION} (Educational Scanner){' '+ua_suffix if ua_suffix else ''}".strip()
        extra_xss = os.getenv("SCANNER_EXTRA_XSS", "")
        if extra_xss:
            for p in extra_xss.split("||"):
                p = p.strip()
                if p and p not in self.XSS_PAYLOADS:
                    self.XSS_PAYLOADS.append(p)

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
    CONFIG = _default_config()
    return CONFIG
