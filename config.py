from dataclasses import dataclass, field
from typing import List
import os

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

    def apply_overrides(self):
        # Environment variable overrides
        self.REQUEST_TIMEOUT = int(os.getenv("SCANNER_REQUEST_TIMEOUT", self.REQUEST_TIMEOUT))
        ua_suffix = os.getenv("SCANNER_UA_SUFFIX", "")
        if not self.USER_AGENT:
            self.USER_AGENT = f"{self.APP_NAME}/{self.VERSION} (Educational Scanner){' '+ua_suffix if ua_suffix else ''}".strip()
        extra_xss = os.getenv("SCANNER_EXTRA_XSS", "")
        if extra_xss:
            for p in extra_xss.split("||"):
                p = p.strip()
                if p and p not in self.XSS_PAYLOADS:
                    self.XSS_PAYLOADS.append(p)


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
    cfg.apply_overrides()
    return cfg

CONFIG = _default_config()


def reload_config():
    global CONFIG
    CONFIG = _default_config()
    return CONFIG

