from dataclasses import dataclass, field
from typing import List

@dataclass
class Config:
    APP_NAME: str = "Simple Web Security Scanner"
    VERSION: str = "0.2.0"
    ETHICAL_WARNING: str = (
        "Use only on sites you own or have explicit written permission to test. Unauthorized testing may be illegal."
    )
    REQUEST_TIMEOUT: int = 10
    USER_AGENT: str = f"{APP_NAME}/{VERSION} (Educational Scanner)"
    # Payloads
    XSS_PAYLOADS: List[str] = field(default_factory=lambda: [
        "<script>alert('XSS_TEST')</script>",
        "\"'><img src=x onerror=alert(1)>",
        "'><svg/onload=alert(1)>",
        '" onmouseover=alert(1) x="',
        "'></textarea><script>alert(1)</script>",
    ])
    SQL_ERRORS: List[str] = field(default_factory=lambda: [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql server",
        "sqlite error",
        "psql:",
    ])

CONFIG = Config()

