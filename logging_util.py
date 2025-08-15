import logging, os, sys, json, time
from typing import Optional

_DEFAULT_LEVEL = os.getenv("NEA_LOG_LEVEL", "INFO").upper()
_JSON = os.getenv("NEA_LOG_JSON", "0") in ("1","true","yes","on")

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        base = {
            'ts': round(record.created, 3),
            'level': record.levelname,
            'msg': record.getMessage(),
            'logger': record.name,
        }
        if record.exc_info:
            base['exc'] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)

def configure_logging(level: Optional[str] = None, json_mode: Optional[bool] = None):
    """Idempotent logging configuration. Environment variables override defaults.
    NEA_LOG_LEVEL, NEA_LOG_JSON control behavior.
    """
    root = logging.getLogger()
    if getattr(root, '_nea_configured', False):
        return
    root.setLevel(level or _DEFAULT_LEVEL)
    handler = logging.StreamHandler(sys.stderr)
    json_mode = _JSON if json_mode is None else json_mode
    fmt = _JsonFormatter() if json_mode else logging.Formatter('[%(levelname)s] %(message)s')
    handler.setFormatter(fmt)
    root.handlers[:] = [handler]
    root._nea_configured = True  # type: ignore[attr-defined]

logger = logging.getLogger('nea')

def get_logger(name: str = 'nea') -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)

