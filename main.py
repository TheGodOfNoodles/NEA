# Entry point for the Simple Web Security Scanner
# Adds guarded launch, logging initialization, and mode selection (GUI vs CLI).

from logging_util import configure_logging, get_logger
import os, sys

logger = get_logger(__name__)


def _run_gui():
    from app_ui import main as run_app  # lazy import to avoid Tk on CLI usage
    run_app()


def _run_cli():
    from cli import run_cli
    return run_cli()


def main():
    configure_logging()
    mode = os.getenv('NEA_MODE', '').lower()
    if len(sys.argv) > 1 and sys.argv[1] in ('--cli', 'cli'):
        mode = 'cli'
        # strip flag
        if sys.argv[1] in ('--cli','cli'):
            del sys.argv[1]
    if mode == 'cli':
        logger.info('Launching in CLI mode')
        code = _run_cli()
        return code
    logger.info('Launching in GUI mode')
    try:
        _run_gui()
    except Exception as e:
        logger.exception('Fatal error in GUI mode: %s', e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
