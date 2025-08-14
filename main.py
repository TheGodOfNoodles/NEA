# Entry point for the Simple Web Security Scanner
# All functionality has been refactored into modular packages (app_ui, crawler, scanner, reporting, etc.)
# This script now only launches the GUI application.

from app_ui import main as run_app

if __name__ == "__main__":
    run_app()
