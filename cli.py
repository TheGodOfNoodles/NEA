import argparse
import sys
import os
from typing import List
from config import CONFIG, reload_config
from http_client import HTTPClient
from crawler import Crawler
from scanner.engine import VulnerabilityScanner
from reporting import ReportBuilder


def list_checks() -> List[str]:
    # temporary engine to discover
    engine = VulnerabilityScanner(HTTPClient())
    return sorted([c.name for c in engine.check_classes])


def run_cli(argv=None):
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(description="Simple Web Security Scanner (CLI mode)")
    parser.add_argument('--url', required=False, help='Target URL (http/https)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default 2)')
    parser.add_argument('--checks', help='Comma-separated subset of checks to run (default: all)')
    parser.add_argument('--list-checks', action='store_true', help='List available checks and exit')
    parser.add_argument('--format', choices=['text', 'html', 'json'], default='text', help='Report output format')
    parser.add_argument('-o', '--output', help='Output file path (default: stdout)')
    parser.add_argument('--timeout', type=int, help='Override request timeout seconds')
    parser.add_argument('--ua-suffix', help='Append string to User-Agent')
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    args = parser.parse_args(argv)

    if args.version:
        print(f"{CONFIG.APP_NAME} v{CONFIG.VERSION}")
        return 0

    if args.list_checks:
        for name in list_checks():
            print(name)
        return 0

    if not args.url:
        parser.error('--url is required unless --list-checks or --version used')

    # Apply overrides
    if args.timeout:
        os.environ['SCANNER_REQUEST_TIMEOUT'] = str(args.timeout)
    if args.ua_suffix:
        os.environ['SCANNER_UA_SUFFIX'] = args.ua_suffix
    reload_config()

    enabled_checks = None
    if args.checks:
        enabled_checks = [c.strip() for c in args.checks.split(',') if c.strip()]

    http = HTTPClient()

    def status(msg: str):
        print(msg, file=sys.stderr)

    crawler = Crawler(args.url, args.depth, http, status_cb=status)
    pages = crawler.crawl()

    engine = VulnerabilityScanner(http, status_cb=status, enabled_checks=enabled_checks)
    findings = engine.scan_pages(pages)

    rb = ReportBuilder(args.url, findings)
    if args.format == 'html':
        content = rb.to_html()
    elif args.format == 'json':
        content = rb.to_json()
    else:
        content = rb.to_text()

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Report written to {args.output}")
    else:
        print(content)
    return 0

if __name__ == '__main__':
    sys.exit(run_cli())

