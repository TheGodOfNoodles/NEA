"""Benchmark harness for crawler & scanner performance.

Usage examples:
  python benchmark.py crawl --pages 200 --depth 1 --concurrency 1,4,8 --latency 0.01
  python benchmark.py scan  --pages 500 --concurrency 1,4,8
  python benchmark.py full  --pages 300 --depth 1 --concurrency 1,4,8
Add --json to emit machine-readable JSON summary.

Synthetic site generation avoids network variance; request latency is simulated.
"""
from __future__ import annotations
import os, time, argparse, json, statistics, random
from dataclasses import dataclass, asdict
from typing import Dict, List, Iterable
from config import reload_config, CONFIG
from crawler import Crawler, PageData
from http_client import HTTPClient
from scanner.engine import VulnerabilityScanner

# -------- Synthetic HTTP clients ---------
class SyntheticHTTP(HTTPClient):
    def __init__(self, pages: Dict[str,str], latency: float, jitter: float = 0.0):
        super().__init__()
        self._pages = pages
        self._lat = latency
        self._jitter = jitter
    def get(self, url, params=None, allow_redirects=True):  # type: ignore[override]
        target = url.split('#')[0]
        body = self._pages.get(target, '<html><body>NF</body></html>')
        delay = self._lat + (random.uniform(-self._jitter, self._jitter) if self._jitter else 0.0)
        if delay > 0:
            time.sleep(max(0.0, delay))
        # Minimal fake response object
        class R:
            def __init__(self, html, url):
                self.text = html
                self.status_code = 200
                self.headers = {'Content-Type':'text/html'}
                self.history = []
                self.raw = type('Raw', (), {'headers': type('H', (), {'get_all': lambda *_: []})()})()
                self.url = url
        return R(body, target), delay, None

# ---------- Site generation --------------
def build_site(n: int, depth: int) -> Dict[str,str]:
    pages: Dict[str,str] = {}
    # Simple breadth structure: root links to level1, each level1 optionally links deeper while budget remains.
    def page_html(name: str, links: Iterable[str]) -> str:
        anchors = ''.join(f"<a href='/{l}'>L</a>" for l in links)
        # inject some patterns for scanner to find
        vuln_bits = "<script>document.write(location.hash)</script> <!-- AKIA1234567890ABCDEF -->"
        form = "<form action='/login' method='post'><input name='u'><input name='p'></form>"
        return f"<html><body>{name}{anchors}{form}{vuln_bits}</body></html>"
    remaining = n - 1
    level = 0
    frontier = ['']  # '' represents root path
    pages['http://bench.test'] = page_html('root', [])  # fill links later
    all_paths: List[str] = []
    while remaining > 0 and level < depth:
        next_frontier: List[str] = []
        per_parent = max(1, remaining // max(1,len(frontier)))
        for parent in frontier:
            if remaining <= 0:
                break
            children = []
            for i in range(per_parent):
                if remaining <= 0:
                    break
                child_name = f"p{len(all_paths)+1}"
                path = (parent + '/' + child_name).strip('/')
                children.append(path)
                all_paths.append(path)
                remaining -= 1
                next_frontier.append(path)
            # update parent page with its links
            url_parent = 'http://bench.test' + ('' if not parent else '/' + parent)
            # regenerate parent html with links
            pages[url_parent] = page_html(parent or 'root', children)
        frontier = next_frontier
        level += 1
    # Fill leaf pages
    for path in all_paths:
        url = 'http://bench.test/' + path
        if url not in pages:
            pages[url] = page_html(path, [])
    return pages

# --------- Results dataclasses ------------
@dataclass
class CrawlStats:
    pages: int
    depth: int
    concurrency: int
    latency: float
    total_time: float
    pages_per_sec: float

@dataclass
class ScanStats:
    pages: int
    concurrency: int
    total_time: float
    pages_per_sec: float
    findings: int

@dataclass
class RunBundle:
    mode: str
    crawl: List[CrawlStats] | None = None
    scan: List[ScanStats] | None = None

# --------- Benchmark functions -----------

def run_crawl_bench(pages: Dict[str,str], depth: int, conc_values: List[int], latency: float, fast: bool=False, pipeline: bool=False) -> List[CrawlStats]:
    out: List[CrawlStats] = []
    for c in conc_values:
        os.environ['SCANNER_CRAWL_CONCURRENCY'] = str(c)
        if fast:
            os.environ['SCANNER_SKIP_ASSETS'] = '1'
            os.environ['SCANNER_SKIP_JS_ENDPOINTS'] = '1'
            os.environ['SCANNER_MAX_BODY_SIZE'] = os.environ.get('SCANNER_MAX_BODY_SIZE','150000')
            os.environ['SCANNER_PROGRESS_INTERVAL'] = '0.75'
        if pipeline:
            os.environ['SCANNER_PIPELINE_SCAN'] = '1'
        reload_config()
        http = SyntheticHTTP(pages, latency=latency)
        scanner = VulnerabilityScanner(http) if pipeline else None
        crawler = Crawler('http://bench.test', max_depth=depth, http_client=http, scanner=scanner)
        t0 = time.perf_counter()
        result = crawler.crawl()
        t1 = time.perf_counter()
        # If pipeline, findings already populated; just ensure remaining pages scanned (idempotent)
        if pipeline and scanner:
            scanner.scan_pages(result)
        elapsed = t1 - t0
        out.append(CrawlStats(pages=len(result), depth=depth, concurrency=c, latency=latency, total_time=round(elapsed,4), pages_per_sec=round(len(result)/elapsed if elapsed>0 else 0,2)))
    return out

def run_scan_bench(pages: Dict[str,str], depth: int, conc_values: List[int]) -> List[ScanStats]:
    # Build PageData collection by doing a quick single crawl at max concurrency to reuse extraction
    os.environ['SCANNER_CRAWL_CONCURRENCY'] = str(max(conc_values))
    reload_config()
    http_crawl = SyntheticHTTP(pages, latency=0.0)
    crawler = Crawler('http://bench.test', max_depth=depth, http_client=http_crawl)
    crawled = crawler.crawl()
    # Duplicate map for fairness
    scan_pages = dict(crawled)
    stats: List[ScanStats] = []
    for c in conc_values:
        os.environ['SCANNER_SCAN_CONCURRENCY'] = str(c)
        reload_config()
        http_scan = SyntheticHTTP(pages, latency=0.0)
        engine = VulnerabilityScanner(http_scan)
        t0 = time.perf_counter()
        findings = engine.scan_pages(scan_pages)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        stats.append(ScanStats(pages=len(scan_pages), concurrency=c, total_time=round(elapsed,4), pages_per_sec=round(len(scan_pages)/elapsed if elapsed>0 else 0,2), findings=len(findings)))
    return stats

# --------- CLI ---------------------------

def parse_args():
    p = argparse.ArgumentParser(description='Benchmark harness for the Simple Web Security Scanner')
    sub = p.add_subparsers(dest='mode', required=True)
    def add_common(sp):
        sp.add_argument('--pages', type=int, default=200, help='Approximate number of pages to synthesize')
        sp.add_argument('--depth', type=int, default=1, help='Crawl depth for synthetic site')
        sp.add_argument('--concurrency', type=str, default='1,4,8', help='Comma list of concurrency levels to test')
        sp.add_argument('--json', action='store_true', help='Emit JSON summary to stdout')
        sp.add_argument('--fast', action='store_true', help='Enable fast-mode flags (skip assets/js endpoints, truncate bodies)')
        sp.add_argument('--pipeline', action='store_true', help='Enable crawl+scan pipeline (scan during crawl)')
    pc = sub.add_parser('crawl', help='Benchmark crawling only (optionally pipeline scanning)')
    add_common(pc)
    pc.add_argument('--latency', type=float, default=0.01, help='Simulated per-request base latency seconds')
    ps = sub.add_parser('scan', help='Benchmark scanning only (after one crawl)')
    add_common(ps)
    pf = sub.add_parser('full', help='Benchmark crawl then scan for each concurrency value')
    add_common(pf)
    pf.add_argument('--latency', type=float, default=0.01, help='Simulated per-request base latency seconds (crawl phase)')
    return p.parse_args()

# --------- Main --------------------------

def main():
    args = parse_args()
    conc_values = [int(x) for x in args.concurrency.split(',') if x.strip()]
    pages_map = build_site(args.pages, args.depth)
    bundle = RunBundle(mode=args.mode)
    if args.mode == 'crawl':
        bundle.crawl = run_crawl_bench(pages_map, args.depth, conc_values, getattr(args,'latency',0.0), fast=args.fast, pipeline=args.pipeline)
    elif args.mode == 'scan':
        bundle.scan = run_scan_bench(pages_map, args.depth, conc_values)
    else:  # full
        bundle.crawl = run_crawl_bench(pages_map, args.depth, conc_values, getattr(args,'latency',0.0), fast=args.fast, pipeline=args.pipeline)
        # Only run separate scan if not pipeline (since pipeline already scanned)
        if not args.pipeline:
            bundle.scan = run_scan_bench(pages_map, args.depth, conc_values)
    if args.json:
        print(json.dumps({k: [asdict(x) for x in v] if v else None for k,v in asdict(bundle).items()}, indent=2))
        return
    # Human readable summary
    if bundle.crawl:
        print('\nCrawl Results:' + (' (pipeline)' if args.pipeline else '') + (' (fast)' if args.fast else ''))
        for r in bundle.crawl:
            print(f"  conc={r.concurrency:<3} pages={r.pages:<5} time={r.total_time:<7} pps={r.pages_per_sec:<6} depth={r.depth} latency={r.latency}")
    if bundle.scan:
        print('\nScan Results:')
        for r in bundle.scan:
            print(f"  conc={r.concurrency:<3} pages={r.pages:<5} time={r.total_time:<7} pps={r.pages_per_sec:<6} findings={r.findings}")

if __name__ == '__main__':
    main()
