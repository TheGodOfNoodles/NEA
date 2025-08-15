import os
import pytest
from scanner.vulnerability import Finding
import app_ui

# Skip UI tests if tkinter not available or DISPLAY issues arise (basic guard)
pytestmark = pytest.mark.skipif(False, reason="UI tests enabled")


def build_finding(issue, sev, cat, loc, ev="e", risk="r", desc="d", rec="rec", refs=None, param="p", payload="pl"):
    return Finding(issue=issue, severity=sev, location=loc, evidence=ev, risk=risk, category=cat,
                   description=desc, recommendation=rec, references=refs or ["ref"], parameter=param, payload=payload)


def test_filter_and_grouping(monkeypatch):
    # Instantiate app (will build Tk root); ensure it closes after
    app = app_ui.SecurityScanApp()
    app.findings = [
        build_finding("Issue A", "High", "Headers", "http://t/a"),
        build_finding("Issue B", "Medium", "XSS", "http://t/b"),
        build_finding("Issue C", "Low", "XSS", "http://t/c"),
    ]
    # Basic apply
    app._apply_filters()
    # Expect 3 leaf nodes
    leaves = [iid for iid in app.tree.get_children('')]
    assert len(leaves) == 3, f"Expected 3 findings rows, got {len(leaves)}"
    # Set severity filter
    app.sev_filter_var.set('High')
    app._apply_filters()
    leaves = [iid for iid in app.tree.get_children('')]
    assert len(leaves) == 1
    # Advanced query token filter by category
    app.sev_filter_var.set('All')
    app.search_var.set('category:xss')
    app._apply_filters()
    leaves = [iid for iid in app.tree.get_children('')]
    assert len(leaves) == 2
    # Include regex to narrow one
    app.include_var.set('Issue C')
    app.exclude_var.set('B')
    app._apply_filters()
    leaves = [iid for iid in app.tree.get_children('')]
    assert len(leaves) == 1
    # Grouping by Severity
    app.include_var.set('')
    app.exclude_var.set('')
    app.search_var.set('')  # clear advanced filter so all categories return
    app.group_mode_var.set('Severity')
    app._apply_filters()
    roots = app.tree.get_children('')
    # 3 severities expected
    assert len(roots) == 3, f"Expected 3 severity groups, got {len(roots)}"
    # Expand children counts sum to 3
    total_children = sum(len(app.tree.get_children(r)) for r in roots)
    assert total_children == 3
    app.root.destroy()


def test_quick_and_selection_export(tmp_path):
    app = app_ui.SecurityScanApp()
    app.findings = [
        build_finding("Issue A", "High", "Headers", "http://t/a"),
        build_finding("Issue B", "Medium", "XSS", "http://t/b"),
    ]
    app._apply_filters()
    # Quick export (text)
    app.export_format_var.set('text')
    # Change working dir to tmp to isolate file output
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        app.quick_export()
        assert any(p.name.startswith('quick_report') for p in tmp_path.iterdir()), "quick_report file not created"
        # Select first finding and export selection
        first = app.tree.get_children('')[0]
        app.tree.selection_set(first)
        app._export_selection()
        assert any(p.name.startswith('selection_report') for p in tmp_path.iterdir()), "selection_report file not created"
    finally:
        os.chdir(cwd)
        app.root.destroy()
