from reporting import ReportBuilder
from scanner.vulnerability import Finding

def sample_finding():
    return Finding(
        issue="Potential Reflected XSS",
        severity="Medium",
        location="http://test/app?name=foo",
        evidence="<script>alert('XSS_TEST')</script>",
        risk="Attackers could run malicious scripts in users' browsers.",
        category="Cross-Site Scripting",
        description="Reflected unsanitized input.",
        recommendation="Apply context-aware encoding and CSP.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        parameter="name",
        payload="<script>alert('XSS_TEST')</script>"
    )


def test_report_text_contains_new_fields():
    f = sample_finding()
    rb = ReportBuilder("http://test", [f])
    txt = rb.to_text()
    for fragment in ["Parameter:", "Payload:", "Description:", "Recommendation:", "References:"]:
        assert fragment in txt
    assert f.payload in txt


def test_report_html_contains_links():
    f = sample_finding()
    rb = ReportBuilder("http://test", [f])
    html = rb.to_html()
    assert '<ul' in html and f.references[0] in html


def test_report_markdown_details():
    f = sample_finding()
    rb = ReportBuilder("http://test", [f])
    md = rb.to_markdown()
    assert "### Potential Reflected XSS" in md
    assert f.parameter in md


def test_report_json_keys():
    f = sample_finding()
    rb = ReportBuilder("http://test", [f])
    js = rb.to_json()
    for key in ["description", "recommendation", "references", "parameter", "payload"]:
        assert f'"{key}":' in js


def test_report_sarif():
    f = sample_finding()
    rb = ReportBuilder("http://test", [f])
    sarif = rb.to_sarif()
    # minimal sanity checks
    assert '"runs"' in sarif
    assert f.issue in sarif
    assert f.payload in sarif or f.evidence in sarif

