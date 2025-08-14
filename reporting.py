from typing import List, Dict
import time
from config import CONFIG
from scanner.vulnerability import Finding

class ReportBuilder:
    def __init__(self, target: str, findings: List[Finding]):
        self.target = target
        self.findings = findings

    def group_by_category(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.category, []).append(f)
        return groups

    def to_text(self) -> str:
        lines = [f"Report for {self.target}", f"Generated: {time.ctime()}", "Disclaimer: " + CONFIG.ETHICAL_WARNING, ""]
        for f in self.findings:
            lines.extend([
                f"[{f.severity}] {f.issue}",
                f"Location: {f.location}",
                f"Evidence: {f.evidence}",
                f"Risk: {f.risk}",
                "---"
            ])
        if not self.findings:
            lines.append("No issues detected by basic tests.")
        return "\n".join(lines)

    def to_html(self) -> str:
        style = """
        <style>
        body { font-family: Arial, sans-serif; margin:20px; }
        .sev-High { color:#b30000; }
        .sev-Medium { color:#d97706; }
        .sev-Low { color:#2563eb; }
        .finding { border:1px solid #ddd; padding:10px; margin-bottom:10px; border-left:6px solid #999; }
        .sev-High.finding { border-left-color:#b30000; }
        .sev-Medium.finding { border-left-color:#d97706; }
        .sev-Low.finding { border-left-color:#2563eb; }
        h1 { font-size:24px; }
        .meta { font-size:12px; color:#555; }
        </style>
        """
        parts = ["<html><head><meta charset='utf-8'><title>Scan Report</title>", style, "</head><body>"]
        parts.append(f"<h1>Report for {self.target}</h1>")
        parts.append(f"<div class='meta'>Generated: {time.ctime()}<br>Disclaimer: {CONFIG.ETHICAL_WARNING}</div><hr>")
        if not self.findings:
            parts.append("<p>No issues detected by basic tests.</p>")
        for f in self.findings:
            parts.append(f"<div class='finding sev-{f.severity}'><h3>[{f.severity}] {f.issue}</h3><p><b>Location:</b> {f.location}<br><b>Evidence:</b> {f.evidence}<br><b>Risk:</b> {f.risk}</p></div>")
        parts.append("</body></html>")
        return "".join(parts)

