from typing import List, Dict
import time, json, csv, io
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

    def _summary(self) -> Dict[str, int | float]:
        counts = {"High":0, "Medium":0, "Low":0}
        weight = {"High":5, "Medium":3, "Low":1}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity,0)+1
        risk_score = sum(weight.get(f.severity,0) for f in self.findings)
        counts['risk_score'] = risk_score
        return counts

    def summary(self) -> Dict[str, int | float]:
        return self._summary()

    def to_text(self) -> str:
        lines = [f"Report for {self.target}", f"Generated: {time.ctime()}", "Disclaimer: " + CONFIG.ETHICAL_WARNING, ""]
        for f in self.findings:
            refs = ", ".join(f.references) if f.references else ""
            lines.extend([
                f"[{f.severity}] {f.issue}",
                f"Category: {f.category}",
                f"Location: {f.location}",
                *( [f"Parameter: {f.parameter}"] if f.parameter else [] ),
                *( [f"Payload: {f.payload}"] if f.payload else [] ),
                f"Evidence: {f.evidence}",
                f"Risk: {f.risk}",
                *( [f"Description: {f.description}"] if f.description else [] ),
                *( [f"Recommendation: {f.recommendation}"] if f.recommendation else [] ),
                *( [f"References: {refs}"] if refs else [] ),
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
        .refs { font-size: 12px; }
        </style>
        """
        parts = ["<html><head><meta charset='utf-8'><title>Scan Report</title>", style, "</head><body>"]
        parts.append(f"<h1>Report for {self.target}</h1>")
        parts.append(f"<div class='meta'>Generated: {time.ctime()}<br>Disclaimer: {CONFIG.ETHICAL_WARNING}</div><hr>")
        if not self.findings:
            parts.append("<p>No issues detected by basic tests.</p>")
        for f in self.findings:
            refs_html = "".join(f"<li><a href='{r}' target='_blank'>{r}</a></li>" for r in f.references) if f.references else ""
            param_line = f"<br><b>Parameter:</b> {f.parameter}" if f.parameter else ""
            payload_line = f"<br><b>Payload:</b> {f.payload}" if f.payload else ""
            desc_line = f"<br><b>Description:</b> {f.description}" if f.description else ""
            rec_line = f"<br><b>Recommendation:</b> {f.recommendation}" if f.recommendation else ""
            refs_block = f"<br><b>References:</b><ul class='refs'>{refs_html}</ul>" if refs_html else ""
            parts.append(
                f"<div class='finding sev-{f.severity}'><h3>[{f.severity}] {f.issue}</h3><p><b>Category:</b> {f.category}<br><b>Location:</b> {f.location}{param_line}{payload_line}<br><b>Evidence:</b> {f.evidence}<br><b>Risk:</b> {f.risk}{desc_line}{rec_line}{refs_block}</p></div>"
            )
        parts.append("</body></html>")
        return "".join(parts)

    def to_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "generated": time.time(),
            "disclaimer": CONFIG.ETHICAL_WARNING,
            "summary": self._summary(),
            "findings": [f.__dict__ for f in self.findings]
        }, indent=2)

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Severity", "Category", "Issue", "Location", "Parameter", "Payload", "Evidence", "Risk", "Description", "Recommendation", "References"])
        for f in self.findings:
            writer.writerow([
                f.severity, f.category, f.issue, f.location, f.parameter, f.payload, f.evidence, f.risk, f.description, f.recommendation, " | ".join(f.references)
            ])
        return buf.getvalue()

    def to_markdown(self) -> str:
        lines = [f"# Report for {self.target}", "", f"_Generated: {time.ctime()}_", "", f"> {CONFIG.ETHICAL_WARNING}", "", "| Severity | Category | Issue | Location | Parameter | Payload |", "|---|---|---|---|---|---|"]
        for f in self.findings:
            lines.append(f"| {f.severity} | {f.category} | {f.issue} | {f.location} | {f.parameter or ''} | {f.payload or ''} |")
        if not self.findings:
            lines.append("\n_No issues detected._")
        lines.append("\n## Details\n")
        for f in self.findings:
            refs_md = '\n'.join(f"  - {r}" for r in f.references) if f.references else ""
            lines.extend([
                f"### {f.issue}",
                f"*Severity:* {f.severity}  ",
                f"*Category:* {f.category}  ",
                f"*Location:* `{f.location}`  ",
                *( [f"*Parameter:* `{f.parameter}`  "] if f.parameter else [] ),
                *( [f"*Payload:* `{f.payload}`  "] if f.payload else [] ),
                f"*Evidence:* `{f.evidence}`  ",
                f"*Risk:* {f.risk}",
                *( [f"*Description:* {f.description}"] if f.description else [] ),
                *( [f"*Recommendation:* {f.recommendation}"] if f.recommendation else [] ),
                *( ["*References:*", refs_md] if refs_md else [] ),
                ""
            ])
        return "\n".join(lines)

    def to_sarif(self) -> str:
        runs = []
        rules = {}
        results = []
        for idx, f in enumerate(self.findings, start=1):
            rule_id = f.category.replace(' ', '_') + '_' + f.issue.replace(' ', '_')[:40]
            full_desc = f.description or f.risk
            help_text = (f"Risk: {f.risk}\n\n" + (f"Description: {f.description}\n\n" if f.description else "") + (f"Recommendation: {f.recommendation}" if f.recommendation else "")).strip()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.issue,
                    "shortDescription": {"text": f.issue},
                    "fullDescription": {"text": full_desc},
                    "help": {"text": help_text},
                    "defaultConfiguration": {"level": f.severity.lower()},
                    "properties": {"references": f.references}
                }
            message_parts = [f.issue, f.evidence]
            if f.parameter:
                message_parts.append(f"param={f.parameter}")
            if f.payload:
                message_parts.append(f"payload={f.payload}")
            results.append({
                "ruleId": rule_id,
                "level": f.severity.lower(),
                "message": {"text": "; ".join(p for p in message_parts if p)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location}
                    }
                }]
            })
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": CONFIG.APP_NAME, "informationUri": "https://example.com", "rules": list(rules.values())}},
                "results": results,
                "invocations": [{"executionSuccessful": True}],
                "properties": {"summary": self._summary()}
            }]
        }
        return json.dumps(sarif, indent=2)
