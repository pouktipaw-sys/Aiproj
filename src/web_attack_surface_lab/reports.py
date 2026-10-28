"""Dependency-free JSON and Markdown report writers."""
import json
from pathlib import Path
from .scanner import ScanReport

def write_reports(report: ScanReport, output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / "report.json", out / "report.md"
    json_path.write_text(json.dumps(report.__dict__, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# Web Attack Surface Lab report", "", f"- **Target:** {report.target}", f"- **Observed at (UTC):** {report.scanned_at}", f"- **HTTP status:** {report.status_code if report.status_code is not None else 'unavailable'}", f"- **Scope:** {report.scope_note}", "", "## Findings", ""]
    if not report.findings:
        lines.append("No configured checks produced findings. This is not proof that the target is secure.")
    for finding in report.findings:
        lines.extend([f"### [{finding['severity'].upper()}] {finding['title']}", "", f"**ID:** {finding['id']}", "", finding["detail"], "", f"**Recommendation:** {finding['recommendation']}", ""])
    if report.errors:
        lines.extend(["## Request notes", ""] + [f"- {error}" for error in report.errors] + [""])
    lines.extend(["## Limitations", "", "This report contains passive observations only. Manually validate each item; no crawling, exploitation, or comprehensive assessment was performed.", ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
