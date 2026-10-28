import json
from web_attack_surface_lab.scanner import inspect_headers
from web_attack_surface_lab.reports import write_reports
from web_attack_surface_lab.cli import main

def test_missing_headers_findings():
    report = inspect_headers("http://127.0.0.1/", {}, 200)
    assert any(f["id"] == "TLS-001" for f in report.findings)
    assert any("Missing" in f["title"] for f in report.findings)

def test_redaction():
    report = inspect_headers("https://localhost/", {"X-Note": "token=supersecret"}, 200)
    assert "supersecret" not in json.dumps(report.__dict__)

def test_report_files(tmp_path):
    report = inspect_headers("https://localhost/", {}, 200)
    jp, mp = write_reports(report, tmp_path)
    assert json.loads(jp.read_text())["target"] == "https://localhost/"
    assert "Limitations" in mp.read_text()

def test_demo_offline(tmp_path):
    assert main(["demo", "--output", str(tmp_path)]) == 0
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()

def test_out_of_scope_does_not_create_report(tmp_path):
    assert main(["scan", "https://example.com/", "--output", str(tmp_path)]) == 2
    assert not (tmp_path / "report.json").exists()
