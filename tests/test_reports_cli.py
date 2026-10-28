import json

from web_attack_surface_lab.cli import main
from web_attack_surface_lab.reports import write_reports
from web_attack_surface_lab.scanner import inspect_headers, redact_url

def test_missing_headers_have_distinct_finding_ids():
    report = inspect_headers("http://127.0.0.1/", {}, 200)
    ids = [finding["id"] for finding in report.findings]
    assert "TLS-001" in ids
    assert len([item for item in ids if item.startswith("HDR-")]) == len(set(ids))

def test_sensitive_header_values_are_redacted():
    report = inspect_headers("https://localhost/", {
        "Authorization": "Bearer supersecret",
        "Cookie": "session=private",
        "X-Note": "token=supersecret",
    }, 200)
    serialized = json.dumps(report.__dict__)
    assert "supersecret" not in serialized
    assert "session=private" not in serialized

def test_sensitive_query_parameters_are_redacted_in_report_target():
    target = redact_url("https://localhost/check?token=abc123&view=full")
    assert "abc123" not in target
    assert "view=full" in target

def test_report_files_are_valid(tmp_path):
    report = inspect_headers("https://localhost/", {}, 200)
    json_path, md_path = write_reports(report, tmp_path)
    assert json.loads(json_path.read_text())["target"] == "https://localhost/"
    assert "Limitations" in md_path.read_text()

def test_demo_is_offline_and_writes_reports(tmp_path):
    assert main(["demo", "--output", str(tmp_path)]) == 0
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()

def test_out_of_scope_target_is_rejected_without_report(tmp_path):
    assert main(["scan", "https://example.com/", "--output", str(tmp_path)]) == 2
    assert not (tmp_path / "report.json").exists()
