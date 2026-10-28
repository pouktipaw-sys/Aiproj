"""Command line interface."""
import argparse
import json
from .scanner import inspect_headers, scan_url
from .reports import write_reports

def build_parser():
    parser = argparse.ArgumentParser(prog="web-attack-surface-lab", description="Safety-first passive web response-header observations.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="One passive GET request to one explicitly scoped URL.")
    scan.add_argument("url")
    scan.add_argument("--allow-host", action="append", default=[], help="Explicit hostname in scope; authorization is your responsibility.")
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--output", default="reports/scan")
    demo = sub.add_parser("demo", help="Generate a synthetic report without network access.")
    demo.add_argument("--output", default="reports/demo")
    return parser

def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        report = inspect_headers("https://demo.invalid/", {"content-type": "text/html", "server": "ExampleServer"}, 200, ["Synthetic offline fixture; no network request was made."])
        jp, mp = write_reports(report, args.output)
        print(f"Offline demo complete: {jp} and {mp}")
        return 0
    try:
        report = scan_url(args.url, set(args.allow_host), args.timeout)
        jp, mp = write_reports(report, args.output)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}")
        return 2
    print(json.dumps({"target": report.target, "status": report.status_code, "findings": len(report.findings), "json": str(jp), "markdown": str(mp)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
