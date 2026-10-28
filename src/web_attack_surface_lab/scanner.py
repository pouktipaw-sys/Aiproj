"""One-request passive observation engine. No crawling or redirect following."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler
from urllib.parse import urlsplit
import re
from .scope import validate_url

SECURITY_HEADERS = {
    "content-security-policy": "Content Security Policy",
    "strict-transport-security": "HTTP Strict Transport Security",
    "x-content-type-options": "MIME sniffing protection",
    "x-frame-options": "Clickjacking protection",
    "referrer-policy": "Referrer policy",
    "permissions-policy": "Permissions policy",
}

@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    recommendation: str

@dataclass
class ScanReport:
    target: str
    scanned_at: str
    status_code: int | None
    headers: dict[str, str]
    findings: list[dict]
    errors: list[str]
    scope_note: str = "One URL, one GET request, no redirects, no crawling, no exploitation."

def redact(value: str) -> str:
    value = re.sub(r"(?i)(authorization|cookie|set-cookie|api[_-]?key|token|secret)(\\s*[:=]\\s*)[^; ,]+", r"\\1\\2[REDACTED]", value)
    return value[:500]

def inspect_headers(url: str, headers: dict[str, str], status: int | None, errors: list[str] | None = None) -> ScanReport:
    findings: list[Finding] = []
    lower = {k.lower(): redact(str(v)) for k, v in headers.items()}
    if urlsplit(url).scheme.lower() != "https":
        findings.append(Finding("TLS-001", "medium", "Target URL uses HTTP", "The supplied URL is not HTTPS.", "Use HTTPS for production applications and redirect HTTP at the edge."))
    for key, label in SECURITY_HEADERS.items():
        if key not in lower:
            findings.append(Finding("HDR-001", "low", f"Missing {label} header", f"No {key} response header was observed.", f"Review whether {key} should be configured for this application."))
    if "server" in lower:
        findings.append(Finding("INFO-001", "info", "Server banner disclosed", f"Server header observed: {lower['server']}", "Consider minimizing unnecessary implementation details in response headers."))
    return ScanReport(url, datetime.now(timezone.utc).isoformat(), status, lower, [asdict(f) for f in findings], errors or [])

class _NoRedirect:
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def scan_url(url: str, allowed_hosts: set[str] | None = None, timeout: float = 5.0) -> ScanReport:
    validate_url(url, allowed_hosts)
    if not 0.2 <= timeout <= 15:
        raise ValueError("Timeout must be between 0.2 and 15 seconds")
    opener = build_opener(_NoRedirect(), HTTPHandler(), HTTPSHandler())
    request = Request(url, headers={"User-Agent": "WebAttackSurfaceLab/0.1 (passive-learning-tool)"}, method="GET")
    status, headers, errors = None, {}, []
    try:
        with opener.open(request, timeout=timeout) as response:
            status, headers = response.status, dict(response.headers.items())
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        if 300 <= exc.code < 400:
            errors.append("Redirect observed but not followed for scope safety.")
    except (URLError, TimeoutError, OSError) as exc:
        errors.append(f"Request failed: {type(exc).__name__}: {redact(str(exc))}")
    return inspect_headers(url, headers, status, errors)
