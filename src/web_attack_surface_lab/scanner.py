"""Passive HTTP observations with small, explicit safety boundaries.

This module deliberately makes one request to one validated URL. It does not
crawl links, submit forms, follow redirects, or read response bodies.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPHandler, HTTPSHandler, Request, build_opener
import re

from .scope import validate_url

SECURITY_HEADERS = {
    "content-security-policy": ("HDR-001", "Content Security Policy"),
    "strict-transport-security": ("HDR-002", "HTTP Strict Transport Security"),
    "x-content-type-options": ("HDR-003", "MIME sniffing protection"),
    "x-frame-options": ("HDR-004", "Clickjacking protection"),
    "referrer-policy": ("HDR-005", "Referrer policy"),
    "permissions-policy": ("HDR-006", "Permissions policy"),
}
SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token",
}
SENSITIVE_QUERY_NAMES = {
    "access_token", "auth", "authorization", "api_key", "apikey",
    "client_secret", "password", "secret", "token", "key",
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
    scope_note: str = "One URL, one GET request, no response-body reading, redirects, crawling or exploitation."

def redact(value: str) -> str:
    """Redact common secret-like assignments and cap values for readable reports."""
    value = re.sub(
        r"(?i)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|token|secret|password)(\s*[:=]\s*)[^; ,&]+",
        r"\1\2[REDACTED]",
        value,
    )
    return value[:500]

def redact_url(url: str) -> str:
    """Keep a useful target reference without leaking sensitive query values."""
    parts = urlsplit(url)
    safe_query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_NAMES or any(word in key.lower() for word in ("token", "secret", "password", "api_key")):
            value = "[REDACTED]"
        safe_query.append((key, value))
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is not None:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(safe_query), ""))

def inspect_headers(url: str, headers: dict[str, str], status: int | None, errors: list[str] | None = None) -> ScanReport:
    findings: list[Finding] = []
    lower: dict[str, str] = {}
    for name, value in headers.items():
        key = name.lower().strip()
        lower[key] = "[REDACTED]" if key in SENSITIVE_HEADER_NAMES else redact(str(value))
    if urlsplit(url).scheme.lower() != "https":
        findings.append(Finding(
            "TLS-001", "medium", "The URL uses HTTP",
            "The supplied URL starts with HTTP, so this request did not use HTTPS.",
            "For production services, use HTTPS and consider redirecting HTTP traffic at the edge.",
        ))
    for key, (finding_id, label) in SECURITY_HEADERS.items():
        if key not in lower:
            findings.append(Finding(
                finding_id, "low", f"Header not observed: {label}",
                f"The response did not include the {key} header.",
                f"Check whether {key} is appropriate for this application. A missing header is not, by itself, proof of a vulnerability.",
            ))
    if "server" in lower:
        findings.append(Finding(
            "INFO-001", "info", "A server banner was returned",
            f"Observed Server header: {lower['server']}",
            "Review whether exposing this implementation detail is necessary.",
        ))
    return ScanReport(
        target=redact_url(url),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        status_code=status,
        headers=lower,
        findings=[asdict(finding) for finding in findings],
        errors=[redact(error) for error in (errors or [])],
    )

class _NoRedirect:
    """Refuse redirects so one run cannot silently change target."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def scan_url(url: str, allowed_hosts: set[str] | None = None, timeout: float = 5.0) -> ScanReport:
    # Validate before creating or opening a request.
    validate_url(url, allowed_hosts)
    if not 0.2 <= timeout <= 15:
        raise ValueError("Timeout must be between 0.2 and 15 seconds")
    opener = build_opener(_NoRedirect(), HTTPHandler(), HTTPSHandler())
    request = Request(
        url,
        headers={"User-Agent": "WebAttackSurfaceLab/0.2 (passive-learning-tool)"},
        method="GET",
    )
    status, headers, errors = None, {}, []
    try:
        # Header-only observation: deliberately do not read the response body.
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            headers = dict(response.headers.items())
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        if 300 <= exc.code < 400:
            errors.append("A redirect was returned but not followed, to preserve the declared scope.")
        exc.close()
    except (URLError, TimeoutError, OSError) as exc:
        errors.append(f"Request failed: {type(exc).__name__}: {redact(str(exc))}")
    return inspect_headers(url, headers, status, errors)
