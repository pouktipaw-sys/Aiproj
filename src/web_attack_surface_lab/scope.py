"""Validate URL scope before any network operation."""
from urllib.parse import urlsplit
import ipaddress

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

class ScopeError(ValueError):
    """The requested URL is outside the declared scope."""

def validate_url(url: str, allowed_hosts: set[str] | None = None) -> str:
    if not url or any(ord(char) < 32 for char in url):
        raise ScopeError("The URL is empty or contains control characters.")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ScopeError(f"The URL is malformed: {exc}") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScopeError("Only http:// and https:// URLs are supported.")
    if not host:
        raise ScopeError("The URL must include a hostname.")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("Credentials inside URLs are not allowed.")
    host = host.rstrip(".").lower()
    allowlist = {
        item.strip().rstrip(".").lower()
        for item in (allowed_hosts or set())
        if item.strip()
    }
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host in LOOPBACK_NAMES
    if not is_loopback and host not in allowlist:
        raise ScopeError(
            f"Host {host!r} is outside scope. By default only localhost is allowed. "
            "Use --allow-host only for a system you own or have explicit permission to assess."
        )
    if port is not None and not 1 <= port <= 65535:
        raise ScopeError("The port must be between 1 and 65535.")
    return url
