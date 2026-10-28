"""Validate scope before any network operation."""
from urllib.parse import urlsplit
import ipaddress

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

class ScopeError(ValueError):
    """URL is outside the declared assessment scope."""

def validate_url(url: str, allowed_hosts: set[str] | None = None) -> str:
    if not url or any(ord(c) < 32 for c in url):
        raise ScopeError("URL is empty or contains control characters")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ScopeError("Only HTTP and HTTPS URLs are supported")
    if not parts.hostname:
        raise ScopeError("URL must contain a hostname")
    if parts.username or parts.password:
        raise ScopeError("Credentials embedded in URLs are forbidden")
    host = parts.hostname.rstrip(".").lower()
    allowlist = {h.strip().rstrip(".").lower() for h in (allowed_hosts or set()) if h.strip()}
    try:
        in_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        in_loopback = host in LOOPBACK_NAMES
    if not in_loopback and host not in allowlist:
        raise ScopeError(f"Host {host!r} is not in scope. Default scope is loopback only; use --allow-host only for systems you own or are authorized to assess.")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ScopeError("Port must be between 1 and 65535")
    return url
