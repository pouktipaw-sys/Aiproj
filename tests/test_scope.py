import pytest

from web_attack_surface_lab.scope import ScopeError, validate_url

def test_loopback_allowed_by_default():
    assert validate_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"

@pytest.mark.parametrize("url", [
    "https://example.com",
    "ftp://localhost/file",
    "http://user:pass@localhost/",
    "",
    "http://localhost:99999/",
    "http://[invalid-ipv6]/",
])
def test_invalid_or_out_of_scope_url_rejected(url):
    with pytest.raises(ScopeError):
        validate_url(url)

def test_explicit_allowlist_is_exact():
    assert validate_url("https://demo.example/", {"demo.example"})
    with pytest.raises(ScopeError):
        validate_url("https://notdemo.example/", {"demo.example"})

def test_ipv6_loopback_allowed():
    assert validate_url("http://[::1]:8080/")
