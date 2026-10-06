"""Public fetch guard: DNS and HTTP mocked, including each redirect hop."""
import socket

import httpx
import pytest

from tipipeline.collect import MAX_REDIRECTS, UnsafeURLError, check_public_url, fetch_public


def dns(monkeypatch, addresses):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kw: [
        (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
        for ip in addresses[host]
    ])


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.1.1", "169.254.169.254",
                                  "100.64.0.1", "100.101.102.103", "::1", "fc00::1", "fe80::1", "224.0.0.1"])
def test_non_public_addresses_refused(monkeypatch, ip):
    dns(monkeypatch, {"host.example": [ip]})
    with pytest.raises(UnsafeURLError, match="non-public"):
        check_public_url("https://host.example/report")


def test_any_non_public_address_refuses_the_host(monkeypatch):
    dns(monkeypatch, {"host.example": ["8.8.8.8", "100.64.0.1"]})
    with pytest.raises(UnsafeURLError):
        check_public_url("https://host.example")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.org/report", "https:///report"])
def test_only_http_https_hosts(url):
    with pytest.raises(UnsafeURLError):
        check_public_url(url)


def test_redirect_to_private_address_never_requested(monkeypatch):
    dns(monkeypatch, {"public.example": ["8.8.8.8"], "private.example": ["192.168.0.1"]})
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://private.example/secret"})
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        with pytest.raises(UnsafeURLError, match="non-public"):
            fetch_public(client, "https://public.example/report")
    assert seen == ["https://8.8.8.8/report"]


def test_public_relative_redirects_and_limit(monkeypatch):
    dns(monkeypatch, {"public.example": ["8.8.8.8"]})
    seen = []
    def handler(request):
        assert request.headers["Host"] == "public.example"
        assert request.extensions["sni_hostname"] == "public.example"
        seen.append(str(request.url))
        return httpx.Response(200, text="report") if request.url.path == "/final" else httpx.Response(301, headers={"Location": "/final"})
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        assert fetch_public(client, "https://public.example/start").text == "report"
    assert seen == ["https://8.8.8.8/start", "https://8.8.8.8/final"]
    seen.clear()
    def loop(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "/loop"})
    with httpx.Client(transport=httpx.MockTransport(loop), follow_redirects=False) as client:
        with pytest.raises(UnsafeURLError, match="redirects"):
            fetch_public(client, "https://public.example/loop")
    assert len(seen) == MAX_REDIRECTS + 1
