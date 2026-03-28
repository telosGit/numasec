"""Central HTTP client factory — single point for proxy, timeout, and TLS config."""

from __future__ import annotations

import os
from typing import Any

import httpx


def create_client(
    timeout: float = 30.0,
    verify: bool = False,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
    max_redirects: int = 20,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with optional proxy support.

    All scanner and tool HTTP traffic flows through this factory,
    enabling proxy interception (Burp Suite, mitmproxy) via the
    ``NUMASEC_PROXY`` environment variable.
    """
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "verify": verify,
        "follow_redirects": follow_redirects,
        "max_redirects": max_redirects,
    }
    if headers:
        kwargs["headers"] = headers
    proxy_url = os.environ.get("NUMASEC_PROXY")
    if proxy_url:
        kwargs["proxy"] = proxy_url
    return httpx.AsyncClient(**kwargs)
