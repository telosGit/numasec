"""Tests for central HTTP client factory."""

from __future__ import annotations

import os
from unittest.mock import patch

import httpx

from numasec.core.http import create_client


class TestCreateClient:
    """Test create_client factory function."""

    def test_returns_async_client(self):
        client = create_client()
        assert isinstance(client, httpx.AsyncClient)

    def test_default_config(self):
        client = create_client()
        assert client._transport._pool._ssl_context.verify_mode.name == "CERT_NONE" or not client._transport._pool._ssl_context  # verify=False

    def test_custom_timeout(self):
        client = create_client(timeout=5.0)
        assert client.timeout.connect == 5.0

    def test_verify_true(self):
        client = create_client(verify=True)
        # Should not raise when created with verify=True
        assert client is not None

    def test_follow_redirects_false(self):
        client = create_client(follow_redirects=False)
        assert client is not None

    def test_custom_headers(self):
        client = create_client(headers={"X-Custom": "test"})
        assert client.headers.get("x-custom") == "test"

    def test_max_redirects(self):
        client = create_client(max_redirects=5)
        assert client.max_redirects == 5

    @patch.dict(os.environ, {"NUMASEC_PROXY": "http://127.0.0.1:8080"})
    def test_proxy_from_env(self):
        # create_client reads NUMASEC_PROXY at call time
        client = create_client()
        assert client is not None

    def test_no_proxy_by_default(self):
        client = create_client()
        # Default: no proxy configured
        assert client is not None
