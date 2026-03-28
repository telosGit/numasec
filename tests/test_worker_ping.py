"""Tests for the worker ping health-check handler."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from numasec.worker import _handle_ping


class TestHandlePing:
    async def test_returns_valid_json_with_status_and_pid(self):
        result = await _handle_ping({})
        data = json.loads(result)
        assert data["status"] == "ok"
        assert data["pid"] == os.getpid()
        assert isinstance(data["memory_mb"], int)
        assert "active_session" in data

    async def test_pid_matches_current_process(self):
        result = await _handle_ping({})
        data = json.loads(result)
        assert data["pid"] == os.getpid()

    async def test_active_session_is_none_by_default(self):
        result = await _handle_ping({})
        data = json.loads(result)
        assert data["active_session"] is None

    async def test_works_without_psutil(self):
        """Simulate psutil not being installed."""
        with patch.dict("sys.modules", {"psutil": None}):
            result = await _handle_ping({})
            data = json.loads(result)
            assert data["status"] == "ok"
            assert data["memory_mb"] == 0
            assert data["pid"] == os.getpid()


class TestPingRegistered:
    def test_ping_in_special_methods(self):
        from numasec.worker import SPECIAL_METHODS

        assert "ping" in SPECIAL_METHODS
        assert SPECIAL_METHODS["ping"] is _handle_ping
