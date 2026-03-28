"""Tests for numasec.scanners.race_tester — race condition (TOCTOU) detection."""

from __future__ import annotations

import json

import httpx
import pytest

from numasec.scanners.race_tester import (
    RaceResult,
    RaceTester,
    RaceVulnerability,
    python_race_test,
)

# ---------------------------------------------------------------------------
# Helpers — httpx.MockTransport factories
# ---------------------------------------------------------------------------


def _make_transport(handler):
    """Wrap a sync handler into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _text_response(body: str, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, text=body)


# ---------------------------------------------------------------------------
# RaceVulnerability / RaceResult serialisation
# ---------------------------------------------------------------------------


class TestRaceResultSerialization:
    def test_to_dict_no_vulns(self):
        result = RaceResult(target="http://example.com/api", requests_sent=20, concurrent_batch_size=20)
        d = result.to_dict()
        assert d["target"] == "http://example.com/api"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["requests_sent"] == 20
        assert "No race condition" in d["summary"]
        assert d["next_steps"] == []

    def test_to_dict_with_vulns(self):
        vuln = RaceVulnerability(
            race_type="limit_bypass",
            endpoint="http://example.com/redeem",
            evidence="All 20/20 succeeded",
            severity="high",
            confidence=0.5,
        )
        result = RaceResult(
            target="http://example.com/redeem",
            vulnerable=True,
            vulnerabilities=[vuln],
            requests_sent=20,
            concurrent_batch_size=20,
            duration_ms=123.456,
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["race_type"] == "limit_bypass"
        assert d["duration_ms"] == 123.46
        assert "Race condition detected" in d["summary"]
        assert len(d["next_steps"]) > 0


# ---------------------------------------------------------------------------
# Technique 1: Limit bypass — all requests succeed
# ---------------------------------------------------------------------------


class TestLimitBypass:
    @pytest.mark.asyncio
    async def test_all_success_detected(self):
        """All 20 concurrent requests returning 200 should flag a potential limit bypass."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"status": "ok"}')

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/redeem", "POST", {}, 20)

        vulns = tester._analyze_responses(responses, "http://target/redeem")
        assert any(v.race_type == "limit_bypass" for v in vulns)

    @pytest.mark.asyncio
    async def test_few_requests_no_flag(self):
        """Fewer than 10 successful requests should NOT flag limit bypass."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"status": "ok"}')

        tester = RaceTester(concurrency=5, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/redeem", "POST", {}, 5)

        vulns = tester._analyze_responses(responses, "http://target/redeem")
        assert not any(v.race_type == "limit_bypass" for v in vulns)


# ---------------------------------------------------------------------------
# Technique 2: State change — varying response bodies
# ---------------------------------------------------------------------------


class TestStateChange:
    @pytest.mark.asyncio
    async def test_varying_responses_detected(self):
        """Two distinct response bodies among many requests should flag state_change."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            # First few get body A, rest get body B → 2 unique bodies out of 20
            if call_count <= 5:
                return _text_response('{"balance": 100}')
            return _text_response('{"balance": 0}')

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/balance", "GET", None, 20)

        vulns = tester._analyze_responses(responses, "http://target/balance")
        assert any(v.race_type == "state_change" for v in vulns)

    @pytest.mark.asyncio
    async def test_identical_responses_no_flag(self):
        """All identical response bodies should NOT flag state_change."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"balance": 100}')

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/balance", "GET", None, 20)

        vulns = tester._analyze_responses(responses, "http://target/balance")
        assert not any(v.race_type == "state_change" for v in vulns)


# ---------------------------------------------------------------------------
# Technique 3: Duplicate action — mix of success and rejection
# ---------------------------------------------------------------------------


class TestDuplicateAction:
    @pytest.mark.asyncio
    async def test_mixed_success_rejection_detected(self):
        """Some 200s and some 409/429 indicate a race window in limit enforcement."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                return _text_response('{"status": "ok"}')
            return _text_response('{"error": "conflict"}', status_code=409)

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/transfer", "POST", {}, 20)

        vulns = tester._analyze_responses(responses, "http://target/transfer")
        assert any(v.race_type == "duplicate_action" for v in vulns)
        dup = next(v for v in vulns if v.race_type == "duplicate_action")
        assert dup.confidence == 0.8

    @pytest.mark.asyncio
    async def test_all_rejected_no_flag(self):
        """All requests rejected (429) should NOT flag duplicate_action."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"error": "rate limited"}', status_code=429)

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/transfer", "POST", {}, 20)

        vulns = tester._analyze_responses(responses, "http://target/transfer")
        assert not any(v.race_type == "duplicate_action" for v in vulns)


# ---------------------------------------------------------------------------
# No race condition — proper rate limiting
# ---------------------------------------------------------------------------


class TestNoRaceCondition:
    @pytest.mark.asyncio
    async def test_rate_limited_clean(self):
        """Server returning 429 after the first request means no race."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _text_response('{"status": "ok"}')
            return _text_response('{"error": "too many"}', status_code=429)

        tester = RaceTester(concurrency=20, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/vote", "POST", {}, 20)

        vulns = tester._analyze_responses(responses, "http://target/vote")
        # Only 1 success + 19 rejections → not enough successes for duplicate_action
        # (duplicate_action requires >1 success)
        # But we should still check: 1 success is not >1 — wait, 1 is exactly 1, not >1
        # Actually need to check the logic: success_count > 1 and rejected > 0
        # Here success_count = 1, so no duplicate_action
        assert not any(v.race_type == "duplicate_action" for v in vulns)


# ---------------------------------------------------------------------------
# Full integration: RaceTester.test()
# ---------------------------------------------------------------------------


class TestFullIntegration:
    @pytest.mark.asyncio
    async def test_full_test_method(self):
        """The high-level test() method should return a complete RaceResult."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"status": "ok"}')

        transport = _make_transport(handler)
        tester = RaceTester(concurrency=15, timeout=5.0)
        # Monkey-patch create_client to use our mock transport
        import numasec.scanners.race_tester as mod

        original = mod.create_client

        def mock_create_client(**kwargs):
            return httpx.AsyncClient(transport=transport, **{k: v for k, v in kwargs.items() if k != "headers" or v})

        mod.create_client = mock_create_client
        try:
            result = await tester.test("http://target/redeem", method="POST", body={"coupon": "SAVE50"}, repeat=15)
        finally:
            mod.create_client = original

        assert isinstance(result, RaceResult)
        assert result.target == "http://target/redeem"
        assert result.requests_sent == 15
        assert result.concurrent_batch_size == 15
        assert result.duration_ms > 0

    @pytest.mark.asyncio
    async def test_get_method(self):
        """GET requests should work correctly."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            return _text_response('{"data": "value"}')

        tester = RaceTester(concurrency=10, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/status", "GET", None, 10)

        assert len(responses) == 10
        assert all(r.status_code == 200 for r in responses)

    @pytest.mark.asyncio
    async def test_post_with_body(self):
        """POST requests should send the JSON body."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            body = json.loads(request.content)
            assert body == {"amount": 100}
            return _text_response('{"status": "ok"}')

        tester = RaceTester(concurrency=5, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(
                client, "http://target/transfer", "POST", {"amount": 100}, 5
            )

        assert len(responses) == 5


# ---------------------------------------------------------------------------
# Concurrency parameter
# ---------------------------------------------------------------------------


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_custom_concurrency(self):
        """Concurrency parameter controls batch size."""
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _text_response('{"ok": true}')

        tester = RaceTester(concurrency=30, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/api", "POST", {}, 30)

        assert len(responses) == 30
        assert request_count == 30


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    @pytest.mark.asyncio
    async def test_python_race_test_returns_json(self):
        """The tool wrapper should return valid JSON with an envelope."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"status": "ok"}')

        transport = _make_transport(handler)
        import numasec.scanners.race_tester as mod

        original = mod.create_client

        def mock_create_client(**kwargs):
            return httpx.AsyncClient(transport=transport, **{k: v for k, v in kwargs.items() if k != "headers" or v})

        mod.create_client = mock_create_client
        try:
            output = await python_race_test(url="http://target/redeem", method="POST", concurrency=12)
        finally:
            mod.create_client = original

        data = json.loads(output)
        assert data["tool"] == "race_test"
        assert data["target"] == "http://target/redeem"
        assert "status" in data
        assert "vulnerabilities" in data

    @pytest.mark.asyncio
    async def test_python_race_test_with_body_and_headers(self):
        """Tool wrapper should parse JSON body and headers strings."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response('{"ok": true}')

        transport = _make_transport(handler)
        import numasec.scanners.race_tester as mod

        original = mod.create_client

        def mock_create_client(**kwargs):
            return httpx.AsyncClient(transport=transport, **{k: v for k, v in kwargs.items() if k != "headers" or v})

        mod.create_client = mock_create_client
        try:
            output = await python_race_test(
                url="http://target/api",
                method="POST",
                body='{"amount": 50}',
                concurrency=5,
                headers='{"Authorization": "Bearer token123"}',
            )
        finally:
            mod.create_client = original

        data = json.loads(output)
        assert data["tool"] == "race_test"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_responses_no_crash(self):
        """Analyzer should handle empty response list gracefully."""
        tester = RaceTester()
        vulns = tester._analyze_responses([], "http://target/api")
        assert vulns == []

    @pytest.mark.asyncio
    async def test_exception_responses_filtered(self):
        """Requests that raise exceptions should be filtered out."""

        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count % 3 == 0:
                raise httpx.ConnectError("Connection refused")
            return _text_response('{"ok": true}')

        tester = RaceTester(concurrency=9, timeout=5.0)
        async with httpx.AsyncClient(transport=_make_transport(handler)) as client:
            responses = await tester._flood_endpoint(client, "http://target/api", "POST", {}, 9)

        # 3 out of 9 raise exceptions → 6 valid responses
        assert len(responses) == 6

    def test_vulnerability_defaults(self):
        """RaceVulnerability defaults should be correct."""
        v = RaceVulnerability(race_type="toctou", endpoint="http://x", evidence="test")
        assert v.severity == "high"
        assert v.confidence == 0.6
