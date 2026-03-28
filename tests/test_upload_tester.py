"""Tests for numasec.scanners.upload_tester — file upload vulnerability detection."""

from __future__ import annotations

import json

import httpx
import pytest

from numasec.scanners.upload_tester import (
    UploadResult,
    UploadTester,
    UploadVulnerability,
    _parse_upload_forms,
    python_upload_test,
)

# ---------------------------------------------------------------------------
# Helpers — httpx.MockTransport factories
# ---------------------------------------------------------------------------


def _make_transport(handler):
    """Wrap a sync handler into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _text_response(
    body: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(status_code, text=body, headers=headers or {})


def _patch_client(handler):
    """Context-manager-style helper to monkeypatch httpx.AsyncClient with a mock transport."""
    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        kwargs["transport"] = _make_transport(handler)
        kwargs.pop("proxy", None)
        original_init(self_client, **kwargs)

    return original_init, patched_init


# ---------------------------------------------------------------------------
# HTML form with file input (used across tests)
# ---------------------------------------------------------------------------

_FORM_HTML = """
<html><body>
<form action="/upload" method="POST" enctype="multipart/form-data">
    <input type="file" name="avatar" />
    <input type="submit" value="Upload" />
</form>
</body></html>
"""

_FORM_HTML_MULTIPLE = """
<html><body>
<form action="/upload" method="POST" enctype="multipart/form-data">
    <input type="file" name="photo" />
    <input type="file" name="document" />
    <input type="submit" />
</form>
</body></html>
"""

_NO_FORM_HTML = "<html><body><p>No forms here</p></body></html>"


# ---------------------------------------------------------------------------
# HTML form parser
# ---------------------------------------------------------------------------


class TestFormParser:
    def test_parse_single_file_input(self):
        forms = _parse_upload_forms(_FORM_HTML)
        assert len(forms) == 1
        assert forms[0]["action"] == "/upload"
        assert forms[0]["method"] == "POST"
        assert "avatar" in forms[0]["file_inputs"]

    def test_parse_multiple_file_inputs(self):
        forms = _parse_upload_forms(_FORM_HTML_MULTIPLE)
        assert len(forms) == 1
        assert len(forms[0]["file_inputs"]) == 2
        assert "photo" in forms[0]["file_inputs"]
        assert "document" in forms[0]["file_inputs"]

    def test_parse_no_forms(self):
        forms = _parse_upload_forms(_NO_FORM_HTML)
        assert forms == []

    def test_parse_form_without_file_input(self):
        html = '<form action="/login"><input type="text" name="user" /></form>'
        forms = _parse_upload_forms(html)
        assert forms == []


# ---------------------------------------------------------------------------
# Unrestricted type test
# ---------------------------------------------------------------------------


class TestUnrestrictedType:
    @pytest.mark.asyncio
    async def test_dangerous_extension_accepted(self):
        """Server accepts .php upload → unrestricted_type finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            # Accept all uploads
            return _text_response('{"status": "ok"}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is True
        type_vulns = [v for v in result.vulnerabilities if v.upload_type == "unrestricted_type"]
        assert len(type_vulns) >= 1
        assert type_vulns[0].confidence == 0.6
        assert type_vulns[0].severity == "high"

    @pytest.mark.asyncio
    async def test_webshell_accessible(self):
        """Uploaded .php file is accessible at /uploads/ → webshell finding (critical)."""
        from numasec.scanners.upload_tester import _MARKER

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if request.method == "GET" and "/uploads/" in url_str:
                return _text_response(f"<!-- {_MARKER} -->")
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"status": "ok"}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is True
        webshell_vulns = [v for v in result.vulnerabilities if v.upload_type == "webshell"]
        assert len(webshell_vulns) >= 1
        assert webshell_vulns[0].confidence == 1.0
        assert webshell_vulns[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_dangerous_extension_rejected(self):
        """Server rejects .php upload with error → no unrestricted_type finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response("Error: file type not allowed", status_code=400)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        type_vulns = [v for v in result.vulnerabilities if v.upload_type == "unrestricted_type"]
        assert len(type_vulns) == 0


# ---------------------------------------------------------------------------
# MIME bypass test
# ---------------------------------------------------------------------------


class TestMimeBypass:
    @pytest.mark.asyncio
    async def test_mime_bypass_detected(self):
        """.php with image/jpeg Content-Type accepted → mime_bypass finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"uploaded": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        mime_vulns = [v for v in result.vulnerabilities if v.upload_type == "mime_bypass"]
        assert len(mime_vulns) >= 1
        assert mime_vulns[0].confidence == 0.7
        assert mime_vulns[0].content_type_sent == "image/jpeg"


# ---------------------------------------------------------------------------
# Double extension test
# ---------------------------------------------------------------------------


class TestDoubleExtension:
    @pytest.mark.asyncio
    async def test_double_extension_accepted(self):
        """file.php.jpg accepted → double_ext finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        dbl_vulns = [v for v in result.vulnerabilities if v.upload_type == "double_ext"]
        assert len(dbl_vulns) >= 1
        assert dbl_vulns[0].confidence == 0.8
        assert dbl_vulns[0].severity == "high"

    @pytest.mark.asyncio
    async def test_double_extension_only_one_finding(self):
        """Only one double_ext finding emitted even if multiple accepted."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        dbl_vulns = [v for v in result.vulnerabilities if v.upload_type == "double_ext"]
        assert len(dbl_vulns) == 1


# ---------------------------------------------------------------------------
# Null byte test
# ---------------------------------------------------------------------------


class TestNullByte:
    @pytest.mark.asyncio
    async def test_null_byte_accepted(self):
        """file.php\\x00.jpg accepted → null_byte finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        nb_vulns = [v for v in result.vulnerabilities if v.upload_type == "null_byte"]
        assert len(nb_vulns) == 1
        assert nb_vulns[0].confidence == 0.8
        assert "null byte" in nb_vulns[0].evidence.lower()


# ---------------------------------------------------------------------------
# SVG XSS test
# ---------------------------------------------------------------------------


class TestSvgXss:
    @pytest.mark.asyncio
    async def test_svg_accepted(self):
        """SVG upload accepted → svg_xss finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        svg_vulns = [v for v in result.vulnerabilities if v.upload_type == "svg_xss"]
        assert len(svg_vulns) >= 1

    @pytest.mark.asyncio
    async def test_svg_accessible_high_confidence(self):
        """SVG file accessible at /uploads/ → confidence 1.0."""
        from numasec.scanners.upload_tester import _SVG_MARKER

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if request.method == "GET" and "/uploads/image.svg" in url_str:
                return _text_response(f"<svg>{_SVG_MARKER}</svg>")
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        svg_vulns = [v for v in result.vulnerabilities if v.upload_type == "svg_xss" and v.confidence == 1.0]
        assert len(svg_vulns) >= 1


# ---------------------------------------------------------------------------
# Polyglot test
# ---------------------------------------------------------------------------


class TestPolyglot:
    @pytest.mark.asyncio
    async def test_polyglot_accepted(self):
        """Polyglot JPEG+PHP accepted → polyglot finding."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        poly_vulns = [v for v in result.vulnerabilities if v.upload_type == "polyglot"]
        assert len(poly_vulns) == 1
        assert poly_vulns[0].confidence == 0.7


# ---------------------------------------------------------------------------
# No forms found
# ---------------------------------------------------------------------------


class TestNoForms:
    @pytest.mark.asyncio
    async def test_no_forms_clean_result(self):
        """Page without file upload forms → clean result."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response(_NO_FORM_HTML)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/no-upload")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False
        assert result.vulnerabilities == []
        assert result.forms_found == 0
        assert result.upload_fields_found == 0

    @pytest.mark.asyncio
    async def test_explicit_field_name_bypasses_discovery(self):
        """Explicit field_name skips form discovery."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return _text_response('{"ok": true}')
            return _text_response(_NO_FORM_HTML)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/api/upload", field_name="file")
        finally:
            httpx.AsyncClient.__init__ = original_init

        # With an explicit field, uploads should be attempted
        assert result.vulnerable is True
        assert len(result.vulnerabilities) > 0


# ---------------------------------------------------------------------------
# UploadResult serialization
# ---------------------------------------------------------------------------


class TestUploadResultSerialization:
    def test_to_dict_empty(self):
        result = UploadResult(target="http://target/upload")
        d = result.to_dict()
        assert d["target"] == "http://target/upload"
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["forms_found"] == 0
        assert d["upload_fields_found"] == 0
        assert d["duration_ms"] == 0.0
        assert "No file upload" in d["summary"]
        assert d["next_steps"] == []

    def test_to_dict_with_vulnerabilities(self):
        result = UploadResult(
            target="http://target/upload",
            vulnerable=True,
            forms_found=1,
            upload_fields_found=1,
            duration_ms=150.789,
            vulnerabilities=[
                UploadVulnerability(
                    upload_type="unrestricted_type",
                    filename_sent="test.php",
                    content_type_sent="application/x-php",
                    evidence="Server accepted test.php",
                    severity="high",
                    confidence=0.6,
                ),
                UploadVulnerability(
                    upload_type="mime_bypass",
                    filename_sent="bypass.php",
                    content_type_sent="image/jpeg",
                    evidence="MIME bypass accepted",
                    severity="high",
                    confidence=0.7,
                ),
            ],
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert d["forms_found"] == 1
        assert d["upload_fields_found"] == 1
        assert d["duration_ms"] == 150.79
        assert len(d["vulnerabilities"]) == 2

        v0 = d["vulnerabilities"][0]
        assert v0["type"] == "file_upload"
        assert v0["upload_type"] == "unrestricted_type"
        assert v0["filename_sent"] == "test.php"
        assert v0["severity"] == "high"
        assert v0["confidence"] == 0.6

        v1 = d["vulnerabilities"][1]
        assert v1["upload_type"] == "mime_bypass"
        assert v1["content_type_sent"] == "image/jpeg"
        assert v1["confidence"] == 0.7

        assert "File upload vulnerability confirmed" in d["summary"]
        assert "unrestricted_type" in d["summary"]
        assert "mime_bypass" in d["summary"]
        assert len(d["next_steps"]) > 0


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    @pytest.mark.asyncio
    async def test_webshell_confidence_1(self):
        """File accessible → confidence 1.0, severity critical."""
        from numasec.scanners.upload_tester import _MARKER

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if request.method == "GET" and "/uploads/" in url_str:
                return _text_response(f"<!-- {_MARKER} -->")
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        webshell_vulns = [v for v in result.vulnerabilities if v.upload_type == "webshell"]
        assert len(webshell_vulns) >= 1
        assert webshell_vulns[0].confidence == 1.0
        assert webshell_vulns[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_accepted_upload_confidence_06(self):
        """Upload accepted but not accessible → confidence 0.6."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                # Return 404 for all upload path checks
                url_str = str(request.url)
                if "/uploads/" in url_str or "/media/" in url_str or "/files/" in url_str:
                    return _text_response("Not Found", status_code=404)
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        type_vulns = [v for v in result.vulnerabilities if v.upload_type == "unrestricted_type"]
        assert len(type_vulns) >= 1
        assert type_vulns[0].confidence == 0.6
        assert type_vulns[0].severity == "high"

    @pytest.mark.asyncio
    async def test_double_ext_confidence_08(self):
        """Double extension accepted → confidence 0.8."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        dbl_vulns = [v for v in result.vulnerabilities if v.upload_type == "double_ext"]
        assert len(dbl_vulns) >= 1
        assert dbl_vulns[0].confidence == 0.8


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    @pytest.mark.asyncio
    async def test_python_upload_test_returns_json(self):
        """python_upload_test returns valid JSON string."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_upload_test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert data["target"] == "http://target/upload-page"
        assert isinstance(data["vulnerable"], bool)
        assert isinstance(data["vulnerabilities"], list)

    @pytest.mark.asyncio
    async def test_python_upload_test_with_field_name(self):
        """python_upload_test accepts explicit field_name."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return _text_response('{"ok": true}')
            return _text_response(_NO_FORM_HTML)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_upload_test("http://target/api/upload", field_name="doc")
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert data["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_python_upload_test_with_headers(self):
        """python_upload_test parses JSON headers string."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_upload_test(
                "http://target/upload-page",
                headers='{"Authorization": "Bearer test123"}',
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert "target" in data

    @pytest.mark.asyncio
    async def test_python_upload_test_invalid_headers_ignored(self):
        """Invalid JSON headers string is ignored gracefully."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response('{"ok": true}')

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_upload_test(
                "http://target/upload-page",
                headers="not-valid-json",
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert "target" in data


# ---------------------------------------------------------------------------
# Error handling & edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_http_error_during_upload(self):
        """HTTP error during upload is handled gracefully."""

        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            call_count += 1
            raise httpx.ConnectError("Connection refused")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        # Should not crash, may or may not have vulnerabilities
        assert isinstance(result, UploadResult)

    @pytest.mark.asyncio
    async def test_server_error_response(self):
        """500 response is not counted as accepted."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response("Internal Server Error", status_code=500)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False

    @pytest.mark.asyncio
    async def test_error_keyword_in_200_response(self):
        """200 response with error keyword is not accepted."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return _text_response(_FORM_HTML)
            return _text_response("Error: file type not allowed")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            tester = UploadTester(timeout=5.0)
            result = await tester.test("http://target/upload-page")
        finally:
            httpx.AsyncClient.__init__ = original_init

        # "error" keyword in body → not accepted
        assert result.vulnerable is False
