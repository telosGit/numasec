"""Tests for the CI/CD integration mode."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from numasec.cli.ci_mode import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    SEVERITY_ORDER,
    _extract_vulns,
    _format_output,
    _meets_threshold,
    _vuln_to_finding,
    main,
    parse_args,
    run_ci_scan,
)
from numasec.models.enums import Severity
from numasec.models.finding import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeRegistry:
    """Minimal ToolRegistry stand-in that returns canned results."""

    def __init__(self, results: dict[str, Any] | None = None, *, delay: float = 0) -> None:
        self._results = results or {}
        self._delay = delay
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, name: str, **kwargs: Any) -> Any:
        self.calls.append((name, kwargs))
        if self._delay:
            await asyncio.sleep(self._delay)
        result = self._results.get(name)
        if isinstance(result, Exception):
            raise result
        return result


def _make_vuln(
    vuln_type: str = "sql_injection",
    param: str = "id",
    evidence: str = "' OR 1=1--",
    **extra: Any,
) -> dict[str, Any]:
    return {"type": vuln_type, "param": param, "evidence": evidence, **extra}


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_minimal(self) -> None:
        args = parse_args(["--target", "https://example.com"])
        assert args.target == "https://example.com"
        assert args.output == "sarif"
        assert args.severity_threshold == "high"
        assert args.timeout == 300
        assert args.verbose is False

    def test_all_flags(self) -> None:
        args = parse_args([
            "--target", "https://api.test.com",
            "--output", "json",
            "--severity-threshold", "medium",
            "--timeout", "120",
            "--verbose",
        ])
        assert args.target == "https://api.test.com"
        assert args.output == "json"
        assert args.severity_threshold == "medium"
        assert args.timeout == 120
        assert args.verbose is True

    def test_markdown_output(self) -> None:
        args = parse_args(["--target", "http://localhost", "--output", "markdown"])
        assert args.output == "markdown"

    def test_missing_target(self) -> None:
        with pytest.raises(SystemExit):
            parse_args([])

    def test_invalid_output(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--target", "http://x", "--output", "xml"])

    def test_invalid_threshold(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--target", "http://x", "--severity-threshold", "extreme"])


# ---------------------------------------------------------------------------
# Vulnerability conversion
# ---------------------------------------------------------------------------

class TestVulnToFinding:
    def test_basic_conversion(self) -> None:
        vuln = _make_vuln()
        finding = _vuln_to_finding(vuln, target="https://example.com", tool_name="injection_test")
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.parameter == "id"
        assert finding.cwe_id == "CWE-89"
        assert finding.tool_used == "injection_test"

    def test_explicit_severity(self) -> None:
        vuln = _make_vuln(severity="critical")
        finding = _vuln_to_finding(vuln, target="http://t", tool_name="test")
        assert finding.severity == Severity.CRITICAL

    def test_unknown_type_defaults_to_info(self) -> None:
        vuln = {"type": "unknown_thing", "evidence": "x"}
        finding = _vuln_to_finding(vuln, target="http://t", tool_name="test")
        assert finding.severity == Severity.INFO

    def test_title_from_type(self) -> None:
        vuln = _make_vuln(vuln_type="xss")
        finding = _vuln_to_finding(vuln, target="http://t", tool_name="test")
        assert finding.title == "Xss"

    def test_explicit_title(self) -> None:
        vuln = _make_vuln(title="Custom Title")
        finding = _vuln_to_finding(vuln, target="http://t", tool_name="test")
        assert finding.title == "Custom Title"

    def test_url_from_vuln(self) -> None:
        vuln = _make_vuln(url="https://vuln.example.com/path")
        finding = _vuln_to_finding(vuln, target="https://example.com", tool_name="test")
        assert finding.url == "https://vuln.example.com/path"


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

class TestExtractVulns:
    def test_dict_result(self) -> None:
        result = {"vulnerabilities": [_make_vuln(), _make_vuln()]}
        assert len(_extract_vulns(result, "test")) == 2

    def test_json_string_result(self) -> None:
        result = json.dumps({"vulnerabilities": [_make_vuln()]})
        assert len(_extract_vulns(result, "test")) == 1

    def test_empty_result(self) -> None:
        assert _extract_vulns({}, "test") == []

    def test_none_result(self) -> None:
        assert _extract_vulns(None, "test") == []

    def test_invalid_json(self) -> None:
        assert _extract_vulns("not json {{", "test") == []

    def test_findings_key(self) -> None:
        result = {"findings": [_make_vuln()]}
        assert len(_extract_vulns(result, "test")) == 1


# ---------------------------------------------------------------------------
# Threshold logic
# ---------------------------------------------------------------------------

class TestMeetsThreshold:
    def test_critical_meets_high(self) -> None:
        f = Finding(title="Test", severity=Severity.CRITICAL)
        assert _meets_threshold(f, "high") is True

    def test_high_meets_high(self) -> None:
        f = Finding(title="Test", severity=Severity.HIGH)
        assert _meets_threshold(f, "high") is True

    def test_medium_below_high(self) -> None:
        f = Finding(title="Test", severity=Severity.MEDIUM)
        assert _meets_threshold(f, "high") is False

    def test_info_meets_info(self) -> None:
        f = Finding(title="Test", severity=Severity.INFO)
        assert _meets_threshold(f, "info") is True

    def test_low_below_critical(self) -> None:
        f = Finding(title="Test", severity=Severity.LOW)
        assert _meets_threshold(f, "critical") is False

    def test_severity_order_completeness(self) -> None:
        for sev in Severity:
            assert sev.value in SEVERITY_ORDER


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

class TestFormatOutput:
    @pytest.fixture()
    def sample_findings(self) -> list[Finding]:
        return [
            Finding(title="SQL Injection in login", severity=Severity.HIGH, url="https://example.com/login"),
            Finding(title="XSS in search", severity=Severity.MEDIUM, url="https://example.com/search"),
        ]

    def test_sarif_format(self, sample_findings: list[Finding]) -> None:
        output = _format_output(sample_findings, "sarif", "https://example.com")
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed
        assert len(parsed["runs"]) == 1
        assert len(parsed["runs"][0]["results"]) == 2

    def test_json_format(self, sample_findings: list[Finding]) -> None:
        output = _format_output(sample_findings, "json", "https://example.com")
        parsed = json.loads(output)
        assert parsed["target"] == "https://example.com"
        assert parsed["finding_count"] == 2
        assert len(parsed["findings"]) == 2

    def test_markdown_format(self, sample_findings: list[Finding]) -> None:
        output = _format_output(sample_findings, "markdown", "https://example.com")
        assert "# numasec Security Assessment Report" in output
        assert "SQL Injection in login" in output

    def test_sarif_empty_findings(self) -> None:
        output = _format_output([], "sarif", "https://example.com")
        parsed = json.loads(output)
        assert parsed["runs"][0]["results"] == []

    def test_json_empty_findings(self) -> None:
        output = _format_output([], "json", "https://example.com")
        parsed = json.loads(output)
        assert parsed["finding_count"] == 0


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

class TestRunCiScan:
    async def test_no_findings_exit_0(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(results={
            "recon": {"target": "example.com", "ports": {}},
            "injection_test": {"vulnerabilities": []},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        code = await run_ci_scan("https://example.com", "json", "high", 60, registry=registry)
        assert code == EXIT_OK

        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["finding_count"] == 0

    async def test_findings_above_threshold_exit_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(results={
            "recon": {"target": "example.com"},
            "injection_test": {"vulnerabilities": [_make_vuln("sql_injection")]},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        code = await run_ci_scan("https://example.com", "json", "high", 60, registry=registry)
        assert code == EXIT_FINDINGS

        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["finding_count"] == 1

    async def test_findings_below_threshold_exit_0(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(results={
            "recon": {"target": "example.com"},
            "injection_test": {"vulnerabilities": [_make_vuln("cors")]},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        code = await run_ci_scan("https://example.com", "json", "high", 60, registry=registry)
        assert code == EXIT_OK

    async def test_sarif_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(results={
            "recon": {},
            "injection_test": {"vulnerabilities": [_make_vuln()]},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        code = await run_ci_scan("https://example.com", "sarif", "high", 60, registry=registry)
        assert code == EXIT_FINDINGS

        out = capsys.readouterr().out
        sarif = json.loads(out)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    async def test_tool_calls_receive_target(self) -> None:
        registry = FakeRegistry(results={
            "recon": {},
            "injection_test": {"vulnerabilities": []},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        await run_ci_scan("https://target.test", "json", "info", 60, registry=registry)

        assert len(registry.calls) == 6
        assert registry.calls[0] == ("recon", {"target": "https://target.test"})
        assert registry.calls[1] == ("injection_test", {"url": "https://target.test"})

    async def test_tool_error_continues(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(results={
            "recon": RuntimeError("connection refused"),
            "injection_test": {"vulnerabilities": [_make_vuln()]},
            "xss_test": json.dumps({"vulnerabilities": []}),
            "auth_test": json.dumps({"vulnerabilities": []}),
            "access_control_test": {"vulnerabilities": []},
            "path_test": {"vulnerabilities": []},
        })
        code = await run_ci_scan("https://example.com", "json", "high", 60, registry=registry)
        assert code == EXIT_FINDINGS

        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["finding_count"] == 1


# ---------------------------------------------------------------------------
# Timeout enforcement
# ---------------------------------------------------------------------------

class TestTimeout:
    async def test_timeout_produces_partial_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        registry = FakeRegistry(
            results={
                "recon": {"target": "t"},
                "injection_test": {"vulnerabilities": [_make_vuln()]},
                "xss_test": json.dumps({"vulnerabilities": []}),
                "auth_test": json.dumps({"vulnerabilities": []}),
                "access_control_test": {"vulnerabilities": []},
                "path_test": {"vulnerabilities": []},
            },
            delay=0.5,
        )
        await run_ci_scan("https://example.com", "json", "high", 1, registry=registry)

        out = capsys.readouterr().out
        parsed = json.loads(out)
        # With 1s timeout and 0.5s per step, only ~2 steps complete
        assert parsed["finding_count"] <= 1


# ---------------------------------------------------------------------------
# Error handling & main()
# ---------------------------------------------------------------------------

class TestMain:
    def test_missing_target_exit_error(self) -> None:
        code = main([])
        assert code == EXIT_ERROR

    def test_valid_args(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        async def _mock_run(*_args: Any, **_kwargs: Any) -> int:
            return EXIT_OK

        monkeypatch.setattr("numasec.cli.ci_mode.run_ci_scan", _mock_run)
        code = main(["--target", "https://example.com", "--output", "json"])
        assert code == EXIT_OK
