"""Tests for community template management CLI."""

from __future__ import annotations

import pytest

from numasec.cli.templates import BUNDLED_DIR, cmd_install, cmd_list, cmd_update, parse_args


class TestParseArgs:
    def test_list(self):
        args = parse_args(["list"])
        assert args.command == "list"

    def test_install_url(self):
        args = parse_args(["install", "https://example.com/template.yaml"])
        assert args.command == "install"
        assert args.source == "https://example.com/template.yaml"

    def test_install_path(self):
        args = parse_args(["install", "/tmp/templates/"])
        assert args.command == "install"
        assert args.source == "/tmp/templates/"

    def test_update(self):
        args = parse_args(["update"])
        assert args.command == "update"

    def test_missing_command(self):
        with pytest.raises(SystemExit):
            parse_args([])


class TestCmdList:
    def test_list_bundled(self, capsys):
        args = parse_args(["list"])
        rc = cmd_list(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "security-headers" in out or "Bundled" in out or "No templates" in out


class TestCmdInstall:
    def test_install_file(self, tmp_path, capsys):
        src = tmp_path / "test-scanner.yaml"
        src.write_text("id: test\nname: Test\nmatchers:\n  - type: status_code\n    code: 200\n")

        args = parse_args(["install", str(src)])
        # Temporarily override TEMPLATES_DIR
        import numasec.cli.templates as mod

        orig = mod.TEMPLATES_DIR
        mod.TEMPLATES_DIR = tmp_path / "installed"
        try:
            rc = cmd_install(args)
        finally:
            mod.TEMPLATES_DIR = orig

        assert rc == 0
        assert (tmp_path / "installed" / "test-scanner.yaml").exists()

    def test_install_directory(self, tmp_path, capsys):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "a.yaml").write_text("id: a\nmatchers: []\n")
        (src_dir / "b.yaml").write_text("id: b\nmatchers: []\n")
        (src_dir / "_skip.yaml").write_text("id: skip\n")

        args = parse_args(["install", str(src_dir)])
        import numasec.cli.templates as mod

        orig = mod.TEMPLATES_DIR
        mod.TEMPLATES_DIR = tmp_path / "installed"
        try:
            rc = cmd_install(args)
        finally:
            mod.TEMPLATES_DIR = orig

        assert rc == 0
        assert (tmp_path / "installed" / "a.yaml").exists()
        assert (tmp_path / "installed" / "b.yaml").exists()

    def test_install_invalid_source(self, capsys):
        args = parse_args(["install", "/nonexistent/path"])
        rc = cmd_install(args)
        assert rc == 2

    def test_install_empty_dir(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        args = parse_args(["install", str(empty)])
        import numasec.cli.templates as mod

        orig = mod.TEMPLATES_DIR
        mod.TEMPLATES_DIR = tmp_path / "installed"
        try:
            rc = cmd_install(args)
        finally:
            mod.TEMPLATES_DIR = orig
        assert rc == 2


class TestCmdUpdate:
    def test_update_installs_bundled(self, tmp_path, capsys):
        args = parse_args(["update"])
        import numasec.cli.templates as mod

        orig = mod.TEMPLATES_DIR
        mod.TEMPLATES_DIR = tmp_path / "installed"
        try:
            rc = cmd_update(args)
        finally:
            mod.TEMPLATES_DIR = orig

        if BUNDLED_DIR.is_dir():
            assert rc == 0
            installed = list((tmp_path / "installed").glob("*.yaml"))
            assert len(installed) >= 1


class TestBundledTemplates:
    def test_bundled_dir_exists(self):
        assert BUNDLED_DIR.is_dir(), f"Bundled templates dir missing: {BUNDLED_DIR}"

    def test_all_templates_have_required_fields(self):
        import yaml

        for f in BUNDLED_DIR.glob("*.yaml"):
            with open(f) as fh:
                data = yaml.safe_load(fh)
            assert "id" in data, f"{f.name} missing 'id'"
            assert "matchers" in data, f"{f.name} missing 'matchers'"
            assert isinstance(data["matchers"], list), f"{f.name} matchers must be a list"


class TestTemplateRegistration:
    def test_templates_registered_in_tool_registry(self):
        from numasec.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        template_tools = [t for t in registry._tools if t.startswith("template_")]
        assert len(template_tools) >= 6
        assert "template_security-headers" in template_tools
