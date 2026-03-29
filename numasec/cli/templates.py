"""Community template management CLI.

Install, list, and update YAML scanner templates from local or remote sources.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("numasec.cli.templates")

TEMPLATES_DIR = Path.home() / ".numasec" / "templates"
BUNDLED_DIR = Path(__file__).resolve().parent.parent.parent / "community-templates"


def _ensure_dir() -> Path:
    """Ensure ~/.numasec/templates exists."""
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    return TEMPLATES_DIR


def cmd_list(_args: argparse.Namespace) -> int:
    """List installed community templates."""
    _ensure_dir()
    templates = sorted(TEMPLATES_DIR.glob("*.yaml")) + sorted(TEMPLATES_DIR.glob("*.yml"))
    bundled = sorted(BUNDLED_DIR.glob("*.yaml")) + sorted(BUNDLED_DIR.glob("*.yml")) if BUNDLED_DIR.is_dir() else []

    if not templates and not bundled:
        print("No templates installed. Use 'install' to add templates.")
        return 0

    if bundled:
        print(f"Bundled templates ({len(bundled)}):")
        for t in bundled:
            print(f"  {t.stem}")

    if templates:
        print(f"\nUser templates in {TEMPLATES_DIR} ({len(templates)}):")
        for t in templates:
            print(f"  {t.stem}")

    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Install templates from a URL or local path."""
    source = args.source
    dest = _ensure_dir()

    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        return _install_from_url(source, dest)

    src_path = Path(source)
    if src_path.is_file() and src_path.suffix in (".yaml", ".yml"):
        return _install_file(src_path, dest)

    if src_path.is_dir():
        return _install_dir(src_path, dest)

    print(f"Error: '{source}' is not a valid URL, file, or directory.", file=sys.stderr)
    return 2


def _install_from_url(url: str, dest: Path) -> int:
    """Download a YAML template from a URL."""
    try:
        import httpx

        resp = httpx.get(url, follow_redirects=True, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        print(f"Error downloading {url}: {exc}", file=sys.stderr)
        return 2

    filename = Path(urlparse(url).path).name
    if not filename.endswith((".yaml", ".yml")):
        filename += ".yaml"

    target = dest / filename
    target.write_text(resp.text, encoding="utf-8")
    print(f"Installed: {filename} → {target}")
    return 0


def _install_file(src: Path, dest: Path) -> int:
    """Copy a single template file."""
    target = dest / src.name
    shutil.copy2(src, target)
    print(f"Installed: {src.name} → {target}")
    return 0


def _install_dir(src: Path, dest: Path) -> int:
    """Copy all YAML templates from a directory."""
    count = 0
    for f in sorted(src.glob("*.yaml")) + sorted(src.glob("*.yml")):
        if f.name.startswith("_"):
            continue
        shutil.copy2(f, dest / f.name)
        count += 1
        print(f"  Installed: {f.name}")

    if count == 0:
        print("No .yaml/.yml templates found in directory.", file=sys.stderr)
        return 2

    print(f"\n{count} template(s) installed to {dest}")
    return 0


def cmd_update(_args: argparse.Namespace) -> int:
    """Re-install bundled templates to user directory."""
    if not BUNDLED_DIR.is_dir():
        print("Bundled templates directory not found.", file=sys.stderr)
        return 2

    return _install_dir(BUNDLED_DIR, _ensure_dir())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="python -m numasec.cli.templates",
        description="Manage numasec community scanner templates",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List installed templates")

    install_p = sub.add_parser("install", help="Install templates from URL or path")
    install_p.add_argument("source", help="URL, file path, or directory")

    sub.add_parser("update", help="Re-install bundled templates")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    commands = {
        "list": cmd_list,
        "install": cmd_install,
        "update": cmd_update,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
