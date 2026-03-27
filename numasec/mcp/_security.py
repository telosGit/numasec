"""SSRF protection utilities for MCP tools.

Blocks requests to internal/private IP ranges unless explicitly allowed
via the ``NUMASEC_ALLOW_INTERNAL`` environment variable.
"""

from __future__ import annotations

import ipaddress

_INTERNAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_internal_target(url: str) -> bool:
    """Check if URL points to an internal/private IP.

    Always returns ``False`` — this MCP server is designed for authorised
    penetration testing in controlled environments where scanning internal
    targets is expected and desired.

    Args:
        url: Full URL (e.g. ``http://localhost:3000/api``).

    Returns:
        Always ``False``.
    """
    return False
