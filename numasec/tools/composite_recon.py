"""Composite reconnaissance tool — unifies port scan, tech fingerprint, subdomain, DNS, service probing, and CVE enrichment."""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


async def recon(
    target: str,
    checks: str = "ports,tech",
    ports: str = "top-100",
    timeout: float = 2.0,
) -> dict[str, Any]:
    """Unified recon: port scan, tech fingerprint, subdomain enumeration, DNS lookup,
    protocol-specific service probing, and CVE enrichment.

    Args:
        target: Hostname, IP, or URL to scan.
        checks: Comma-separated checks: ports, tech, subdomains, dns, services.
        ports: Port specification for port scan (top-100, top-1000, specific ports).
        timeout: Per-connection timeout in seconds.
    """
    check_set = {c.strip().lower() for c in checks.split(",")}
    results: dict[str, Any] = {"target": target, "checks_run": sorted(check_set)}

    # Normalize target for different tools
    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = parsed.hostname or target
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else f"http://{target}"

    # ------------------------------------------------------------------
    # Port scan — required as prerequisite for services and CVE enrichment
    # ------------------------------------------------------------------
    port_scan_data = None
    if "ports" in check_set or "services" in check_set:
        try:
            from numasec.scanners.python_connect import PythonConnectScanner

            scanner = PythonConnectScanner()
            port_scan_data = await scanner.scan_with_banners(hostname, ports=ports, timeout=timeout)
            results["ports"] = port_scan_data
        except Exception as exc:
            results["ports"] = {"error": str(exc)}

    if "tech" in check_set:
        try:
            from numasec.scanners.crawler import PythonTechFingerprinter

            fp = PythonTechFingerprinter(timeout=timeout)
            fp_result = await fp.fingerprint(base_url)
            results["technologies"] = fp_result.to_dict()
        except Exception as exc:
            results["technologies"] = {"error": str(exc)}

    if "subdomains" in check_set:
        try:
            from numasec.scanners.subdomain_scanner import PythonSubdomainScanner

            sub_scanner = PythonSubdomainScanner(timeout=timeout)
            sub_result = await sub_scanner.scan(hostname)
            results["subdomains"] = sub_result.to_dict()
        except Exception as exc:
            results["subdomains"] = {"error": str(exc)}

    if "dns" in check_set:
        try:
            from numasec.tools.recon_tools import dns_lookup

            results["dns"] = await dns_lookup(domain=hostname)
        except Exception as exc:
            results["dns"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Service probing — protocol-specific tests on discovered ports
    # ------------------------------------------------------------------
    if "services" in check_set and port_scan_data and isinstance(port_scan_data, dict):
        try:
            from numasec.scanners._base import PortInfo
            from numasec.scanners.service_prober import ServiceProber

            # Convert port scan dict to PortInfo objects for the prober
            port_infos: list[PortInfo] = []
            open_ports = port_scan_data.get("open_ports", port_scan_data.get("ports", {}))
            if isinstance(open_ports, dict):
                for port_str, info in open_ports.items():
                    port_num = int(port_str) if isinstance(port_str, str) else port_str
                    if isinstance(info, dict):
                        port_infos.append(
                            PortInfo(
                                port=port_num,
                                state="open",
                                service=info.get("service", ""),
                                version=info.get("version", ""),
                                banner=info.get("banner", ""),
                            )
                        )
            elif isinstance(open_ports, list):
                for info in open_ports:
                    if isinstance(info, dict):
                        port_infos.append(
                            PortInfo(
                                port=info.get("port", 0),
                                state="open",
                                service=info.get("service", ""),
                                version=info.get("version", ""),
                                banner=info.get("banner", ""),
                            )
                        )

            if port_infos:
                prober = ServiceProber()
                service_results = await prober.probe_all(hostname, port_infos, timeout=timeout + 3.0)
                results["services"] = {}
                for sr in service_results:
                    key = f"{sr.service}_{sr.port}" if sr.service else f"unknown_{sr.port}"
                    results["services"][key] = asdict(sr)
        except Exception as exc:
            results["services"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # CVE enrichment — match discovered service versions against known CVEs
    # ------------------------------------------------------------------
    if port_scan_data and isinstance(port_scan_data, dict):
        try:
            from numasec.scanners.cve_enricher import CVEEnricher

            enricher = CVEEnricher()
            open_ports = port_scan_data.get("open_ports", port_scan_data.get("ports", {}))

            # Build a list of port dicts for the batch enrichment API
            port_list: list[dict[str, Any]] = []
            port_keys: list[str] = []
            if isinstance(open_ports, dict):
                for k, v in open_ports.items():
                    if isinstance(v, dict):
                        port_list.append(dict(v))  # copy to avoid mutating original
                        port_keys.append(str(k))
            elif isinstance(open_ports, list):
                for idx, v in enumerate(open_ports):
                    if isinstance(v, dict):
                        port_list.append(dict(v))
                        port_keys.append(str(v.get("port", idx)))

            if port_list:
                await enricher.enrich_ports(port_list)
                cve_results: dict[str, Any] = {}
                for key, info in zip(port_keys, port_list, strict=True):
                    cves = info.get("cves", [])
                    if cves:
                        cve_results[key] = cves
                if cve_results:
                    results["cves"] = cve_results
        except Exception as exc:
            logger.debug("CVE enrichment failed: %s", exc)
            # CVE enrichment is non-critical; don't pollute results with errors

    # ------------------------------------------------------------------
    # Target profile synthesis — high-level classification for the agent
    # ------------------------------------------------------------------
    target_profile: dict[str, Any] = {}

    # Probable database from open ports
    if port_scan_data and isinstance(port_scan_data, dict):
        open_ports = port_scan_data.get("open_ports", port_scan_data.get("ports", []))
        port_numbers: set[int] = set()
        if isinstance(open_ports, dict):
            for v in open_ports.values():
                if isinstance(v, dict):
                    port_numbers.add(int(v.get("port", 0)))
        elif isinstance(open_ports, list):
            for v in open_ports:
                if isinstance(v, dict):
                    port_numbers.add(int(v.get("port", 0)))

        db_map = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 1433: "MSSQL", 6379: "Redis", 1521: "Oracle"}
        detected_dbs = [db_map[p] for p in port_numbers if p in db_map]
        target_profile["probable_database"] = detected_dbs[0] if detected_dbs else None
        target_profile["total_open_ports"] = len(port_numbers)
    else:
        target_profile["probable_database"] = None
        target_profile["total_open_ports"] = 0

    # Web server and technologies from fingerprinting
    tech_data = results.get("technologies", {})
    if isinstance(tech_data, dict):
        techs = tech_data.get("technologies", [])
        tech_names = []
        web_server = None
        for t in techs:
            name = t.get("name", "") if isinstance(t, dict) else str(t)
            tech_names.append(name)
            if not web_server and any(ws in name.lower() for ws in ("nginx", "apache", "iis", "caddy", "lighttpd")):
                web_server = name
        target_profile["web_server"] = web_server
        target_profile["technologies"] = tech_names
    else:
        target_profile["web_server"] = None
        target_profile["technologies"] = []

    # CVE summary
    cve_data = results.get("cves", {})
    critical_count = 0
    has_exploits = False
    if isinstance(cve_data, dict):
        for cve_list in cve_data.values():
            if isinstance(cve_list, list):
                for cve in cve_list:
                    if isinstance(cve, dict):
                        severity = str(cve.get("severity", "")).lower()
                        if severity in ("critical", "high"):
                            critical_count += 1
                        if cve.get("exploit_available"):
                            has_exploits = True
    target_profile["critical_cves"] = critical_count
    target_profile["has_known_exploits"] = has_exploits

    results["target_profile"] = target_profile

    return results
