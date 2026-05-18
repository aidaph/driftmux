from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from typing import Sequence

from driftmux.models import Finding, HostScanResult


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def read_hosts(host_file: str | None = None, host: str | None = None) -> list[str]:
    hosts: list[str] = []
    if host:
        hosts.append(host.strip())
    if host_file:
        with open(host_file, encoding="utf-8") as fh:
            for line in fh:
                value = line.strip().strip("'").strip('"')
                if value:
                    hosts.append(value)
    deduped: list[str] = []
    for item in hosts:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def split_csv_values(value: str | None) -> list[str]:
    if not value:
        return []

    return [item.strip() for item in value.split(",") if item.strip()]


def expand_targets(target: str, max_hosts: int = 256) -> list[str]:
    """
    Expand a target string into a list of hosts.

    Supports:
    - single IP: 192.168.1.10
    - hostname: example.org
    - CIDR: 192.168.1.0/24
    - comma-separated values: 192.168.1.0/30,example.org
    """

    raw_targets = split_csv_values(target)
    expanded: list[str] = []

    for raw_target in raw_targets:
        try:
            network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError:
            expanded.append(raw_target)
            continue

        if network.num_addresses == 1:
            expanded.append(str(network.network_address))
            continue

        hosts: list[str] = []

        for ip in network.hosts():
            if len(hosts) >= max_hosts:
                break

            hosts.append(str(ip))

        expanded.extend(hosts)

    return deduplicate_preserving_order(expanded)

def collect_scan_hosts(
    *,
    host: str | None = None,
    targets: str | None = None,
    max_hosts: int = 256,
) -> list[str]:
    """
    Collect CLI inputs from --host and --target into a unique host list.
    """

    raw_targets: list[str] = []

    if host:
        raw_targets.append(host.strip())

    if targets:
        raw_targets.extend(split_csv_values(targets))

    if not raw_targets:
        raise ValueError("One of --host or --target is required.")

    expanded: list[str] = []

    for raw_target in raw_targets:
        expanded.extend(expand_targets(raw_target, max_hosts=max_hosts))

    return deduplicate_preserving_order(expanded)


def deduplicate_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)

    return unique

def safe_filename(value: str) -> str:
    """
    Convert a host, IP or URL into a filesystem-safe filename fragment.
    """
    value = value.strip()
    value = value.removeprefix("http://")
    value = value.removeprefix("https://")
    value = value.rstrip("/")

    # Evita problemas con puertos, rutas o caracteres raros.
    value = value.replace("/", "_")
    value = value.replace(":", "_")

    # Mantiene puntos para IPs/FQDNs.
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)

    return value.strip("._-") or "unknown"


def write_json(path: str | Path, results: Sequence[HostScanResult]) -> Path:
    target = Path(path)
    target.write_text(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_csv(path: str | Path, results: Sequence[HostScanResult]) -> Path:
    target = Path(path)
    with target.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["host", "scanner", "severity", "title", "port", "service", "detected_version", "reference", "confidence"],
        )
        writer.writeheader()
        for result in results:
            for finding in result.findings:
                writer.writerow(
                    {
                        "host": result.host,
                        "scanner": finding.scanner,
                        "severity": finding.normalized_severity(),
                        "title": finding.title,
                        "port": finding.port,
                        "service": finding.service,
                        "detected_version": finding.detected_version,
                        "reference": finding.reference,
                        "confidence": finding.confidence,
                    }
                )
    return target


def write_markdown(path: str | Path, results: Sequence[HostScanResult]) -> Path:
    target = Path(path)

    lines: list[str] = ["# Driftmux report", ""]

    for result in results:
        scanner = str(result.metadata.get("scanner") or "").lower()
        host = str(result.host or "").lower()

        is_openstack_report = (
            scanner == "openstack"
            or host == "openstack:neutron"
            or any(
                str(finding.scanner or "").lower() == "openstack"
                for finding in result.findings
            )
            or any(
                str(finding.service or "").lower() == "neutron-security-group"
                for finding in result.findings
            )
        )

        if is_openstack_report:
            lines.extend(_render_openstack_neutron_markdown(result))
            lines.append(
                f"<!-- DEBUG scanner={result.metadata.get('scanner')} host={result.host} findings={len(result.findings)} -->"
            )
        else:
            lines.extend(_render_default_markdown(result))

    target.write_text("\n".join(lines), encoding="utf-8")

    return target

def _render_default_markdown(result: HostScanResult) -> list[str]:
    lines: list[str] = []

    lines.append(f"## {result.host}")
    lines.append("")
    lines.append(f"- Services: {len(result.services)}")
    lines.append(f"- Findings: {len(result.findings)}")
    lines.append(f"- Errors: {len(result.errors)}")
    lines.append("")

    if result.services:
        lines.append("### Services")
        lines.append("")
        lines.append("| Port | Service | Product | Version | Labels |")
        lines.append("|---|---|---|---|---|")

        for service in result.services:
            lines.append(
                f"| {service.endpoint()} | {service.service} | {service.product} | {service.version} | {', '.join(service.classifications)} |"
            )

        lines.append("")

    if result.findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Scanner | Title | Service | Port | Confidence |")
        lines.append("|---|---|---|---|---|---|")

        for finding in result.findings:
            lines.append(
                f"| {finding.normalized_severity()} | {finding.scanner} | {finding.title} | {finding.service or ''} | {finding.port or ''} | {finding.confidence} |"
            )

        lines.append("")

    return lines


def _render_openstack_neutron_markdown(result: HostScanResult) -> list[str]:
    lines: list[str] = []

    lines.append("## Driftmux OpenStack Neutron Security Group Audit")
    lines.append("")
    lines.append(f"- Checked rules: {result.metadata.get('checked_rules', 0)}")
    lines.append(f"- Findings: {len(result.findings)}")
    lines.append(f"- Errors: {len(result.errors)}")
    lines.append("")

    grouped = _group_openstack_findings_by_project(result.findings)
    
    if not result.findings:
        lines.append("No public exposure of critical ports detected.")
        lines.append("")
        return lines

    for project in sorted(
        grouped.values(),
        key=lambda item: (
            -int(item.get("critical", 0)),
            -int(item.get("high", 0)),
            str(item.get("project_name") or ""),
        ),
    ):
        lines.append(
            f"### Project: {project.get('project_name')} `{project.get('project_id')}`"
        )
        lines.append("")
        lines.append(f"- Total findings: {project.get('total_findings', 0)}")
        lines.append(f"- Critical: {project.get('critical', 0)}")
        lines.append(f"- High: {project.get('high', 0)}")
        lines.append(f"- Medium: {project.get('medium', 0)}")
        lines.append(f"- Low: {project.get('low', 0)}")
        lines.append(f"- Info: {project.get('info', 0)}")
        lines.append("")

        lines.append("| Severity | Security group | Protocol | Ports | Source | Match | Rule ID |")
        lines.append("|---|---|---|---|---|---|---|")

        project_findings = sorted(
            project.get("findings", []),
            key=lambda item: (
                _severity_order(str(item.get("severity", ""))),
                str(item.get("security_group_name") or ""),
                str(item.get("port_range_min") or ""),
            ),
        )

        for finding in project_findings:
            port_min = finding.get("port_range_min")
            port_max = finding.get("port_range_max")

            if port_min is None and port_max is None:
                ports = "all"
            elif port_min == port_max:
                ports = str(port_min)
            else:
                ports = f"{port_min}-{port_max}"

            matched = finding.get("matched") or []
            if isinstance(matched, list):
                matched_text = ", ".join(str(item) for item in matched)
            else:
                matched_text = str(matched)

            lines.append(
                "| {severity} | {sg} | {proto} | {ports} | {src} | {matched} | {rule_id} |".format(
                    severity=str(finding.get("severity", "")).upper(),
                    sg=finding.get("security_group_name", ""),
                    proto=finding.get("protocol", ""),
                    ports=ports,
                    src=finding.get("remote_ip_prefix", ""),
                    matched=matched_text,
                    rule_id=finding.get("rule_id", ""),
                )
            )

        lines.append("")

    return lines

def _group_openstack_findings_by_project(findings: Sequence[Finding]) -> dict:
    grouped: dict[str, dict] = {}

    for finding in findings:
        metadata = finding.metadata or {}

        project_id = (
            metadata.get("project_id")
            or _project_from_title(finding.title)
            or "unknown-project-id"
        )
        project_name = (
            metadata.get("project_name")
            or _project_from_title(finding.title)
            or "unknown-project"
        )

        key = str(project_id)

        if key not in grouped:
            grouped[key] = {
                "project_id": project_id,
                "project_name": project_name,
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "findings": [],
            }

        severity = _normalize_openstack_severity(finding)

        grouped[key]["total_findings"] += 1

        if severity in grouped[key]:
            grouped[key][severity] += 1
        else:
            grouped[key]["info"] += 1

        grouped[key]["findings"].append(
            {
                "severity": severity,
                "title": finding.title,
                "rule_id": metadata.get("rule_id", ""),
                "security_group_id": metadata.get("security_group_id", ""),
                "security_group_name": metadata.get("security_group_name")
                or _security_group_from_title(finding.title),
                "protocol": metadata.get("protocol") or _protocol_from_title(finding.title),
                "port_range_min": metadata.get("port_range_min")
                if metadata.get("port_range_min") is not None
                else finding.port,
                "port_range_max": metadata.get("port_range_max")
                if metadata.get("port_range_max") is not None
                else finding.port,
                "remote_ip_prefix": metadata.get("remote_ip_prefix")
                or _remote_from_title(finding.title),
                "matched": metadata.get("matched") or _matched_from_title(finding.title),
            }
        )

    return grouped


def _normalize_openstack_severity(finding: Finding) -> str:
    raw = str(getattr(finding, "severity", "") or "").lower().strip()

    if raw in {"critical", "crit", "crítico", "critico"}:
        return "critical"
    if raw in {"high", "alta", "alto"}:
        return "high"
    if raw in {"medium", "moderate", "media", "medio"}:
        return "medium"
    if raw in {"low", "baja", "bajo"}:
        return "low"
    if raw in {"info", "informational"}:
        return "info"

    title = str(getattr(finding, "title", "") or "").lower()
    evidence = str(getattr(finding, "evidence", "") or "").lower()

    if (
        "all_ports" in title
        or "all ports" in title
        or "all_ports" in evidence
        or "all ports" in evidence
    ):
        return "critical"

    return "info"


def _severity_order(severity: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return order.get(severity.lower(), 99)


def _project_from_title(title: str) -> str | None:
    prefix = "OpenStack security group exposure: "

    if not title.startswith(prefix):
        return None

    rest = title[len(prefix):]

    if "/" not in rest:
        return None

    return rest.split("/", 1)[0].strip() or None


def _security_group_from_title(title: str) -> str | None:
    prefix = "OpenStack security group exposure: "

    if not title.startswith(prefix):
        return None

    rest = title[len(prefix):]

    if "/" not in rest:
        return None

    after_project = rest.split("/", 1)[1]

    if " exposes " not in after_project:
        return None

    return after_project.split(" exposes ", 1)[0].strip() or None


def _remote_from_title(title: str) -> str:
    marker = " to "

    if marker not in title:
        return ""

    rest = title.split(marker, 1)[1]

    if " " in rest:
        return rest.split(" ", 1)[0]

    return rest


def _matched_from_title(title: str) -> list[str]:
    if "(" not in title or ")" not in title:
        return []

    inside = title.rsplit("(", 1)[1].split(")", 1)[0]

    if not inside:
        return []

    return [inside]


def _protocol_from_title(title: str) -> str:
    if "/tcp" in title:
        return "tcp"
    if "/udp" in title:
        return "udp"
    return ""