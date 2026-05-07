from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path
from typing import Sequence

from driftmux.models import HostScanResult


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


def split_csv_values(values: list[str] | None) -> list[str]:
    """Split comma-separated CLI values while preserving order."""
    if not values:
        return []

    items: list[str] = []

    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                items.append(item)

    return items


def expand_targets(target: str, max_hosts: int = 256) -> list[str]:
    """
    Expand a target string into a list of hosts.

    Supports:
    - single IP: 192.168.1.10
    - hostname: example.org
    - CIDR: 192.168.1.0/24
    - comma-separated values: 192.168.1.0/30,example.org
    """

    import ipaddress

    raw_targets = [item.strip() for item in target.split(",") if item.strip()]
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

        hosts = [str(ip) for ip in network.hosts()]

        if len(hosts) > max_hosts:
            raise ValueError(
                f"Target {raw_target} expands to {len(hosts)} hosts; "
                f"maximum allowed is {max_hosts}."
            )

        expanded.extend(hosts)

    seen: set[str] = set()
    return [item for item in expanded if not (item in seen or seen.add(item))]

def collect_scan_hosts(
    *,
    host: str | None = None,
    hosts: list[str] | None = None,
    target: str | None = None,
    targets: list[str] | None = None,
    max_hosts: int = 256,
) -> list[str]:
    """
    Collect and expand all CLI host/target inputs into a unique host list.

    Accepted inputs:
    - --host: one host
    - --target: one host or CIDR
    """

    raw_targets: list[str] = []

    if host:
        raw_targets.append(host)

    raw_targets.extend(split_csv_values(hosts))

    if target:
        raw_targets.append(target)

    raw_targets.extend(split_csv_values(targets))

    if not raw_targets:
        raise ValueError("At least one of --host, --hosts, --target or --targets is required.")

    expanded: list[str] = []

    for raw_target in raw_targets:
        expanded.extend(expand_target(raw_target, max_hosts=max_hosts))

    seen: set[str] = set()
    unique: list[str] = []

    for item in expanded:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)

    return unique

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
    lines = ["# AuditBBox report", ""]
    for result in results:
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
    target.write_text("\n".join(lines), encoding="utf-8")
    return target
