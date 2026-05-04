from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Sequence

from auditbbox.models import HostScanResult


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
