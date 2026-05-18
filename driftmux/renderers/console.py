from __future__ import annotations

import click

from driftmux.models import HostScanResult

COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
    "unknown": "white",
}


def render_console(results: list[HostScanResult]) -> None:
    for result in results:
        if _is_openstack_result(result):
            _render_openstack_console(result)
        else:
            click.echo(click.style(f"\n[{result.host}]", fg="green", bold=True))
            click.echo(f"Services: {len(result.services)} | Findings: {len(result.findings)} | Errors: {len(result.errors)}")
            for service in result.services:
                labels = ", ".join(service.classifications) or "generic"
                click.echo(f"  - {service.endpoint():<10} {service.service:<12} {service.product} {service.version} [{labels}]")
            for finding in result.findings:
                color = COLORS.get(finding.normalized_severity(), "white")
                sev = click.style(finding.normalized_severity().upper(), fg=color, bold=True)
                click.echo(f"  * {sev} {finding.scanner}: {finding.title}")
            for error in result.errors:
                click.echo(click.style(f"  ! {error.scanner}: {error.message}", fg="red"))

def _is_openstack_result(result) -> bool:
    scanner = str(result.metadata.get("scanner") or "").lower()
    host = str(result.host or "").lower()

    return (
        scanner in {"openstack", "openstack-neutron"}
        or host == "openstack:neutron"
        or any(
            str(finding.scanner or "").lower() in {"openstack", "openstack-neutron"}
            for finding in result.findings
        )
        or any(
            str(finding.service or "").lower() == "neutron-security-group"
            for finding in result.findings
        )
    )

def _render_openstack_console(result) -> None:
    grouped = _group_openstack_console_findings_by_project(result.findings)

    print()
    print("OpenStack Neutron Security Group Audit")
    print(f"Checked rules: {result.metadata.get('checked_rules', 0)}")
    print(f"Findings: {len(result.findings)}")
    print(f"Errors: {len(result.errors)}")
    print()

    if not result.findings:
        print("No public exposure of critical ports detected.")
        return

    for project in sorted(
        grouped.values(),
        key=lambda item: (
            -item.get("critical", 0),
            -item.get("high", 0),
            item.get("project_name", ""),
        ),
    ):
        print(
            f"[{project['project_name']}] "
            f"total={project['total_findings']} "
            f"critical={project['critical']} "
            f"high={project['high']}"
        )

        for finding in project["findings"]:
            print(
                "  - {severity} sg={sg} ports={ports} src={src} match={match} used_by={used_by}".format(
                    severity=finding.get("severity", "").upper(),
                    sg=finding.get("security_group_name", ""),
                    ports=finding.get("ports", ""),
                    src=finding.get("remote_ip_prefix", ""),
                    match=", ".join(finding.get("matched") or []),
                    used_by=finding.get("used_by_count", "unknown"),
                )
            )

        print()

def _group_openstack_console_findings_by_project(findings):
    grouped = {}

    for finding in findings:
        metadata = finding.metadata or {}

        project_id = metadata.get("project_id") or "unknown-project-id"
        project_name = metadata.get("project_name") or project_id

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

        severity = str(finding.severity or finding.normalized_severity() or "info").lower()

        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "info"

        port_min = metadata.get("port_range_min")
        port_max = metadata.get("port_range_max")

        if port_min is None and port_max is None:
            ports = "all"
        elif port_min == port_max:
            ports = str(port_min)
        else:
            ports = f"{port_min}-{port_max}"

        grouped[key]["total_findings"] += 1
        grouped[key][severity] += 1

        grouped[key]["findings"].append(
            {
                "severity": severity,
                "security_group_name": metadata.get("security_group_name"),
                "ports": ports,
                "remote_ip_prefix": metadata.get("remote_ip_prefix"),
                "matched": metadata.get("matched") or [],
                "used_by_count": metadata.get("used_by_count"),
            }
        )

    return grouped