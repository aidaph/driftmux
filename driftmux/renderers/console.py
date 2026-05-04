from __future__ import annotations

import click

from auditbbox.models import HostScanResult

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
