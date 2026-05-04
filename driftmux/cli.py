from __future__ import annotations

from pathlib import Path

import click
import pyfiglet

from auditbbox.engine import AuditBBoxEngine, ScanConfig
from auditbbox.renderers.console import render_console
from auditbbox.utils import ensure_dir, read_hosts, write_csv, write_json, write_markdown


def banner() -> None:
    click.echo(pyfiglet.figlet_format("AuditBBox"))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host-file", type=click.Path(exists=True, dir_okay=False), help="File with one host per line")
@click.option("--host", help="Single host or URL to scan")
@click.option("--ports", help="Port selection for nmap, for example 1-1000 or 80,443,6443")
@click.option("--nmap-script", help="Nmap NSE scripts to run, for example vulners or default,vulners")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "csv", "markdown"], case_sensitive=False), default="json")
@click.option("--timeout", type=int, default=120, show_default=True, help="Timeout per external scanner")
@click.option("--http-only", is_flag=True, help="Prefer HTTP targets for web scanners")
@click.option("--https-only", is_flag=True, help="Prefer HTTPS targets for web scanners")
@click.option("--output-dir", default="reports", show_default=True, help="Directory for generated reports")
@click.option("--log-dir", default="logs", show_default=True, help="Directory for scan logs")
@click.option("--deep-wordpress", is_flag=True, help="Enable Plecost deep mode for WordPress")
def main(host_file: str | None, host: str | None, ports: str | None, nmap_script: str | None, output_format: str, timeout: int, http_only: bool, https_only: bool, output_dir: str, log_dir: str, deep_wordpress: bool) -> None:
    if not host and not host_file:
        raise click.UsageError("Provide --host or --host-file")
    if http_only and https_only:
        raise click.UsageError("Use only one of --http-only or --https-only")

    banner()
    scheme = "auto"
    if http_only:
        scheme = "http"
    elif https_only:
        scheme = "https"

    config = ScanConfig(
        ports=ports,
        nmap_script=nmap_script,
        timeout=timeout,
        web_scheme=scheme,
        output_format=output_format.lower(),
        output_dir=output_dir,
        log_dir=log_dir,
        deep_wordpress=deep_wordpress,
    )
    hosts = read_hosts(host_file=host_file, host=host)
    engine = AuditBBoxEngine(config)
    results = engine.scan_hosts(hosts)

    ensure_dir(output_dir)
    out_base = Path(output_dir) / "auditbbox-report"
    if config.output_format == "json":
        path = write_json(out_base.with_suffix(".json"), results)
    elif config.output_format == "csv":
        path = write_csv(out_base.with_suffix(".csv"), results)
    elif config.output_format == "markdown":
        path = write_markdown(out_base.with_suffix(".md"), results)
    else:
        path = None

    render_console(results)
    if path:
        click.echo(f"\nSaved report to {path}")


if __name__ == "__main__":
    main()
