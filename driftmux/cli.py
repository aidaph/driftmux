from __future__ import annotations

from pathlib import Path

import click
import pyfiglet

from driftmux.engine import DriftmuxEngine, ScanConfig
from driftmux.renderers.console import render_console
from driftmux.utils import ensure_dir, read_hosts, expand_targets, safe_filename, write_csv, write_json, write_markdown


def banner() -> None:
    click.echo(pyfiglet.figlet_format("Driftmux"))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--host-file", 
    type=click.Path(exists=True, dir_okay=False), 
    help="File with one host per line")
@click.option(
    "--host", 
    help="Single host, IP adsress or URL to scan")
@click.option(
    "--target",
    help="Target host, IP address, hostname or CIDR subnet to scan",
)
@click.option(
    "--max-hosts",
    type=int,
    default=256,
    show_default=True,
    help="Maximum number of hosts allowed when expanding CIDR targets.",
)
@click.option(
    "--ports", 
    help="Port selection for nmap, for example 1-1000 or 80,443,6443")
@click.option(
    "--nmap-script", 
    help="Nmap NSE scripts to run, for example vulners or default,vulners")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "csv", "markdown"], 
    case_sensitive=False),
    default="json")
@click.option(
    "--timeout", 
    type=int, 
    default=600, 
    show_default=True, 
    help="Timeout per external scanner")
@click.option(
    "--http-only", 
    is_flag=True, 
    help="Prefer HTTP targets for web scanners")
@click.option(
    "--https-only", 
    is_flag=True, 
    help="Prefer HTTPS targets for web scanners")
@click.option(
    "--output-dir", 
    default="reports", show_default=True, 
    help="Directory for generated reports")
@click.option(
    "--log-dir", 
    default="logs", 
    show_default=True, 
    help="Directory for scan logs")
@click.option(
    "--deep-wordpress", 
    is_flag=True, 
    help="Enable Plecost deep mode for WordPress")
@click.option(
    "--profile",
    "nuclei_profile",
    type=click.Choice(["passive", "fast", "deep"], case_sensitive=False),
    default="fast",
    show_default=True,
    help="Scan profile. passive disables Nuclei; fast/deep run Nuclei.",
)
@click.option(
    "--vuln-backend",
    type=click.Choice(["none", "nvd"], case_sensitive=False),
    default="none",
    show_default=True,
    help="Passive vulnerability backend.",
)
@click.option(
    "--min-cvss",
    type=float,
    default=0.0,
    show_default=True,
    help="Minimum CVSS score for passive vulnerability findings.",
)
@click.option(
    "--nvd-api-key",
    default=None,
    help="NVD API key. If omitted, Driftmux also checks the NVD_API_KEY environment variable.",
)
@click.option(
    "--nvd-cache",
    default="~/.cache/driftmux/nvd.sqlite",
    show_default=True,
    help="SQLite cache path for NVD responses.",
)
@click.option(
    "--nvd-cache-ttl-hours",
    type=int,
    default=168,
    show_default=True,
    help="How long cached NVD responses remain valid.",
)
def main(
    host_file: str | None,
    host: str | None,
    target: str | None,
    max_hosts: int,
    ports: str | None,
    nmap_script: str | None,
    output_format: str,
    timeout: int,
    http_only: bool,
    https_only: bool,
    output_dir: str,
    log_dir: str,
    deep_wordpress: bool,
    nuclei_profile: str,
    vuln_backend: str,
    min_cvss: float,
    nvd_api_key: str | None,
    nvd_cache: str,
    nvd_cache_ttl_hours: int,
) -> None:
    if not host and not host_file and not target:
        raise click.UsageError("Provide one of --host, --host-file or --target.")

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
        nuclei_profile=nuclei_profile.lower(),
        output_format=output_format.lower(),
        output_dir=output_dir,
        log_dir=log_dir,
        deep_wordpress=deep_wordpress,
        vuln_backend=vuln_backend.lower(),
        min_cvss=min_cvss,
        nvd_api_key=nvd_api_key,
        nvd_cache=nvd_cache,
        nvd_cache_ttl_hours=nvd_cache_ttl_hours,
    )

    hosts: list[str] = []

    if host_file:
        hosts.extend(read_hosts(host_file=host_file, host=None))

    if host:
        hosts.append(host)

    if target:
        try:
            hosts.extend(expand_targets(target, max_hosts=max_hosts))
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc

    seen: set[str] = set()
    hosts = [item for item in hosts if not (item in seen or seen.add(item))]

    if not hosts:
        raise click.UsageError("No valid hosts were provided.")

    engine = DriftmuxEngine(config)
    results = engine.scan_hosts(hosts)

    ensure_dir(output_dir)

    if len(results) == 1:
        report_name = f"driftmux-report-{safe_filename(results[0].host)}"
    else:
        report_name = "driftmux-report-multiple-hosts"

    out_base = Path(output_dir) / report_name

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