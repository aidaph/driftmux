from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from driftmux.planner import build_scan_plan
from driftmux.models import HostScanResult
from driftmux.scanners.nmap import NmapScanner
from driftmux.scanners.nuclei import NucleiScanner
from driftmux.scanners.nvd import NvdConfig, NvdCveScanner
from driftmux.scanners.plecost import PlecostScanner


WEB_PORTS = {
    80,
    81,
    443,
    444,
    591,
    593,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9443,
}


def is_web_candidate(service) -> bool:
    svc = (getattr(service, "service", "") or "").lower()
    product = (getattr(service, "product", "") or "").lower()
    port = int(getattr(service, "port", 0) or 0)

    if "http" in svc or "https" in svc:
        return True

    if any(x in product for x in ("apache", "nginx", "tomcat", "jetty", "nextcloud")):
        return True

    if port in WEB_PORTS:
        return True

    return False


def guess_scheme(service, configured_scheme: str) -> str:
    if configured_scheme in {"http", "https"}:
        return configured_scheme

    port = int(getattr(service, "port", 0) or 0)

    if port in {443, 8443, 9443}:
        return "https"

    if port in {80, 81, 8000, 8008, 8080, 8081, 8088, 8888}:
        return "http"

    return "auto"


@dataclass(slots=True)
class ScanConfig:
    ports: str | None = None
    nmap_script: str | None = None
    timeout: int = 120
    web_scheme: str = "auto"
    nuclei_profile: str = "fast"
    output_format: str = "json"
    output_dir: str = "reports"
    log_dir: str = "logs"
    deep_wordpress: bool = False

    # NVD backend
    vuln_backend: str = "none"
    min_cvss: float = 0.0
    nvd_api_key: str | None = None
    nvd_cache: str = "~/.cache/driftmux/nvd.sqlite"
    nvd_cache_ttl_hours: int = 168


class DriftmuxEngine:
    def __init__(self, config: ScanConfig):
        self.config = config

        self.nmap = NmapScanner(
            timeout=config.timeout,
            ports=config.ports,
            nmap_script=config.nmap_script,
        )

        self.nvd = NvdCveScanner(
            NvdConfig(
                enabled=config.vuln_backend == "nvd",
                api_key=config.nvd_api_key,
                min_cvss=config.min_cvss,
                cache_path=config.nvd_cache,
                cache_ttl_hours=config.nvd_cache_ttl_hours,
                timeout=max(20, min(config.timeout, 60)),
            )
        )

        self.nuclei = NucleiScanner(
            timeout=max(config.timeout, 180),
            profile=getattr(config, "nuclei_profile", "fast"),
        )

        self.plecost = PlecostScanner(
            timeout=max(config.timeout, 180),
            mode=config.web_scheme,
            deep=config.deep_wordpress,
        )

    def scan_host(self, host: str) -> HostScanResult:
        discovery = self.nmap.scan(host)

        final = HostScanResult(
            host=host,
            services=discovery.services.copy(),
            findings=discovery.findings.copy(),
            errors=discovery.errors.copy(),
            metadata=discovery.metadata.copy(),
        )

        final.metadata["config"] = {
            "ports": self.config.ports,
            "nmap_script": self.config.nmap_script,
            "timeout": self.config.timeout,
            "web_scheme": self.config.web_scheme,
            "nuclei_profile": self.config.nuclei_profile,
            "vuln_backend": self.config.vuln_backend,
            "min_cvss": self.config.min_cvss,
            "deep_wordpress": self.config.deep_wordpress,
        }

        if self.config.vuln_backend == "nvd":
            nvd_result = self.nvd.scan(host, discovery.services)
            final.findings.extend(nvd_result.findings)
            final.errors.extend(nvd_result.errors)
            final.metadata.update(nvd_result.metadata)

        if self.config.nuclei_profile != "passive":
            self._run_nuclei(host, discovery, final)

        self._run_plecost(host, discovery, final)

        return final


    def scan_hosts(self, hosts: list[str]) -> list[HostScanResult]:
        results: list[HostScanResult] = []

        for host in hosts:
            results.append(self.scan(host))

        return results


    def scan_targets(
        self,
        *,
        host: str | None = None,
        targets: str | None = None,
        max_hosts: int = 256,
    ) -> list[HostScanResult]:
        scan_hosts = collect_scan_hosts(
            host=host,
            targets=targets,
            max_hosts=max_hosts,
        )

        return self.scan_hosts(scan_hosts)

    def _run_nuclei(
            self,
            host: str,
            discovery: HostScanResult,
            final: HostScanResult,
        ) -> None:
            plan = build_scan_plan(
                host=host,
                services=discovery.services,
                passive_findings=final.findings,
                scheme=self.config.web_scheme,
                profile=self.config.nuclei_profile,
            )

            nuclei_result = self.nuclei.scan_many(
                host=host,
                targets=plan.nuclei_targets,
            )

            final.findings.extend(nuclei_result.findings)
            final.errors.extend(nuclei_result.errors)

    def _run_plecost(
        self,
        host: str,
        discovery: HostScanResult,
        final: HostScanResult,
    ) -> None:
        wp_done = False

        for service in discovery.services:
            if not wp_done and self.plecost.maybe_wordpress(host, service):
                plecost_result = self.plecost.scan(host, service)
                final.findings.extend(plecost_result.findings)
                final.errors.extend(plecost_result.errors)
                final.metadata.update(plecost_result.metadata)
                wp_done = True

        if not wp_done and self.plecost.maybe_wordpress(host):
            plecost_result = self.plecost.scan(host)
            final.findings.extend(plecost_result.findings)
            final.errors.extend(plecost_result.errors)
            final.metadata.update(plecost_result.metadata)

    def scan_hosts(self, hosts: Iterable[str]) -> list[HostScanResult]:
        return [self.scan_host(host) for host in hosts]