from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from auditbbox.models import HostScanResult
from auditbbox.scanners.nmap import NmapScanner
from auditbbox.scanners.nuclei import NucleiScanner
from auditbbox.scanners.plecost import PlecostScanner


@dataclass(slots=True)
class ScanConfig:
    ports: str | None = None
    nmap_script: str | None = None
    timeout: int = 120
    web_scheme: str = "auto"
    output_format: str = "json"
    output_dir: str = "reports"
    log_dir: str = "logs"
    deep_wordpress: bool = False


class AuditBBoxEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.nmap = NmapScanner(timeout=config.timeout, ports=config.ports, nmap_script=config.nmap_script)
        self.nuclei = NucleiScanner(timeout=max(config.timeout, 180))
        self.plecost = PlecostScanner(timeout=max(config.timeout, 180), mode=config.web_scheme, deep=config.deep_wordpress)

    def scan_host(self, host: str) -> HostScanResult:
        discovery = self.nmap.scan(host)
        final = HostScanResult(host=host, services=discovery.services.copy(), findings=discovery.findings.copy(), errors=discovery.errors.copy())
        wp_done = False
        for service in discovery.services:
            nuclei_result = self.nuclei.scan(host, service, scheme=self.config.web_scheme)
            final.findings.extend(nuclei_result.findings)
            final.errors.extend(nuclei_result.errors)
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
        return final

    def scan_hosts(self, hosts: Iterable[str]) -> list[HostScanResult]:
        return [self.scan_host(host) for host in hosts]
