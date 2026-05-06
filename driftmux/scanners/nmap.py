from __future__ import annotations

import shlex
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from driftmux.models import HostScanResult
from driftmux.parsers.nmap import NmapXmlParser


@dataclass(slots=True)
class NmapScanner:
    timeout: int = 600
    ports: str | None = None
    nmap_script: str | None = None
    extra_args: list[str] = field(default_factory=list)
    debug: bool = False

    def scan(self, host: str) -> HostScanResult:
        if self.ports:
            return self._run_version_scan(host, self.ports)

        return self._run_version_discovery_scan(host)

    def _run_version_discovery_scan(self, host: str) -> HostScanResult:
        command = [
            "nmap",
            "-sV",
            "-Pn",
            "--open",
        ]

        if self.nmap_script:
            command.extend(["--script", self.nmap_script])

        if self.extra_args:
            command.extend(self.extra_args)

        command.extend(["-oX", "-", host])

        return self._run_and_parse(command, host, mode="single_phase_version_discovery", ports="default")

    def _run_version_scan(self, host: str, ports: str) -> HostScanResult:
        command = [
            "nmap",
            "-sV",
            "-Pn",
            "-p",
            ports,
        ]

        if self.nmap_script:
            command.extend(["--script", self.nmap_script])

        if self.extra_args:
            command.extend(self.extra_args)

        command.extend(["-oX", "-", host])

        return self._run_and_parse(command, host, mode="direct_version", ports=ports)

    def _run_and_parse(
        self,
        command: list[str],
        host: str,
        *,
        mode: str,
        ports: str,
    ) -> HostScanResult:
        proc = self._run_command(command)

        result = HostScanResult(host=host)

        if proc.returncode not in (0, 1):
            result.add_error(
                "nmap",
                f"Nmap failed with exit code {proc.returncode}",
                proc.stderr.strip() or proc.stdout.strip(),
            )
            return result

        try:
            parsed = NmapXmlParser.parse(proc.stdout, host)
        except ET.ParseError as exc:
            result.add_error("nmap", "Failed to parse Nmap XML", str(exc))
            return result

        parsed.metadata.setdefault("nmap", {}).update(
            {
                "mode": mode,
                "ports": ports,
            }
        )

        if self.debug:
            print("[DEBUG] parsed services:", len(parsed.services))
            for service in parsed.services:
                print(
                    "[DEBUG] parsed service:",
                    service.port,
                    service.protocol,
                    service.state,
                    service.service,
                    service.product,
                    service.version,
                    service.cpes,
                )

        return parsed

    def _run_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        if self.debug:
            print("[DEBUG] Nmap command:", shlex.join(command))

        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
            check=False,
        )

        if self.debug:
            print("[DEBUG] Nmap return code:", proc.returncode)
            print("[DEBUG] Nmap stderr:", proc.stderr[:1000])
            print("[DEBUG] Nmap stdout preview:", proc.stdout[:4000])

        return proc