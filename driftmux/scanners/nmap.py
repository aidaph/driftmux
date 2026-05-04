from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from auditbbox.models import HostScanResult
from auditbbox.parsers.nmap import NmapXmlParser


@dataclass(slots=True)
class NmapScanner:
    timeout: int = 120
    ports: Optional[str] = None
    nmap_script: Optional[str] = None
    extra_args: tuple[str, ...] = ()

    def build_command(self, host: str) -> list[str]:
        command = ["nmap", "-sV", "-Pn", "-oX", "-", host]
        if self.ports:
            command.extend(["-p", self.ports])
        if self.nmap_script:
            command.extend(["--script", self.nmap_script])
        if self.extra_args:
            command.extend(self.extra_args)
        return command

    def scan(self, host: str) -> HostScanResult:
        result = HostScanResult(host=host)
        if not shutil.which("nmap"):
            result.add_error("nmap", "nmap not found in PATH")
            return result

        proc = subprocess.run(
            self.build_command(host),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode not in (0, 1):
            result.add_error("nmap", f"nmap failed with exit code {proc.returncode}", proc.stderr.strip() or proc.stdout.strip())
            return result
        try:
            return NmapXmlParser.parse(proc.stdout, host)
        except Exception as exc:  # pragma: no cover - defensive wrapper
            result.add_error("nmap", f"unable to parse nmap output: {exc}", proc.stdout[:4000])
            return result
