from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from driftmux.models import Finding, HostScanResult, OpenPort

@dataclass(slots=True)
class NucleiScanner:
    timeout: int = 180
    profile: str = "fast"  # fast | deep

    def should_scan(self, service: OpenPort) -> bool:
        labels = {label.lower() for label in (service.classifications or [])}
        svc = (service.service or "").lower()
        product = (service.product or "").lower()
        port = int(service.port or 0)

        web_ports = {80, 81, 443, 444, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9443}

        if any(label in labels for label in ["http", "apache-httpd", "nginx", "kubernetes"]):
            return True

        if "http" in svc or "https" in svc:
            return True

        if any(x in product for x in ["apache", "nginx", "tomcat", "jetty", "nextcloud", "kubernetes"]):
            return True

        if port in web_ports:
            return True

        return False

    def build_target(self, host: str, service: OpenPort, scheme: str = "auto") -> str:
        if host.startswith(("http://", "https://")):
            return host

        if scheme == "https" or service.tunnel == "ssl" or service.port in (443, 8443, 6443, 9443):
            return f"https://{host}:{service.port}"

        if scheme == "http":
            return f"http://{host}:{service.port}"

        if service.port in (443, 8443, 6443, 9443):
            return f"https://{host}:{service.port}"

        return f"http://{host}:{service.port}"

    def _build_cmd(self, target: str, output_file: str) -> list[str]:
        cmd = ["nuclei", "-u", target, "-jsonl", "-o", output_file]

        if self.profile == "fast":
            cmd.extend([
                "-severity", "medium,high,critical",
                "-etags", "fuzz,headless,dos",
                "-ss","host-spray",
                "-c","10"
            ])

        return cmd

    def scan(self, host: str, service: OpenPort, scheme: str = "auto") -> HostScanResult:
        result = HostScanResult(host=host)
        if not self.should_scan(service):
            return result
        if not shutil.which("nuclei"):
            result.add_error("nuclei", "nuclei not found in PATH")
            return result
        target = self.build_target(host, service, scheme=scheme)
        with tempfile.NamedTemporaryFile(prefix="nuclei-", suffix=".jsonl", delete=True) as tmp:
            print(f"[DEBUG] running nuclei against: {target}")
            cmd = self._build_cmd(target, tmp.name)
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            if proc.returncode not in (0, 1):
                result.add_error("nuclei", f"nuclei failed with exit code {proc.returncode}", proc.stderr.strip() or proc.stdout.strip())
                return result
            findings: list[Finding] = []
            output_path = Path(tmp.name)
            if output_path.exists() and output_path.read_text(encoding="utf-8", errors="ignore").strip():
                for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    info = item.get("info", {})
                    findings.append(Finding(
                        scanner="nuclei",
                        host=host,
                        title=info.get("name") or item.get("template-id") or "Nuclei finding",
                        severity=(info.get("severity") or "info").lower(),
                        description=info.get("description") or item.get("matcher-name") or "",
                        evidence=json.dumps(item, ensure_ascii=False)[:4000],
                        confidence="high" if item.get("matched-at") else "medium",
                        port=service.port,
                        service=service.service,
                        detected_version=service.version or None,
                        reference=(info.get("reference") or [None])[0] if isinstance(info.get("reference"), list) else info.get("reference"),
                        metadata=item,
                    ))
            result.findings.extend(findings)
        return result
