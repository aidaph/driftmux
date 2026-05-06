from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
from bs4 import BeautifulSoup

from driftmux.models import Finding, HostScanResult, OpenPort


@dataclass(slots=True)
class PlecostScanner:
    timeout: int = 120
    mode: str = "auto"
    deep: bool = False

    def maybe_wordpress(self, host: str, service: Optional[OpenPort] = None) -> bool:
        if service and "wordpress" in service.classifications:
            return True
        candidates: list[str] = []
        if host.startswith(("http://", "https://")):
            candidates.append(host)
        else:
            if self.mode in ("auto", "https"):
                candidates.append(f"https://{host}")
            if self.mode in ("auto", "http"):
                candidates.append(f"http://{host}")
        headers = {"User-Agent": "driftmux/0.3"}
        markers = ["/wp-content/", "/wp-includes/", "wp-json", "wp-login.php", "wordpress"]
        for url in candidates:
            try:
                response = requests.get(url, headers=headers, timeout=8, allow_redirects=True, verify=True)
                text = response.text.lower()
                if any(marker in text for marker in markers):
                    return True
                soup = BeautifulSoup(response.text, "html.parser")
                for meta in soup.find_all("meta"):
                    content = (meta.get("content") or "").lower()
                    if "wordpress" in content:
                        return True
            except requests.RequestException:
                continue
        return False

    def build_command(self, target: str, output_path: str) -> list[str]:
        command = ["plecost", "scan", target, "--output", output_path]
        if self.deep:
            command.append("--deep")
        return command

    def scan(self, host: str, service: Optional[OpenPort] = None) -> HostScanResult:
        result = HostScanResult(host=host)
        if not shutil.which("plecost"):
            result.add_error("plecost", "plecost not found in PATH")
            return result
        if not self.maybe_wordpress(host, service):
            return result
        target = host if host.startswith(("http://", "https://")) else f"https://{host}"
        with tempfile.NamedTemporaryFile(prefix="plecost-", suffix=".json", delete=True) as tmp:
            proc = subprocess.run(
                self.build_command(target, tmp.name),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if proc.returncode != 0:
                result.add_error("plecost", f"plecost failed with exit code {proc.returncode}", proc.stderr.strip() or proc.stdout.strip())
                return result
            try:
                payload = json.loads(Path(tmp.name).read_text(encoding="utf-8"))
            except Exception as exc:
                result.add_error("plecost", f"unable to parse plecost output: {exc}", (proc.stdout + "\n" + proc.stderr)[:4000])
                return result
        result.findings.extend(self._findings_from_payload(host, service, payload))
        result.metadata["plecost"] = {
            "is_wordpress": payload.get("is_wordpress"),
            "wordpress_version": payload.get("wordpress_version"),
        }
        return result

    def _findings_from_payload(self, host: str, service: Optional[OpenPort], payload: dict) -> list[Finding]:
        findings: list[Finding] = []
        wp_version = payload.get("wordpress_version")
        if payload.get("is_wordpress") or wp_version:
            findings.append(Finding(
                scanner="plecost",
                host=host,
                title="WordPress detected",
                severity="info",
                description=f"WordPress version: {wp_version or 'unknown'}",
                evidence=json.dumps({"wordpress_version": wp_version}, ensure_ascii=False),
                confidence="high",
                port=(service.port if service else None),
                service=(service.service if service else "http"),
                detected_version=wp_version,
            ))
        for item in payload.get("findings", []) or []:
            findings.append(Finding(
                scanner="plecost",
                host=host,
                title=item.get("title") or item.get("id") or "Plecost finding",
                severity=(item.get("severity") or "info").lower(),
                description=item.get("description") or item.get("title") or "",
                evidence=json.dumps(item, ensure_ascii=False)[:4000],
                confidence="high" if item.get("cve") else "medium",
                port=(service.port if service else None),
                service=(service.service if service else "http"),
                detected_version=wp_version,
                reference=item.get("cve") or item.get("id"),
                metadata=item,
            ))
        for plugin in payload.get("plugins", []) or []:
            findings.append(Finding(
                scanner="plecost",
                host=host,
                title=f"Plugin detected: {plugin.get('slug', 'unknown')}",
                severity="info",
                description=f"Plugin version: {plugin.get('version', 'unknown')}",
                evidence=json.dumps(plugin, ensure_ascii=False)[:4000],
                confidence="medium",
                port=(service.port if service else None),
                service=(service.service if service else "http"),
                detected_version=plugin.get("version"),
            ))
        return findings
