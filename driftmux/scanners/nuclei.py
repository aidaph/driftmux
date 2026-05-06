# driftmux/scanners/nuclei.py

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from driftmux.models import Finding, HostScanResult
from driftmux.planner import NucleiTarget


@dataclass(slots=True)
class NucleiScanner:
    timeout: int = 180
    profile: str = "fast"

    def _profile_args(self) -> list[str]:
        if self.profile == "passive":
            return []

        if self.profile == "fast":
            return [
                "-severity", "high,critical",
                "-etags", "fuzz,headless,dos,bruteforce,intrusive",
                "-ss", "host-spray",
                "-c", "10",
                "-rl", "25",
            ]

        if self.profile == "deep":
            return [
                "-severity", "medium,high,critical",
                "-etags", "dos,bruteforce",
                "-ss", "host-spray",
                "-c", "25",
                "-rl", "75",
            ]

        return []

    def _build_cmd(
        self,
        targets_file: str,
        output_file: str,
        tags: set[str] | None = None,
    ) -> list[str]:
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-jsonl",
            "-o", output_file,
        ]

        cmd.extend(self._profile_args())

        if tags:
            cmd.extend(["-tags", ",".join(sorted(tags))])

        return cmd

    def scan_many(self, host: str, targets: list[NucleiTarget]) -> HostScanResult:
        result = HostScanResult(host=host)

        if not targets:
            return result

        if self.profile == "passive":
            return result

        if not shutil.which("nuclei"):
            result.add_error("nuclei", "nuclei not found in PATH")
            return result

        # Agrupar por conjunto de tags para no lanzar todo el catálogo contra todo.
        grouped: dict[tuple[str, ...], list[NucleiTarget]] = {}

        for target in targets:
            key = tuple(sorted(target.tags))
            grouped.setdefault(key, []).append(target)

        for tag_tuple, group in grouped.items():
            self._scan_group(result, group, set(tag_tuple))

        return result

    def _scan_group(
        self,
        result: HostScanResult,
        targets: list[NucleiTarget],
        tags: set[str],
    ) -> None:
        url_to_target = {target.url: target for target in targets}

        with tempfile.NamedTemporaryFile("w", prefix="nuclei-targets-", suffix=".txt", delete=True) as targets_tmp:
            for target in targets:
                targets_tmp.write(target.url + "\n")
            targets_tmp.flush()

            with tempfile.NamedTemporaryFile(prefix="nuclei-", suffix=".jsonl", delete=True) as out_tmp:
                cmd = self._build_cmd(
                    targets_file=targets_tmp.name,
                    output_file=out_tmp.name,
                    tags=tags,
                )

                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )

                if proc.returncode not in (0, 1):
                    result.add_error(
                        "nuclei",
                        f"nuclei failed with exit code {proc.returncode}",
                        proc.stderr.strip() or proc.stdout.strip(),
                    )
                    return

                output_path = Path(out_tmp.name)

                if not output_path.exists():
                    return

                for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    info = item.get("info", {})
                    matched_at = item.get("matched-at") or item.get("host") or ""
                    target = self._resolve_target(matched_at, url_to_target)

                    result.findings.append(
                        Finding(
                            scanner="nuclei",
                            host=result.host,
                            title=info.get("name") or item.get("template-id") or "Nuclei finding",
                            severity=(info.get("severity") or "info").lower(),
                            description=info.get("description") or item.get("matcher-name") or "",
                            evidence=json.dumps(item, ensure_ascii=False)[:4000],
                            confidence="high" if item.get("matched-at") else "medium",
                            port=target.service.port if target else None,
                            service=target.service.service if target else None,
                            detected_version=target.service.version if target else None,
                            reference=self._first_reference(info.get("reference")),
                            metadata=item,
                        )
                    )

    @staticmethod
    def _first_reference(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _resolve_target(matched_at: str, url_to_target: dict[str, NucleiTarget]) -> NucleiTarget | None:
        for url, target in url_to_target.items():
            if matched_at.startswith(url):
                return target
        return None