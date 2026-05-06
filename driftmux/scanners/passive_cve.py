# driftmux/scanners/passive_cve.py

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from driftmux.models import Finding, HostScanResult, OpenPort


@dataclass(slots=True)
class PassiveRule:
    product: str
    cve: str
    severity: str
    summary: str
    reference: str = ""
    template_tags: str = ""


@dataclass(slots=True)
class PassiveCveScanner:
    database_path: Path

    def load_rules(self) -> list[PassiveRule]:
        if not self.database_path.exists():
            return []

        rules: list[PassiveRule] = []

        with self.database_path.open("r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)

            for row in reader:
                rules.append(
                    PassiveRule(
                        product=(row.get("product") or row.get("service") or "").lower(),
                        cve=row.get("cve") or row.get("id") or "",
                        severity=(row.get("severity") or "info").lower(),
                        summary=row.get("summary") or row.get("description") or "",
                        reference=row.get("reference") or "",
                        template_tags=row.get("template_tags") or "",
                    )
                )

        return rules

    def scan(self, host: str, services: list[OpenPort]) -> HostScanResult:
        result = HostScanResult(host=host)
        rules = self.load_rules()

        for service in services:
            haystack = " ".join([
                service.service or "",
                service.product or "",
                service.version or "",
                service.extrainfo or "",
                " ".join(service.cpes or []),
            ]).lower()

            for rule in rules:
                if not rule.product:
                    continue

                if rule.product not in haystack:
                    continue

                result.findings.append(
                    Finding(
                        scanner="passive-cve",
                        host=host,
                        title=f"Possible vulnerability: {rule.cve or rule.product}",
                        severity=rule.severity,
                        description=rule.summary,
                        evidence=f"Matched product/version fingerprint: {haystack[:500]}",
                        confidence="low",
                        port=service.port,
                        service=service.service,
                        detected_version=service.version or None,
                        reference=rule.reference or rule.cve or None,
                        metadata={
                            "passive": True,
                            "cve": rule.cve,
                            "template_tags": rule.template_tags,
                        },
                    )
                )

        return result