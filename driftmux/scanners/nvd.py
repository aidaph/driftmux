from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from driftmux.models import Finding, HostScanResult, OpenPort


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_FROM_SCORE = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


@dataclass(slots=True)
class NvdConfig:
    enabled: bool = False
    api_key: str | None = None
    min_cvss: float = 0.0
    cache_path: str = "~/.cache/driftmux/nvd.sqlite"
    cache_ttl_hours: int = 120
    timeout: int = 20
    max_cves_per_service: int = 50
    debug: bool = False


class NvdCveScanner:
    def __init__(self, config: NvdConfig):
        self.config = config
        self.cache_path = Path(config.cache_path).expanduser()
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_cache()

        def _debug(self, *parts: object) -> None:
            if self.debug:
                print("[DEBUG][nvd]", *parts)

    def scan(self, host: str, services: list[OpenPort]) -> HostScanResult:
        result = HostScanResult(host=host)

        if not self.config.enabled:
            return result

        for service in services:
            cpes = self._service_cpes(service)
            self._debug(
                "input service:",
                f"host={host}",
                f"port={service.port}",
                f"service={service.service}",
                f"product={service.product}",
                f"version={service.version}",
                f"extrainfo={service.extrainfo}",
                f"cpes={cpes}",
                f"classifications={service.classifications}",
            )

            if not cpes:
                result.metadata.setdefault("nvd", {}).setdefault("services_without_cpe", []).append(
                    {
                        "port": service.port,
                        "service": service.service,
                        "product": service.product,
                        "version": service.version,
                    }
                )
                continue

            for cpe23 in cpes:
                try:
                    payload = self._get_cves_for_cpe(cpe23)
                except Exception as exc:
                    result.add_error(
                        "nvd",
                        f"NVD lookup failed for {cpe23}",
                        str(exc),
                    )
                    continue

                findings = self._payload_to_findings(
                    host=host,
                    service=service,
                    cpe23=cpe23,
                    payload=payload,
                )
                result.findings.extend(findings[: self.config.max_cves_per_service])

        result.metadata.setdefault("nvd", {}).update(
            {
                "enabled": True,
                "min_cvss": self.config.min_cvss,
                "cache_path": str(self.cache_path),
                "cache_ttl_hours": self.config.cache_ttl_hours,
            }
        )

        return result

    def is_actionable_cpe(self, cpe: str) -> bool:
        parts = cpe.split(":")

        # CPE 2.3 esperado:
        # cpe:2.3:a:vendor:product:version:...
        if len(parts) < 6:
            return False

        cpe_part = parts[2]
        #vendor = parts[3]
        product = parts[4]
        version = parts[5]

        if version in {"*", "-", ""}:
            return False

        # Evita CPEs de sistema operativo demasiado genéricos
        if cpe_part == "o" and product in {"linux_kernel", "linux"}:
            return False

        # Evita productos vacíos o genéricos
        if product in {"*", "-", ""}:
            return False

        return True

    def _service_cpes(self, service: OpenPort) -> list[str]:
        normalized: list[str] = []

        for cpe in service.cpes:
            if not self.is_actionable_cpe(cpe):
                self._debug("skip cpe:", cpe, "reason=not actionable")
                continue
            cpe23 = normalize_cpe_to_23(cpe)
            if cpe23 and cpe23 not in normalized:
                normalized.append(cpe23)

            self._debug("query cpe:", cpe)

        return normalized

    def _get_cves_for_cpe(self, cpe23: str) -> dict[str, Any]:
        cached = self._cache_get(cpe23)

        if cached is not None:
            return cached

        payload = self._query_nvd(cpe23)
        self._cache_put(cpe23, payload)

        return payload

    def _query_nvd(self, cpe23: str) -> dict[str, Any]:
        headers = {}

        api_key = self.config.api_key or os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        params = {
            "cpeName": cpe23,
            "resultsPerPage": 2000,
        }

        response = requests.get(
            NVD_CVE_API,
            params=params,
            headers=headers,
            timeout=self.config.timeout,
        )
        response.raise_for_status()

        # Conservative delay. With an API key NVD allows more throughput,
        # but this keeps single-host scans polite.
        time.sleep(0.7 if api_key else 6.1)

        return response.json()

    def should_suppress_cve_for_service(self, service, cve_id: str) -> tuple[bool, str]:
        product = (service.product or "").lower()
        version = (service.version or "").lower()
        extrainfo = (service.extrainfo or "").lower()
        service_name = (service.service or "").lower()

        text = " ".join(
            [
                service_name,
                product,
                version,
                extrainfo,
                " ".join(service.cpes or []),
            ]
        ).lower()

        if "openssh" in text:
            # CVE antiguo específico de paquetes Red Hat comprometidos en 2008.
            # No aplica a OpenSSH moderno en Ubuntu.
            if cve_id == "CVE-2008-3844" and "ubuntu" in text:
                return True, "Red Hat-specific 2008 package issue; not applicable to Ubuntu OpenSSH"

            # Ubuntu 24.04 corrigió CVE-2024-6387 en 1:9.6p1-3ubuntu13.3.
            # Si el banner muestra 3ubuntu13.16, está por encima.
            if cve_id == "CVE-2024-6387" and "ubuntu" in text:
                marker = "3ubuntu13."
                if marker in text:
                    try:
                        patch = int(text.split(marker, 1)[1].split()[0])
                        if patch >= 3:
                            return True, "Ubuntu OpenSSH package appears patched for CVE-2024-6387"
                    except ValueError:
                        pass

            # CVE disputado/con amenaza muy específica; mejor no mostrar como HIGH directo.
            if cve_id == "CVE-2023-51767":
                return True, "Disputed OpenSSH issue with specific Rowhammer/co-location threat model"

        return False, ""

    def _payload_to_findings(
        self,
        host: str,
        service: OpenPort,
        cpe23: str,
        payload: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []
        supressed: list[dict] = []

        vulnerabilities = payload.get("vulnerabilities") or []

        for entry in vulnerabilities:
            cve = entry.get("cve") or {}
            cve_id = cve.get("id") or "CVE-UNKNOWN"

            metrics = cve.get("metrics") or {}
            cvss_score, cvss_vector, cvss_version = extract_cvss(metrics)

            if cvss_score is not None and cvss_score < self.config.min_cvss:
                continue

            severity = severity_from_cvss(cvss_score)

            descriptions = cve.get("descriptions") or []
            description = first_english_description(descriptions)

            references = extract_references(cve)
            reference_url = first_reference_url(references)

            published = cve.get("published")
            last_modified = cve.get("lastModified")

            suppress, reason = self.should_suppress_cve_for_service(service, cve_id)

            if suppress:
                supressed.append(
                    {
                        "cve": cve_id,
                        "port": service.port,
                        "service": service.service,
                        "reason": reason,
                    }
                )
                continue

            findings.append(
                Finding(
                    scanner="nvd",
                    host=host,
                    title=f"{cve_id} affects {service.product or service.service or service.endpoint()}",
                    severity=severity,
                    description=description,
                    evidence=f"NVD matched CPE {cpe23} against service {service.endpoint()}",
                    confidence="medium",
                    port=service.port,
                    service=service.service,
                    detected_version=service.version or service.extrainfo or None,
                    reference=reference_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    metadata={
                        "verified": False,
                        "source": "nvd",
                        "match_type": "cpe",
                        "cpe": cpe23,
                        "cve": cve_id,
                        "cvss": cvss_score,
                        "cvss_vector": cvss_vector,
                        "cvss_version": cvss_version,
                        "published": published,
                        "last_modified": last_modified,
                    },
                )
            )

        findings.sort(
            key=lambda finding: (
                finding.metadata.get("cvss") is not None,
                finding.metadata.get("cvss") or 0.0,
            ),
            reverse=True,
        )

        return findings

    def _init_cache(self) -> None:
        with sqlite3.connect(self.cache_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nvd_cpe_cache (
                    cpe TEXT PRIMARY KEY,
                    fetched_at INTEGER NOT NULL,
                    response_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _cache_get(self, cpe23: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.cache_path) as conn:
            row = conn.execute(
                "SELECT fetched_at, response_json FROM nvd_cpe_cache WHERE cpe = ?",
                (cpe23,),
            ).fetchone()

        if row is None:
            return None

        fetched_at, response_json = row
        age_seconds = int(time.time()) - int(fetched_at)

        if age_seconds > self.config.cache_ttl_hours * 3600:
            return None

        try:
            return json.loads(response_json)
        except json.JSONDecodeError:
            return None

    def _cache_put(self, cpe23: str, payload: dict[str, Any]) -> None:
        with sqlite3.connect(self.cache_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nvd_cpe_cache (cpe, fetched_at, response_json)
                VALUES (?, ?, ?)
                """,
                (cpe23, int(time.time()), json.dumps(payload)),
            )
            conn.commit()


def normalize_cpe_to_23(cpe: str) -> str | None:
    cpe = (cpe or "").strip()

    if not cpe:
        return None

    if cpe.startswith("cpe:2.3:"):
        return cpe

    if not cpe.startswith("cpe:/"):
        return None

    raw = cpe.removeprefix("cpe:/")
    parts = raw.split(":")

    if len(parts) < 3:
        return None

    part = parts[0] or "*"
    vendor = parts[1] or "*"
    product = parts[2] or "*"
    version = parts[3] if len(parts) > 3 and parts[3] else "*"
    update = parts[4] if len(parts) > 4 and parts[4] else "*"
    edition = parts[5] if len(parts) > 5 and parts[5] else "*"
    language = parts[6] if len(parts) > 6 and parts[6] else "*"

    return ":".join(
        [
            "cpe",
            "2.3",
            escape_cpe23(part),
            escape_cpe23(vendor),
            escape_cpe23(product),
            escape_cpe23(version),
            escape_cpe23(update),
            escape_cpe23(edition),
            escape_cpe23(language),
            "*",
            "*",
            "*",
            "*",
        ]
    )


def escape_cpe23(value: str) -> str:
    return (
        value.strip()
        .replace("\\", "\\\\")
        .replace(" ", "_")
    )


def extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []

        if not values:
            continue

        metric = values[0]
        data = metric.get("cvssData") or {}

        score = data.get("baseScore")
        vector = data.get("vectorString")
        version = data.get("version")

        if score is not None:
            return float(score), vector, str(version) if version else key

    return None, None, None


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"

    for threshold, severity in SEVERITY_FROM_SCORE:
        if score >= threshold:
            return severity

    return "info"


def first_english_description(descriptions: list[dict[str, Any]]) -> str:
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]

    for item in descriptions:
        if item.get("value"):
            return item["value"]

    return ""


def first_reference_url(references: list[dict[str, Any]]) -> str | None:
    for item in references:
        if not isinstance(item, dict):
            continue

        url = item.get("url")
        if url:
            return url

    return None

def extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    references = cve.get("references") or []

    # NVD API 2.0 format:
    # "references": [{"url": "...", "source": "...", "tags": [...]}]
    if isinstance(references, list):
        return references

    # Older / legacy NVD-like format:
    # "references": {"referenceData": [{"url": "..."}]}
    if isinstance(references, dict):
        reference_data = references.get("referenceData") or []
        if isinstance(reference_data, list):
            return reference_data

    return []
