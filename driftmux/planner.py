# driftmux/planner.py

from __future__ import annotations
from dataclasses import dataclass, field
from driftmux.models import Finding, OpenPort


@dataclass(slots=True)
class NucleiTarget:
    host: str
    service: OpenPort
    url: str
    tags: set[str] = field(default_factory=set)
    severity: str = "high,critical"
    reason: str = ""


@dataclass(slots=True)
class ScanPlan:
    nuclei_targets: list[NucleiTarget] = field(default_factory=list)
    wordpress_targets: list[OpenPort] = field(default_factory=list)
    passive_only: bool = False

WEB_PORTS = {
    80, 81, 443, 444, 591, 593,
    8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9443,
}

def is_web_candidate(service: OpenPort) -> bool:
    labels = {x.lower() for x in service.classifications or []}
    svc = (service.service or "").lower()
    product = (service.product or "").lower()
    port = int(service.port or 0)

    if "http" in labels:
        return True

    if "http" in svc or "https" in svc:
        return True

    if any(x in product for x in ("apache", "nginx", "tomcat", "jetty", "nextcloud", "iis")):
        return True

    return port in WEB_PORTS


def build_url(host: str, service: OpenPort, scheme: str = "auto") -> str:
    if host.startswith(("http://", "https://")):
        return host

    if scheme == "https" or service.tunnel == "ssl" or service.port in (443, 8443, 9443, 6443):
        return f"https://{host}:{service.port}"

    if scheme == "http":
        return f"http://{host}:{service.port}"

    return f"http://{host}:{service.port}"


def tags_for_service(service: OpenPort) -> set[str]:
    labels = {x.lower() for x in service.classifications or []}
    text = " ".join([
        service.service or "",
        service.product or "",
        service.version or "",
        service.extrainfo or "",
        " ".join(service.cpes or []),
    ]).lower()

    tags: set[str] = set()

    if "kubernetes" in labels or "kubernetes" in text or "kube" in text:
        tags.update({"kubernetes", "exposure", "misconfig"})

    if "apache" in text:
        tags.update({"apache", "cve"})

    if "nginx" in text:
        tags.update({"nginx", "misconfig", "exposure"})

    if "tomcat" in text:
        tags.update({"tomcat", "cve", "exposure"})

    if "wordpress" in labels or "wordpress" in text:
        tags.update({"wordpress", "cve"})

    if not tags:
        tags.update({"exposure", "panel", "misconfig"})

    return tags

def build_scan_plan(
    host: str,
    services: list[OpenPort],
    passive_findings: list[Finding],
    scheme: str = "auto",
    profile: str = "fast",
) -> ScanPlan:
    plan = ScanPlan(passive_only=(profile == "passive"))

    findings_by_port: dict[int, list[Finding]] = {}

    for finding in passive_findings:
        if finding.port is None:
            continue
        findings_by_port.setdefault(finding.port, []).append(finding)

    for service in services:
        labels = {x.lower() for x in service.classifications or []}

        if "wordpress" in labels:
            plan.wordpress_targets.append(service)

        if profile == "passive":
            continue

        if not is_web_candidate(service):
            continue

        tags = tags_for_service(service)

        passive_hits = findings_by_port.get(service.port, [])

        # Si hay hallazgo pasivo alto/crítico, ejecutar CVEs concretos.
        if any(f.severity in {"high", "critical"} for f in passive_hits):
            tags.add("cve")

        # Si no hay señal fuerte y estamos en fast, no escanear genérico en exceso.
        if profile == "fast" and not passive_hits and tags == {"exposure", "panel", "misconfig"}:
            reason = "generic web exposure check"
        elif passive_hits:
            reason = "passive CVE match"
        else:
            reason = "technology fingerprint"

        plan.nuclei_targets.append(
            NucleiTarget(
                host=host,
                service=service,
                url=build_url(host, service, scheme),
                tags=tags,
                reason=reason,
            )
        )

    return plan