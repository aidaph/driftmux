from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List

from auditbbox.models import Finding, HostScanResult, OpenPort


class NmapXmlParser:
    @staticmethod
    def parse(xml_text: str, host: str) -> HostScanResult:
        result = HostScanResult(host=host)
        root = ET.fromstring(xml_text)
        for host_node in root.findall("host"):
            for port in host_node.findall("ports/port"):
                state_el = port.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state != "open":
                    continue
                service_el = port.find("service")
                service = OpenPort(
                    port=int(port.get("portid", 0)),
                    protocol=port.get("protocol", "tcp"),
                    state=state,
                    service=(service_el.get("name", "unknown") if service_el is not None else "unknown"),
                    product=(service_el.get("product", "") if service_el is not None else ""),
                    version=(service_el.get("version", "") if service_el is not None else ""),
                    extrainfo=(service_el.get("extrainfo", "") if service_el is not None else ""),
                    tunnel=(service_el.get("tunnel", "") if service_el is not None else ""),
                    cpes=[cpe.text for cpe in port.findall("service/cpe") if cpe.text],
                )
                service.classifications = classify_service(service)
                result.services.append(service)

                for script_el in port.findall("script"):
                    result.findings.append(
                        Finding(
                            scanner="nmap",
                            host=host,
                            title=f"Nmap script result: {script_el.get('id', 'script')}",
                            severity="info",
                            description=script_el.get("output", ""),
                            evidence=script_el.get("output", ""),
                            confidence="medium",
                            port=service.port,
                            service=service.service,
                            detected_version=service.version or None,
                        )
                    )
        return result


def classify_service(service: OpenPort) -> List[str]:
    text = " ".join(
        part.lower() for part in [service.service, service.product, service.version, service.extrainfo, " ".join(service.cpes)] if part
    )
    labels: list[str] = []
    if any(token in text for token in ["http", "https", "ssl/http", "apache", "nginx", "iis"]):
        labels.append("http")
    if "apache" in text:
        labels.append("apache-httpd")
    if "nginx" in text:
        labels.append("nginx")
    if any(token in text for token in ["kubernetes", "kube-apiserver", "kubelet", "etcd", "openshift"]):
        labels.append("kubernetes")
    if "wordpress" in text:
        labels.append("wordpress")
    if service.service.lower() == "ssh" or "openssh" in text:
        labels.append("ssh")
    # preserve order
    dedup: list[str] = []
    for label in labels:
        if label not in dedup:
            dedup.append(label)
    return dedup
