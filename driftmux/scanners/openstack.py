from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from driftmux.models import Finding, HostScanResult


DEFAULT_CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch/OpenSearch",
    5601: "Kibana/OpenSearch Dashboards",
    8080: "HTTP alternativo/Tomcat",
    8443: "HTTPS alternativo",
    9092: "Kafka",
    11211: "Memcached",
    2049: "NFS",
    445: "SMB",
    139: "NetBIOS",
    389: "LDAP",
    636: "LDAPS",
    1521: "Oracle",
    1433: "SQL Server",
    2375: "Docker API sin TLS",
    2376: "Docker API TLS",
    6443: "Kubernetes API",
    10250: "Kubelet",
}

DEFAULT_CRITICAL_RANGES = [
    (5900, 5999, "VNC"),
]

PUBLIC_CIDRS = {
    "0.0.0.0/0",
    "::/0",
}

DEFAULT_ALLOWED_PUBLIC_PORTS = {
    80,
    443,
}


@dataclass(slots=True)
class NeutronSecurityGroupAuditor:
    os_cloud: str | None = None
    critical_ports: dict[int, str] = field(default_factory=lambda: DEFAULT_CRITICAL_PORTS.copy())
    allowed_public_ports: set[int] = field(default_factory=lambda: DEFAULT_ALLOWED_PUBLIC_PORTS.copy())
    include_ipv6: bool = True
    include_unused: bool = True
    max_servers_per_finding: int = 20
    max_ports_per_finding: int = 20

    def audit(self) -> HostScanResult:
        result = HostScanResult(host="openstack:neutron")

        try:
            import openstack
        except ImportError:
            result.add_error(
                "openstack-neutron",
                "openstacksdk not installed. Install it with: pip install openstacksdk",
            )
            return result

        try:
            conn = openstack.connect(cloud=self.os_cloud) if self.os_cloud else openstack.connect()
        except Exception as exc:
            result.add_error(
                "openstack",
                f"Unable to connect to OpenStack: {exc}",
            )
            return result

        project_cache = {}
        sg_cache = {}

        try:
            rules = list(conn.network.security_group_rules())
        except Exception as exc:
            result.add_error(
                "openstack-neutron",
                f"Unable to list Neutron security group rules: {exc}",
            )
            return result

        project_cache: dict[str, Any | None] = {}
        sg_cache: dict[str, Any | None] = {}

        try:
            rules = list(conn.network.security_group_rules())
        except Exception as exc:
            result.add_error(
                "openstack",
                f"Unable to list Neutron security group rules: {exc}",
            )
            return result

        sg_usage_index = self._build_security_group_usage_index(conn)

        for rule in rules:
            if getattr(rule, "direction", None) != "ingress":
                continue

            remote_ip_prefix = getattr(rule, "remote_ip_prefix", None)

            if not self._is_public_cidr(remote_ip_prefix):
                continue

            if not self.include_ipv6 and remote_ip_prefix == "::/0":
                continue

            matched = self._matched_critical_ports(
                getattr(rule, "protocol", None),
                getattr(rule, "port_range_min", None),
                getattr(rule, "port_range_max", None),
            )

            if not matched:
                continue

            sg_id = getattr(rule, "security_group_id", None)
            project_id = getattr(rule, "project_id", None)

            sg_name = self._get_security_group_name(conn, sg_cache, sg_id) if sg_id else None
            project_name = (
                self._get_project_name(conn, project_cache, project_id)
                if project_id
                else None
            )

            usage = sg_usage_index.get(sg_id, {}) if sg_id else {}

            used_by_count = int(usage.get("used_by_count", 0) or 0)
            used_by_server_count = int(usage.get("used_by_server_count", 0) or 0)

            if not self.include_unused and used_by_count == 0:
                continue

            used_by_servers = usage.get("used_by_servers", []) or []
            used_by_ports = usage.get("ports", []) or []

            exposure_status = "active" if used_by_count > 0 else "unused"

            severity = self._severity_for_rule(
                rule=rule,
                matched=matched,
                exposure_status=exposure_status,
            )

            title = self._build_title(
                severity=severity,
                project_name=project_name,
                security_group_name=sg_name,
                remote_ip_prefix=remote_ip_prefix,
                protocol=getattr(rule, "protocol", None),
                port_min=getattr(rule, "port_range_min", None),
                port_max=getattr(rule, "port_range_max", None),
                matched=matched,
                exposure_status=exposure_status,
                used_by_server_count=used_by_server_count,
            )

            evidence = (
                f"rule_id={getattr(rule, 'id', None)} "
                f"sg={sg_name or sg_id} "
                f"project={project_name or project_id} "
                f"direction={getattr(rule, 'direction', None)} "
                f"protocol={getattr(rule, 'protocol', None)} "
                f"ports={getattr(rule, 'port_range_min', None)}-{getattr(rule, 'port_range_max', None)} "
                f"remote_ip_prefix={remote_ip_prefix}"
                f"used_by_ports={used_by_count} "
                f"used_by_servers={used_by_server_count} "
                f"exposure_status={exposure_status}"
            )

            finding = Finding(
                scanner="openstack",
                host="cloud",
                title=title,
                severity=severity.lower(),
                description="Security group rule exposes a critical port or port range to a public CIDR.",
                evidence=evidence,
                confidence="high",
                port=getattr(rule, "port_range_min", None),
                service="neutron-security-group",
                metadata={
                    "event_type": "openstack_security_group_exposure",
                    "rule_id": getattr(rule, "id", None),
                    "project_id": project_id,
                    "project_name": project_name,
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "direction": getattr(rule, "direction", None),
                    "protocol": getattr(rule, "protocol", None),
                    "port_range_min": getattr(rule, "port_range_min", None),
                    "port_range_max": getattr(rule, "port_range_max", None),
                    "remote_ip_prefix": remote_ip_prefix,
                    "matched": matched,
                    "description": getattr(rule, "description", None),
                    "findings_by_project": self._group_findings_by_project(result.findings),
                    "used_by_count": used_by_count,
                    "used_by_server_count": used_by_server_count,
                    "used_by_servers": used_by_servers[: self.max_servers_per_finding],
                    "used_by_ports": used_by_ports[: self.max_ports_per_finding],
                    "exposure_status": exposure_status,
                },
            )

            result.findings.append(finding)

        result.metadata.update(
            {
                "scanner": "openstack-neutron",
                "checked_rules": len(rules),
                "findings": len(result.findings),
                "active_findings": sum(
                    1
                    for finding in result.findings
                    if (finding.metadata or {}).get("exposure_status") == "active"
                ),
                "unused_findings": sum(
                    1
                    for finding in result.findings
                    if (finding.metadata or {}).get("exposure_status") == "unused"
                ),
                "findings_by_project": self._group_findings_by_project(result.findings),

            }
        )

        return result

    def _is_public_cidr(self, cidr: str | None) -> bool:
        if not cidr:
            return False

        if cidr in PUBLIC_CIDRS:
            return True

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

        return network.prefixlen == 0

    def _matched_critical_ports(self, protocol, port_min, port_max) -> list[str]:
        matched: list[str] = []

        if protocol not in ("tcp", "udp", None):
            return matched

        if port_min is None and port_max is None:
            matched.append("all_ports")
            return matched

        try:
            pmin = int(port_min)
            pmax = int(port_max)
        except (TypeError, ValueError):
            return matched

        for port, name in self.critical_ports.items():
            if pmin <= port <= pmax:
                matched.append(f"{port}/{name}")

        for start, end, name in DEFAULT_CRITICAL_RANGES:
            if pmin <= end and pmax >= start:
                matched.append(f"{start}-{end}/{name}")

        return matched

    def _severity_for_rule(
    self,
    rule,
    matched: list[str],
    exposure_status: str,
) -> str:
        if "all_ports" in matched:
            return "critical" if exposure_status == "active" else "high"

        protocol = getattr(rule, "protocol", None)
        port_min = getattr(rule, "port_range_min", None)
        port_max = getattr(rule, "port_range_max", None)

        try:
            pmin = int(port_min)
            pmax = int(port_max)
        except (TypeError, ValueError):
            return "high" if exposure_status == "active" else "medium"

        if protocol in (None, "tcp", "udp"):
            for port in range(pmin, pmax + 1):
                if port not in self.allowed_public_ports:
                    return "high" if exposure_status == "active" else "medium"

        return "info"

    def _get_security_group_name(self, conn, cache: dict, sg_id: str) -> str | None:
        if sg_id in cache:
            return cache[sg_id]

        try:
            sg = conn.network.get_security_group(sg_id)
            cache[sg_id] = getattr(sg, "name", None)
        except Exception:
            cache[sg_id] = None

        return cache[sg_id]

    def _get_project_name(self, conn, cache: dict, project_id: str) -> str | None:
        if project_id in cache:
            return cache[project_id]

        try:
            project = conn.identity.get_project(project_id)
            cache[project_id] = getattr(project, "name", None)
        except Exception:
            cache[project_id] = None

        return cache[project_id]

    def _build_title(
        self,
        severity: str,
        project_name: str | None,
        security_group_name: str | None,
        remote_ip_prefix: str | None,
        protocol: str | None,
        port_min: int | None,
        port_max: int | None,
        matched: list[str],
        exposure_status: str,
        used_by_server_count: int,
    ) -> str:
        project = project_name or "unknown-project"
        sg = security_group_name or "unknown-security-group"

        if "all_ports" in matched:
            exposed = "all ports"
        elif port_min is None and port_max is None:
            exposed = "all ports"
        elif port_min == port_max:
            exposed = f"{port_min}/{protocol or 'any'}"
        else:
            exposed = f"{port_min}-{port_max}/{protocol or 'any'}"

        return (
            f"OpenStack security group exposure: {project}/{sg} exposes "
            f"{exposed} to {remote_ip_prefix} ({', '.join(matched)}) "
            f"[{exposure_status}, servers={used_by_server_count}]"
        )

    def _group_findings_by_project(self, findings: list[Finding]) -> dict:
        grouped: dict[str, dict] = {}

        for finding in findings:
            metadata = finding.metadata or {}

            project_id = metadata.get("project_id") or "unknown-project-id"
            project_name = metadata.get("project_name") or "unknown-project"

            key = str(project_id)

            if key not in grouped:
                grouped[key] = {
                    "project_id": project_id,
                    "project_name": project_name,
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "active": 0,
                    "unused": 0,
                    "security_groups": {},
                    "findings": [],
                }

            severity = str(finding.severity or "info").lower()

            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"

            exposure_status = str(metadata.get("exposure_status") or "unknown").lower()

            grouped[key]["total_findings"] += 1
            grouped[key][severity] += 1

            if exposure_status == "active":
                grouped[key]["active"] += 1
            elif exposure_status == "unused":
                grouped[key]["unused"] += 1

            sg_id = metadata.get("security_group_id") or "unknown-security-group-id"
            sg_name = metadata.get("security_group_name") or "unknown-security-group"

            if sg_id not in grouped[key]["security_groups"]:
                grouped[key]["security_groups"][sg_id] = {
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "active": 0,
                    "unused": 0,
                }

            grouped[key]["security_groups"][sg_id]["total_findings"] += 1
            grouped[key]["security_groups"][sg_id][severity] += 1

            if exposure_status == "active":
                grouped[key]["security_groups"][sg_id]["active"] += 1
            elif exposure_status == "unused":
                grouped[key]["security_groups"][sg_id]["unused"] += 1

            grouped[key]["findings"].append(
                {
                    "severity": severity,
                    "title": finding.title,
                    "rule_id": metadata.get("rule_id"),
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "protocol": metadata.get("protocol"),
                    "port_range_min": metadata.get("port_range_min"),
                    "port_range_max": metadata.get("port_range_max"),
                    "remote_ip_prefix": metadata.get("remote_ip_prefix"),
                    "matched": metadata.get("matched"),
                    "used_by_count": metadata.get("used_by_count", 0),
                    "used_by_server_count": metadata.get("used_by_server_count", 0),
                    "used_by_servers": metadata.get("used_by_servers", []),
                    "exposure_status": exposure_status,
                }
            )

        return grouped

    def _build_security_group_usage_index(self, conn) -> dict[str, dict]:
        usage: dict[str, dict] = {}

        try:
            ports = list(conn.network.ports())
        except Exception:
            return usage

        server_cache: dict[str, object | None] = {}

        for port in ports:
            sg_ids = (
                getattr(port, "security_group_ids", None)
                or getattr(port, "security_groups", None)
                or []
            )

            if not sg_ids:
                continue

            device_owner = getattr(port, "device_owner", None)
            device_id = getattr(port, "device_id", None)

            # Normalmente las VMs aparecen como compute:nova.
            is_compute_port = bool(device_id) and str(device_owner or "").startswith("compute:")

            server_info = None

            if is_compute_port:
                if device_id not in server_cache:
                    try:
                        server_cache[device_id] = conn.compute.get_server(device_id)
                    except Exception:
                        server_cache[device_id] = None

                server = server_cache.get(device_id)

                server_info = {
                    "server_id": device_id,
                    "server_name": getattr(server, "name", None) if server else None,
                    "status": getattr(server, "status", None) if server else None,
                }

            fixed_ips = getattr(port, "fixed_ips", None) or []

            port_info = {
                "port_id": getattr(port, "id", None),
                "port_name": getattr(port, "name", None),
                "network_id": getattr(port, "network_id", None),
                "device_id": device_id,
                "device_owner": device_owner,
                "fixed_ips": fixed_ips,
                "server": server_info,
            }

            for sg_id in sg_ids:
                if sg_id not in usage:
                    usage[sg_id] = {
                        "used_by_count": 0,
                        "ports": [],
                        "servers": {},
                    }

                usage[sg_id]["used_by_count"] += 1
                usage[sg_id]["ports"].append(port_info)

                if server_info:
                    usage[sg_id]["servers"][server_info["server_id"]] = server_info

        for sg_id, item in usage.items():
            item["used_by_servers"] = list(item["servers"].values())
            item["used_by_server_count"] = len(item["used_by_servers"])
            del item["servers"]

        return usage

    def _normalize_openstack_severity(self, finding: Finding) -> str:
        raw = ""

        if getattr(finding, "severity", None):
            raw = str(finding.severity).lower().strip()
        elif hasattr(finding, "normalized_severity"):
            raw = str(finding.normalized_severity()).lower().strip()

        if raw in {"critical", "crit", "crítico", "critico"}:
            return "critical"

        if raw in {"high", "alta", "alto"}:
            return "high"

        if raw in {"medium", "moderate", "media", "medio"}:
            return "medium"

        if raw in {"low", "baja", "bajo"}:
            return "low"

        if raw in {"info", "informational", "informativa", "informativo"}:
            return "info"

        title = str(getattr(finding, "title", "") or "").lower()
        evidence = str(getattr(finding, "evidence", "") or "").lower()

        if "all_ports" in title or "all ports" in title or "all_ports" in evidence or "all ports" in evidence:
            return "critical"

        return "info"