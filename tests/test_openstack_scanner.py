from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from driftmux.scanners.openstack import NeutronSecurityGroupAuditor


class FakeNetwork:
    def __init__(self, rules, ports, security_groups):
        self._rules = rules
        self._ports = ports
        self._security_groups = security_groups

    def security_group_rules(self):
        return self._rules

    def ports(self):
        return self._ports

    def get_security_group(self, sg_id):
        return self._security_groups.get(sg_id)


class FakeIdentity:
    def __init__(self, projects):
        self._projects = projects

    def get_project(self, project_id):
        return self._projects.get(project_id)


class FakeCompute:
    def __init__(self, servers):
        self._servers = servers

    def get_server(self, server_id):
        return self._servers.get(server_id)


class FakeConnection:
    def __init__(self, *, rules, ports, security_groups, projects, servers):
        self.network = FakeNetwork(rules, ports, security_groups)
        self.identity = FakeIdentity(projects)
        self.compute = FakeCompute(servers)


def make_rule(
    *,
    rule_id: str,
    sg_id: str,
    project_id: str,
    protocol: str | None,
    port_min: int | None,
    port_max: int | None,
    remote_ip_prefix: str,
    direction: str = "ingress",
):
    return SimpleNamespace(
        id=rule_id,
        security_group_id=sg_id,
        project_id=project_id,
        direction=direction,
        protocol=protocol,
        port_range_min=port_min,
        port_range_max=port_max,
        remote_ip_prefix=remote_ip_prefix,
        remote_group_id=None,
        ethertype="IPv4",
        description=None,
    )


def make_port(
    *,
    port_id: str,
    sg_ids: list[str],
    project_id: str,
    device_id: str | None = None,
    device_owner: str | None = "compute:nova",
):
    return SimpleNamespace(
        id=port_id,
        name=f"port-{port_id}",
        project_id=project_id,
        network_id="net-1",
        device_id=device_id,
        device_owner=device_owner,
        fixed_ips=[{"ip_address": "10.0.0.10", "subnet_id": "subnet-1"}],
        security_group_ids=sg_ids,
    )


@pytest.fixture
def fake_openstack(monkeypatch):
    def _install(fake_conn):
        fake_module = types.SimpleNamespace(connect=lambda cloud=None: fake_conn)
        monkeypatch.setitem(sys.modules, "openstack", fake_module)
        return fake_conn

    return _install


def test_openstack_scanner_detects_active_public_ssh(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-ssh",
            sg_id="sg-ssh",
            project_id="project-1",
            protocol="tcp",
            port_min=22,
            port_max=22,
            remote_ip_prefix="0.0.0.0/0",
        ),
    ]

    ports = [
        make_port(
            port_id="port-1",
            sg_ids=["sg-ssh"],
            project_id="project-1",
            device_id="server-1",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=ports,
        security_groups={
            "sg-ssh": SimpleNamespace(id="sg-ssh", name="ssh-public"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={
            "server-1": SimpleNamespace(
                id="server-1",
                name="vm-datalab-1",
                status="ACTIVE",
            ),
        },
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(os_cloud="admin").audit()

    assert result.host == "openstack:neutron"
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.scanner == "openstack"
    assert finding.service == "neutron-security-group"
    assert finding.severity == "high"
    assert finding.port == 22
    assert "ssh-public" in finding.title
    assert "22/tcp" in finding.title

    metadata = finding.metadata

    assert metadata["project_id"] == "project-1"
    assert metadata["project_name"] == "datalab"
    assert metadata["security_group_id"] == "sg-ssh"
    assert metadata["security_group_name"] == "ssh-public"
    assert metadata["remote_ip_prefix"] == "0.0.0.0/0"
    assert metadata["matched"] == ["22/SSH"]
    assert metadata["used_by_count"] == 1
    assert metadata["used_by_server_count"] == 1
    assert metadata["exposure_status"] == "active"
    assert metadata["used_by_servers"][0]["server_name"] == "vm-datalab-1"

    assert result.metadata["scanner"] == "openstack-neutron"
    assert result.metadata["checked_rules"] == 1
    assert result.metadata["findings"] == 1
    assert result.metadata["active_findings"] == 1
    assert result.metadata["unused_findings"] == 0

    grouped = result.metadata["findings_by_project"]

    assert "project-1" in grouped
    assert grouped["project-1"]["project_name"] == "datalab"
    assert grouped["project-1"]["total_findings"] == 1
    assert grouped["project-1"]["high"] == 1
    assert grouped["project-1"]["active"] == 1


def test_openstack_scanner_marks_active_all_ports_as_critical(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-all",
            sg_id="sg-default",
            project_id="project-1",
            protocol=None,
            port_min=None,
            port_max=None,
            remote_ip_prefix="0.0.0.0/0",
        ),
    ]

    ports = [
        make_port(
            port_id="port-1",
            sg_ids=["sg-default"],
            project_id="project-1",
            device_id="server-1",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=ports,
        security_groups={
            "sg-default": SimpleNamespace(id="sg-default", name="default"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={
            "server-1": SimpleNamespace(
                id="server-1",
                name="vm-datalab-1",
                status="ACTIVE",
            ),
        },
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(os_cloud="admin").audit()

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.severity == "critical"
    assert "all ports" in finding.title
    assert finding.metadata["matched"] == ["all_ports"]
    assert finding.metadata["exposure_status"] == "active"
    assert finding.metadata["used_by_server_count"] == 1

    grouped = result.metadata["findings_by_project"]

    assert grouped["project-1"]["critical"] == 1
    assert grouped["project-1"]["active"] == 1


def test_openstack_scanner_marks_unused_public_ssh_as_medium(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-unused-ssh",
            sg_id="sg-unused",
            project_id="project-1",
            protocol="tcp",
            port_min=22,
            port_max=22,
            remote_ip_prefix="0.0.0.0/0",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=[],
        security_groups={
            "sg-unused": SimpleNamespace(id="sg-unused", name="unused-ssh"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={},
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(os_cloud="admin").audit()

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.severity == "medium"
    assert finding.metadata["used_by_count"] == 0
    assert finding.metadata["used_by_server_count"] == 0
    assert finding.metadata["exposure_status"] == "unused"

    grouped = result.metadata["findings_by_project"]

    assert grouped["project-1"]["medium"] == 1
    assert grouped["project-1"]["unused"] == 1


def test_openstack_scanner_ignores_allowed_public_http_https(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-http",
            sg_id="sg-web",
            project_id="project-1",
            protocol="tcp",
            port_min=80,
            port_max=80,
            remote_ip_prefix="0.0.0.0/0",
        ),
        make_rule(
            rule_id="rule-https",
            sg_id="sg-web",
            project_id="project-1",
            protocol="tcp",
            port_min=443,
            port_max=443,
            remote_ip_prefix="0.0.0.0/0",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=[],
        security_groups={
            "sg-web": SimpleNamespace(id="sg-web", name="web-public"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={},
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(os_cloud="admin").audit()

    assert result.findings == []
    assert result.metadata["checked_rules"] == 2
    assert result.metadata["findings"] == 0


def test_openstack_scanner_ignores_private_cidr(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-private-ssh",
            sg_id="sg-admin",
            project_id="project-1",
            protocol="tcp",
            port_min=22,
            port_max=22,
            remote_ip_prefix="10.0.0.0/8",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=[],
        security_groups={
            "sg-admin": SimpleNamespace(id="sg-admin", name="admin-ssh"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={},
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(os_cloud="admin").audit()

    assert result.findings == []
    assert result.metadata["checked_rules"] == 1
    assert result.metadata["findings"] == 0


def test_openstack_scanner_can_exclude_unused_findings(fake_openstack):
    rules = [
        make_rule(
            rule_id="rule-unused-ssh",
            sg_id="sg-unused",
            project_id="project-1",
            protocol="tcp",
            port_min=22,
            port_max=22,
            remote_ip_prefix="0.0.0.0/0",
        ),
    ]

    fake_conn = FakeConnection(
        rules=rules,
        ports=[],
        security_groups={
            "sg-unused": SimpleNamespace(id="sg-unused", name="unused-ssh"),
        },
        projects={
            "project-1": SimpleNamespace(id="project-1", name="datalab"),
        },
        servers={},
    )

    fake_openstack(fake_conn)

    result = NeutronSecurityGroupAuditor(
        os_cloud="admin",
        include_unused=False,
    ).audit()

    assert result.findings == []
    assert result.metadata["checked_rules"] == 1
    assert result.metadata["findings"] == 0